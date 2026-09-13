// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package directconn

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/stun"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Direct connector timing constants mirroring the reference behavior.
const (
	// DefaultDialLoopInterval paces candidate collection.
	DefaultDialLoopInterval = 5 * time.Second
	// peerBlacklistTimeout excludes a peer after service rejection.
	peerBlacklistTimeout = 5 * time.Minute
	// listenerBlacklistTimeout excludes a peer+URL after retries exhaust.
	listenerBlacklistTimeout = 5 * time.Minute
	// directDialTimeout bounds one non-punch dial.
	directDialTimeout = 3 * time.Second
	// getIPListTimeout bounds the address discovery RPC.
	getIPListTimeout = 5 * time.Second
	// listenerRetryLadder is the per-URL retry backoff in milliseconds.
	listenerRetryLadderMS = 1000
	// punchAssistRPCInterval spaces repeated punch assists (unused today).
	udpPunchAssistTimeout = 3 * time.Second
)

// Handoff upgrades a dialed channel into an authenticated peer session. It
// returns an error when the authenticated peer differs from dstPeerID.
type Handoff func(ctx context.Context, channel peer.PacketChannel, dstPeerID uint32) error

// IsSelfListener reports whether ip:port is a local listener of the given
// protocol; used to avoid dialing ourselves during address expansion.
type IsSelfListener func(ip netip.Addr, port uint16, udp bool) bool

// DialFunc dials a tunnel URL and returns a packet channel.
type DialFunc func(ctx context.Context, rawURL string, maxFrame int) (peer.PacketChannel, error)

// ConnectorConfig wires the direct connector.
type ConnectorConfig struct {
	MyPeerID uint32
	Domain   string
	RPC      *rpc.PeerRpcManager
	Stun     stun.Source

	// Candidates returns routed peer IDs that should get direct connections.
	Candidates func() []uint32
	// HasDirectConn reports whether the peer already has a direct connection.
	HasDirectConn func(peerID uint32) bool
	// IsSelfListener optionally filters self-targeting dials.
	IsSelfListener IsSelfListener
	// EnableIPv6 gates IPv6 listener expansion.
	EnableIPv6 bool
	// DefaultProtocol is the highest-priority listener scheme.
	DefaultProtocol string
	// Dial dials non-UDP tunnel URLs.
	Dial DialFunc
	// Handoff authenticates and installs a new connection.
	Handoff Handoff
	// MaxFrame is the tunnel frame size limit.
	MaxFrame int

	// LoopInterval overrides DefaultDialLoopInterval when positive.
	LoopInterval time.Duration
}

// Connector runs the direct connect loop: discover addresses via RPC, then
// dial or punch toward them.
type Connector struct {
	cfg ConnectorConfig

	peerBlacklist     *timedSet
	listenerBlacklist map[listenerKey]time.Time
	blacklistMu       sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	active map[uint32]struct{}
	closed bool
}

type listenerKey struct {
	peerID uint32
	url    string
}

type timedSet struct {
	timeout time.Duration
	mu      sync.Mutex
	entries map[uint32]time.Time
}

func newTimedSet(timeout time.Duration) *timedSet {
	return &timedSet{timeout: timeout, entries: make(map[uint32]time.Time)}
}

func (s *timedSet) insert(peerID uint32) {
	s.mu.Lock()
	s.entries[peerID] = time.Now()
	s.mu.Unlock()
}

func (s *timedSet) contains(peerID uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	inserted, ok := s.entries[peerID]
	if !ok {
		return false
	}
	if time.Since(inserted) >= s.timeout {
		delete(s.entries, peerID)
		return false
	}
	return true
}

// NewConnector builds a direct connector loop.
func NewConnector(cfg ConnectorConfig) *Connector {
	if cfg.LoopInterval <= 0 {
		cfg.LoopInterval = DefaultDialLoopInterval
	}
	if cfg.Dial == nil {
		cfg.Dial = defaultDial
	}
	return &Connector{
		cfg:               cfg,
		peerBlacklist:     newTimedSet(peerBlacklistTimeout),
		listenerBlacklist: make(map[listenerKey]time.Time),
		active:            make(map[uint32]struct{}),
	}
}

// defaultDial dials via the transport package.
func defaultDial(ctx context.Context, rawURL string, maxFrame int) (peer.PacketChannel, error) {
	endpoint, err := config.ParseEndpoint(rawURL)
	if err != nil {
		return nil, err
	}
	address := endpoint.Address()
	if endpoint.Protocol == config.ProtocolUnix {
		address = endpoint.Path
	}
	if endpoint.Protocol == config.ProtocolWS || endpoint.Protocol == config.ProtocolWSS {
		address = rawURL
	}
	return transport.DialPacketChannel(ctx, string(endpoint.Protocol), address, maxFrame)
}

// Start launches the dial loop.
func (c *Connector) Start(ctx context.Context) {
	if ctx == nil {
		return
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.wg.Add(1)
	go c.loop()
}

// Stop cancels the loop.
func (c *Connector) Stop() {
	c.mu.Lock()
	if c.closed || c.cancel == nil {
		c.mu.Unlock()
		return
	}
	c.closed = true
	cancel := c.cancel
	c.mu.Unlock()
	cancel()
	c.wg.Wait()
}

func (c *Connector) loop() {
	defer c.wg.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-timer.C:
		}
		c.collect()
		timer.Reset(c.cfg.LoopInterval)
	}
}

func (c *Connector) collect() {
	if c.cfg.Candidates == nil || c.cfg.Handoff == nil {
		return
	}
	c.peerBlacklist.cleanup()
	c.cleanupListenerBlacklist()

	for _, peerID := range c.cfg.Candidates() {
		if peerID == c.cfg.MyPeerID || c.cfg.HasDirectConn(peerID) {
			continue
		}
		if c.peerBlacklist.contains(peerID) {
			continue
		}
		c.mu.Lock()
		if _, running := c.active[peerID]; running {
			c.mu.Unlock()
			continue
		}
		c.active[peerID] = struct{}{}
		c.mu.Unlock()

		taskCtx, taskCancel := context.WithCancel(c.ctx)
		c.wg.Add(1)
		go func(peerID uint32) {
			defer c.wg.Done()
			defer c.clearActive(peerID)
			defer taskCancel()
			c.runDirectConnect(taskCtx, peerID)
		}(peerID)
	}
}

func (s *timedSet) cleanup() {
	s.mu.Lock()
	for peerID, inserted := range s.entries {
		if time.Since(inserted) >= s.timeout {
			delete(s.entries, peerID)
		}
	}
	s.mu.Unlock()
}

func (c *Connector) cleanupListenerBlacklist() {
	c.blacklistMu.Lock()
	for key, inserted := range c.listenerBlacklist {
		if time.Since(inserted) >= listenerBlacklistTimeout {
			delete(c.listenerBlacklist, key)
		}
	}
	c.blacklistMu.Unlock()
}

func (c *Connector) clearActive(peerID uint32) {
	c.mu.Lock()
	delete(c.active, peerID)
	c.mu.Unlock()
}

// runDirectConnect retries the full discovery+dial cycle with the reference
// backoff ladder until a direct connection exists.
func (c *Connector) runDirectConnect(ctx context.Context, dstPeerID uint32) {
	backoff := []time.Duration{time.Second, 2 * time.Second, 2 * time.Second, 5 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second, time.Minute}
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		if c.peerBlacklist.contains(dstPeerID) {
			return
		}
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff[min(attempt-1, len(backoff)-1)]):
			}
		}
		if err := c.connectOnce(ctx, dstPeerID); err == nil {
			return
		}
		if c.cfg.HasDirectConn(dstPeerID) {
			return
		}
	}
}

// connectOnce performs one discovery + dial cycle.
func (c *Connector) connectOnce(ctx context.Context, dstPeerID uint32) error {
	ipList, err := c.getIPList(ctx, dstPeerID)
	if err != nil {
		return err
	}

	listeners := expandListeners(ipList, c.cfg.DefaultProtocol, c.cfg.EnableIPv6)
	if len(listeners) == 0 {
		return fmt.Errorf("peer %d has no valid listener", dstPeerID)
	}

	// Process one scheme group at a time, highest priority last.
	for groupStart := len(listeners); groupStart > 0; {
		groupEnd := groupStart
		scheme := listeners[groupStart-1].scheme
		for groupStart > 0 && listeners[groupStart-1].scheme == scheme {
			groupStart--
		}
		var wg sync.WaitGroup
		for _, entry := range listeners[groupStart:groupEnd] {
			for _, target := range c.expandAddrs(ipList, entry, dstPeerID) {
				wg.Add(1)
				go func(dstPeerID uint32, target string) {
					defer wg.Done()
					c.tryConnectToIP(ctx, dstPeerID, target)
				}(dstPeerID, target)
			}
		}
		wg.Wait()
		if c.cfg.HasDirectConn(dstPeerID) {
			return nil
		}
	}
	return nil
}

type listenerEntry struct {
	url    string
	scheme string
	host   string
	port   uint16
}

// expandListeners filters and orders the remote's listeners: ring dropped,
// port+host required, IPv6 gated, scheme priority ascending (default > udp >
// rest).
func expandListeners(response *peer_rpc.GetIpListResponse, defaultProtocol string, enableIPv6 bool) []listenerEntry {
	var entries []listenerEntry
	for _, raw := range response.GetListeners() {
		url := raw.GetUrl()
		if url == "" {
			continue
		}
		endpoint, err := config.ParseEndpoint(url)
		if err != nil {
			continue
		}
		scheme := string(endpoint.Protocol)
		if scheme == "ring" {
			continue
		}
		host := endpoint.Host
		port := endpoint.Port
		if port == 0 || host == "" {
			continue
		}
		if !enableIPv6 && isV6Host(host) {
			continue
		}
		entries = append(entries, listenerEntry{url: url, scheme: scheme, host: host, port: port})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return schemePriority(entries[i].scheme, defaultProtocol) < schemePriority(entries[j].scheme, defaultProtocol)
	})
	return entries
}

func schemePriority(scheme, defaultProtocol string) int {
	switch {
	case scheme == defaultProtocol:
		return 3
	case scheme == "udp":
		return 2
	default:
		return 1
	}
}

func isV6Host(host string) bool {
	return strings.Contains(host, ":")
}

// candidateIPs lists the remote's interface and public addresses.
func candidateIPs(response *peer_rpc.GetIpListResponse) (v4 []netip.Addr, v6 []netip.Addr) {
	for _, raw := range response.GetInterfaceIpv4S() {
		if addr, err := protoIPv4ToAddr(raw); err == nil {
			v4 = append(v4, addr)
		}
	}
	if pub := response.GetPublicIpv4(); pub != nil {
		if addr, err := protoIPv4ToAddr(pub); err == nil {
			v4 = append(v4, addr)
		}
	}
	for _, raw := range response.GetInterfaceIpv6S() {
		if addr, err := protoIPv6ToAddr(raw); err == nil {
			v6 = append(v6, addr)
		}
	}
	if pub := response.GetPublicIpv6(); pub != nil {
		if addr, err := protoIPv6ToAddr(pub); err == nil {
			v6 = append(v6, addr)
		}
	}
	return dedupAddrs(v4), dedupAddrs(v6)
}

func protoIPv4ToAddr(value *common.Ipv4Addr) (netip.Addr, error) {
	if value == nil {
		return netip.Addr{}, errors.New("missing IPv4")
	}
	return netip.AddrFrom4([4]byte{
		byte(value.Addr >> 24), byte(value.Addr >> 16), byte(value.Addr >> 8), byte(value.Addr),
	}), nil
}

func protoIPv6ToAddr(value *common.Ipv6Addr) (netip.Addr, error) {
	if value == nil {
		return netip.Addr{}, errors.New("missing IPv6")
	}
	word := func(v uint32) (byte, byte, byte, byte) {
		return byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)
	}
	b0, b1, b2, b3 := word(value.Part1)
	b4, b5, b6, b7 := word(value.Part2)
	b8, b9, b10, b11 := word(value.Part3)
	b12, b13, b14, b15 := word(value.Part4)
	return netip.AddrFrom16([16]byte{b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15}), nil
}

// expandAddrs turns one listener into concrete dial targets, expanding
// unspecified hosts with the remote's interface and public addresses.
func (c *Connector) expandAddrs(response *peer_rpc.GetIpListResponse, entry listenerEntry, dstPeerID uint32) []string {
	isUDP := entry.scheme == "udp"

	if !strings.Contains(entry.host, ":") || !isV6Host(entry.host) {
		// IPv4 or hostname listener.
		if ip, err := netip.ParseAddr(entry.host); err == nil {
			if ip.IsUnspecified() {
				v4, _ := candidateIPs(response)
				var targets []string
				for _, candidate := range v4 {
					if c.selfListener(candidate, entry.port, isUDP) {
						continue
					}
					targets = append(targets, replaceHost(entry.url, candidate.String()))
				}
				return targets
			}
			if ip.IsLoopback() {
				return nil
			}
			if c.selfListener(ip, entry.port, isUDP) {
				return nil
			}
			return []string{entry.url}
		}
		// Hostname: dial the URL as-is.
		return []string{entry.url}
	}

	// IPv6 listener.
	inner := strings.Trim(entry.host, "[]")
	if ip, err := netip.ParseAddr(inner); err == nil && ip.IsUnspecified() {
		_, v6 := candidateIPs(response)
		var targets []string
		seen := make(map[netip.Addr]struct{})
		for _, candidate := range v6 {
			if !usablePublicV6(candidate) {
				continue
			}
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			if c.selfListener(candidate, entry.port, isUDP) {
				continue
			}
			targets = append(targets, replaceHost(entry.url, candidate.String()))
		}
		return targets
	}
	if isV6Managed(inner) {
		return nil
	}
	if ip, err := netip.ParseAddr(inner); err == nil {
		if ip.IsLoopback() {
			return nil
		}
		if c.selfListener(ip, entry.port, isUDP) {
			return nil
		}
	}
	return []string{entry.url}
}

// usablePublicV6 filters loopback, unspecified, ULA, link-local, and
// multicast candidates for direct connection targets.
func usablePublicV6(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsLoopback() && !ip.IsUnspecified() &&
		!ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast()
}

// isV6Managed reports whether the address looks like an EasyTier overlay
// address (unique-local with the reference fd79:bcdb:ef98::/48 prefix).
func isV6Managed(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	managed := netip.MustParsePrefix("fd79:bcdb:ef98::/48")
	return managed.Contains(ip)
}

func (c *Connector) selfListener(ip netip.Addr, port uint16, udp bool) bool {
	if c.cfg.IsSelfListener == nil {
		return false
	}
	return c.cfg.IsSelfListener(ip, port, udp)
}

// replaceHost swaps the host portion of a tunnel URL, preserving the port.
func replaceHost(rawURL, newHost string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return rawURL
	}
	if _, port, splitErr := net.SplitHostPort(parsed.Host); splitErr == nil {
		parsed.Host = net.JoinHostPort(newHost, port)
	} else {
		parsed.Host = newHost
	}
	return parsed.String()
}

// tryConnectToIP attempts one dial target with the per-URL retry ladder,
// blacklisting the target when retries exhaust.
func (c *Connector) tryConnectToIP(ctx context.Context, dstPeerID uint32, target string) {
	backoffMS := []int{1000, 2000, 4000}
	if c.listenerBlacklisted(dstPeerID, target) {
		return
	}
	for attempt := 0; attempt <= len(backoffMS); attempt++ {
		if ctx.Err() != nil {
			return
		}
		if c.cfg.HasDirectConn(dstPeerID) {
			return
		}
		if err := c.connectToIP(ctx, dstPeerID, target); err == nil {
			return
		}
		if c.cfg.HasDirectConn(dstPeerID) {
			return
		}
		if attempt == len(backoffMS) {
			c.blacklistListener(dstPeerID, target)
			return
		}
		jitter := rand.Intn(backoffMS[attempt]/2+1) - backoffMS[attempt]/2
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(backoffMS[attempt]+jitter) * time.Millisecond):
		}
	}
}

func (c *Connector) listenerBlacklisted(peerID uint32, target string) bool {
	c.blacklistMu.Lock()
	defer c.blacklistMu.Unlock()
	key := listenerKey{peerID: peerID, url: target}
	inserted, ok := c.listenerBlacklist[key]
	if !ok {
		return false
	}
	if time.Since(inserted) >= listenerBlacklistTimeout {
		delete(c.listenerBlacklist, key)
		return false
	}
	return true
}

func (c *Connector) blacklistListener(peerID uint32, target string) {
	c.blacklistMu.Lock()
	c.listenerBlacklist[listenerKey{peerID: peerID, url: target}] = time.Now()
	c.blacklistMu.Unlock()
}

// connectToIP performs one dial toward target, using the UDP punch-assist
// path for public UDP listeners.
func (c *Connector) connectToIP(ctx context.Context, dstPeerID uint32, target string) error {
	endpoint, err := config.ParseEndpoint(target)
	if err != nil {
		return err
	}

	if endpoint.Protocol == config.ProtocolUDP {
		host := endpoint.Host
		port := endpoint.Port
		if port == 0 {
			return fmt.Errorf("udp listener %s has no port", target)
		}
		ip, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			// Hostnames fall back to a plain dial.
			return c.dialDirect(ctx, dstPeerID, target)
		}
		if ip.Is6() {
			return c.connectViaPunchV6(ctx, dstPeerID, target, ip, port)
		}
		if isPublicIPv4(ip) {
			if err := c.connectViaPunchV4(ctx, dstPeerID, target, ip, port); err == nil {
				return nil
			}
			return c.dialDirect(ctx, dstPeerID, target)
		}
		return c.dialDirect(ctx, dstPeerID, target)
	}
	return c.dialDirect(ctx, dstPeerID, target)
}

func isPublicIPv4(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsUnspecified() && ip != netip.IPv4Unspecified()
}

func (c *Connector) dialDirect(ctx context.Context, dstPeerID uint32, target string) error {
	dialCtx, cancel := context.WithTimeout(ctx, directDialTimeout)
	defer cancel()
	channel, err := c.cfg.Dial(dialCtx, target, c.cfg.MaxFrame)
	if err != nil {
		return err
	}
	if err := c.cfg.Handoff(ctx, channel, dstPeerID); err != nil {
		_ = closeChannel(channel)
		return err
	}
	return nil
}

// connectViaPunchV4 asks the remote to punch toward our mapped address and
// then dials with the same socket so the NAT mapping is shared.
func (c *Connector) connectViaPunchV4(ctx context.Context, dstPeerID uint32, target string, ip netip.Addr, port uint16) error {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("bind punch socket for %s: %w", target, err)
	}
	mapped, mapErr := c.cfg.Stun.GetUDPPortMappingWithSocket(ctx, socket)
	if mapErr != nil {
		_ = socket.Close()
		return fmt.Errorf("get udp port mapping for %s: %w", target, mapErr)
	}

	// Best effort: the punch assist only improves the odds.
	assistCtx, cancel := context.WithTimeout(ctx, udpPunchAssistTimeout)
	_, _ = c.callPunchAssist(assistCtx, dstPeerID, mapped, port)
	cancel()

	session, dialErr := transport.DialUDPWithSocket(ctx, socket, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(port)})
	if dialErr != nil {
		_ = socket.Close()
		return dialErr
	}
	if err := c.cfg.Handoff(ctx, session, dstPeerID); err != nil {
		_ = session.Close()
		return err
	}
	return nil
}

// connectViaPunchV6 mirrors the v4 path with an IPv6 socket and connector
// address derived from the host's public IPv6 (best effort).
func (c *Connector) connectViaPunchV6(ctx context.Context, dstPeerID uint32, target string, ip netip.Addr, port uint16) error {
	socket, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero})
	if err != nil {
		return fmt.Errorf("bind punch socket for %s: %w", target, err)
	}

	// Best effort punch assist from our public IPv6, if any.
	if publicV6 := c.publicIPv6(); publicV6.IsValid() {
		local, localErr := netip.ParseAddrPort(socket.LocalAddr().String())
		if localErr == nil {
			assistCtx, cancel := context.WithTimeout(ctx, udpPunchAssistTimeout)
			_, _ = c.callPunchAssist(assistCtx, dstPeerID, netip.AddrPortFrom(publicV6, local.Port()), port)
			cancel()
		}
	}

	session, dialErr := transport.DialUDPWithSocket(ctx, socket, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(port)})
	if dialErr != nil {
		_ = socket.Close()
		return dialErr
	}
	if err := c.cfg.Handoff(ctx, session, dstPeerID); err != nil {
		_ = session.Close()
		return err
	}
	return nil
}

func (c *Connector) publicIPv6() netip.Addr {
	for _, raw := range c.cfg.Stun.GetStunInfo().GetPublicIp() {
		addr, err := netip.ParseAddr(raw)
		if err == nil && addr.Is6() && !addr.Is4In6() {
			return addr
		}
	}
	return netip.Addr{}
}

func (c *Connector) getIPList(ctx context.Context, dstPeerID uint32) (*peer_rpc.GetIpListResponse, error) {
	body, err := callProto(ctx, c.cfg.RPC, dstPeerID, c.cfg.Domain, ServiceName, MethodGetIpList, &peer_rpc.GetIpListRequest{}, getIPListTimeout)
	if err != nil {
		if errors.Is(err, rpc.ErrNoService) {
			c.peerBlacklist.insert(dstPeerID)
		}
		return nil, err
	}
	var response peer_rpc.GetIpListResponse
	if err := (protojson.UnmarshalOptions{}).Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode ip list response: %w", err)
	}
	return &response, nil
}

func (c *Connector) callPunchAssist(ctx context.Context, dstPeerID uint32, connectorAddr netip.AddrPort, listenerPort uint16) ([]byte, error) {
	addrProto, err := addrPortToProto(connectorAddr)
	if err != nil {
		return nil, err
	}
	return callProto(ctx, c.cfg.RPC, dstPeerID, c.cfg.Domain, ServiceName, MethodSendUdpHolePunchPacket, &peer_rpc.SendUdpHolePunchPacketRequest{
		ConnectorAddr: addrProto,
		ListenerPort:  uint32(listenerPort),
	}, udpPunchAssistTimeout)
}

// closeChannel closes a packet channel when it supports Close.
func closeChannel(channel peer.PacketChannel) error {
	if closer, ok := channel.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// callProto marshals one request, invokes the peer RPC, and enforces a
// timeout context.
func callProto(ctx context.Context, mgr *rpc.PeerRpcManager, dstPeerID uint32, domain, serviceName string, method uint32, request proto.Message, timeout time.Duration) ([]byte, error) {
	body, err := protojson.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode rpc request: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return mgr.Call(callCtx, dstPeerID, domain, serviceName, method, body)
}

type protoMessage interface {
	String() string
	Reset()
	ProtoMessage()
}

func addrPortToProto(addr netip.AddrPort) (*common.SocketAddr, error) {
	if !addr.IsValid() {
		return nil, errors.New("socket address is invalid")
	}
	if addr.Addr().Is4() {
		raw := addr.Addr().As4()
		return &common.SocketAddr{
			Ip:   &common.SocketAddr_Ipv4{Ipv4: &common.Ipv4Addr{Addr: uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])}},
			Port: uint32(addr.Port()),
		}, nil
	}
	raw := addr.Addr().As16()
	return &common.SocketAddr{
		Ip: &common.SocketAddr_Ipv6{Ipv6: &common.Ipv6Addr{
			Part1: uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3]),
			Part2: uint32(raw[4])<<24 | uint32(raw[5])<<16 | uint32(raw[6])<<8 | uint32(raw[7]),
			Part3: uint32(raw[8])<<24 | uint32(raw[9])<<16 | uint32(raw[10])<<8 | uint32(raw[11]),
			Part4: uint32(raw[12])<<24 | uint32(raw[13])<<16 | uint32(raw[14])<<8 | uint32(raw[15]),
		}},
		Port: uint32(addr.Port()),
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package stun

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
)

// Default STUN server lists used when the configuration omits them.
const (
	DefaultUDPServerList = "txt:stun.easytier.cn,stun.miwifi.com,stun.chat.bilibili.com,stun.hitv.com"
	DefaultTCPServerList = "stun.hot-chilli.net,stun.fitauto.ru,fwa.lifesizecloud.com,global.turn.twilio.com,turn.cloudflare.com,stun.voip.blackberry.com,stun.radiojar.com"
	DefaultUDPServerV6   = "txt:stun-v6.easytier.cn"
)

// Refresh cadence for the detection loops.
const (
	detectRetryInterval = 10 * time.Second
	detectOKInterval    = 600 * time.Second
	v6RetryInterval     = 60 * time.Second
	v6OKInterval        = 360 * time.Second
)

// Source is the NAT information surface consumed by hole punching and the
// direct connector. Collector implements it; tests provide mocks.
type Source interface {
	// GetStunInfo returns the latest NAT snapshot. It never blocks on a
	// detection round; unknown values are reported until one completes.
	GetStunInfo() *common.StunInfo
	// GetUDPPortMapping maps localPort (0 = ephemeral) through a STUN server.
	GetUDPPortMapping(ctx context.Context, localPort uint16) (netip.AddrPort, error)
	// GetUDPPortMappingWithSocket maps an existing socket and leaves it usable.
	GetUDPPortMappingWithSocket(ctx context.Context, socket *net.UDPConn) (netip.AddrPort, error)
	// GetTCPPortMapping maps a bound local TCP port through a STUN server.
	GetTCPPortMapping(ctx context.Context, localPort uint16) (netip.AddrPort, error)
}

// Collector runs periodic NAT behavior detection and serves mapping queries.
type Collector struct {
	udpServers []string
	tcpServers []string
	v6Servers  []string

	mu           sync.Mutex
	udpResult    *DetectResult
	tcpResult    *DetectResult
	publicV6     netip.Addr
	lastUpdate   atomic.Int64
	redetect     chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	stopOnce     sync.Once
	started      atomic.Bool
	maxIPPerHost int
}

// NewCollector builds a collector; empty server lists select the defaults.
func NewCollector(udpServers, tcpServers, v6Servers []string) *Collector {
	return &Collector{
		udpServers:   withDefaults(udpServers, DefaultUDPServerList),
		tcpServers:   withDefaults(tcpServers, DefaultTCPServerList),
		v6Servers:    withDefaults(v6Servers, DefaultUDPServerV6),
		redetect:     make(chan struct{}, 1),
		maxIPPerHost: 1,
	}
}

func withDefaults(servers []string, fallback string) []string {
	if len(servers) == 0 {
		return strings.Split(fallback, ",")
	}
	return servers
}

// Start launches the background detection loops. It is idempotent.
func (c *Collector) Start(ctx context.Context) {
	if c == nil || ctx == nil {
		return
	}
	if !c.started.CompareAndSwap(false, true) {
		return
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	go c.udpLoop()
	go c.tcpLoop()
	go c.publicIPv6Loop()
}

// Stop cancels the background loops.
func (c *Collector) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
	})
}

// Redetect triggers an immediate re-detection round.
func (c *Collector) Redetect() {
	if c == nil {
		return
	}
	select {
	case c.redetect <- struct{}{}:
	default:
	}
}

func (c *Collector) udpLoop() {
	if c.ctx == nil {
		return
	}
	for {
		servers := pickServers(c.udpServers)
		result, err := c.runUDPDetect(c.ctx, servers, 0)
		sleep := detectRetryInterval
		if err == nil {
			natType := result.NATType()
			if natType == NatTypeSymmetric && result.ExtraBind == nil {
				// One more binding from a fresh socket distinguishes easy
				// symmetric allocation from hard symmetric.
				for _, server := range result.AvailableServers() {
					extra, extraErr := extraBindRequest(c.ctx, server)
					if extraErr == nil {
						result.ExtraBind = &extra
						break
					}
				}
			}
			c.mu.Lock()
			c.udpResult = result
			c.mu.Unlock()
			c.lastUpdate.Store(time.Now().Unix())
			if natType != NatTypeUnknown && (natType != NatTypeSymmetric || result.ExtraBind != nil) {
				sleep = detectOKInterval
			}
		}
		select {
		case <-c.ctx.Done():
			return
		case <-c.redetect:
		case <-time.After(sleep):
		}
	}
}

func (c *Collector) tcpLoop() {
	if c.ctx == nil {
		return
	}
	for {
		servers := pickServers(c.tcpServers)
		result := c.runTCPDetect(c.ctx, servers)
		sleep := detectRetryInterval
		if result != nil {
			c.mu.Lock()
			c.tcpResult = result
			c.mu.Unlock()
			c.lastUpdate.Store(time.Now().Unix())
			if result.NATType() != NatTypeUnknown {
				sleep = detectOKInterval
			}
		}
		select {
		case <-c.ctx.Done():
			return
		case <-c.redetect:
		case <-time.After(sleep):
		}
	}
}

func (c *Collector) publicIPv6Loop() {
	if c.ctx == nil {
		return
	}
	for {
		servers := pickServers(c.v6Servers)
		var publicV6 netip.Addr
		found := false
		for _, server := range servers {
			if !server.Addr().Is6() {
				continue
			}
			socket, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero})
			if err != nil {
				break
			}
			response, err := singleBindRequest(c.ctx, socket, server)
			_ = socket.Close()
			if err == nil && response.MappedValid && response.MappedAddr.Addr().Is6() && !response.MappedAddr.Addr().Is4In6() {
				publicV6 = response.MappedAddr.Addr()
				found = true
				break
			}
		}
		if found {
			c.mu.Lock()
			c.publicV6 = publicV6
			c.mu.Unlock()
			c.lastUpdate.Store(time.Now().Unix())
		}
		sleep := v6RetryInterval
		if found {
			sleep = v6OKInterval
		}
		select {
		case <-c.ctx.Done():
			return
		case <-c.redetect:
		case <-time.After(sleep):
		}
	}
}

// pickServers keeps the first two entries and appends one random remainder,
// matching the reference server selection.
func pickServers(hosts []string) []netip.AddrPort {
	if len(hosts) == 0 {
		return nil
	}
	selected := make([]string, 0, 3)
	selected = append(selected, hosts[:minInt(2, len(hosts))]...)
	if len(hosts) > 2 {
		selected = append(selected, hosts[2+rand.Intn(len(hosts)-2)])
	}
	return ResolveServers(context.Background(), selected)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ResolveServers expands host entries (host, host:port, ip:port, txt:domain)
// into server addresses, taking up to maxIPPerHost addresses per host.
func ResolveServers(ctx context.Context, hosts []string) []netip.AddrPort {
	var servers []netip.AddrPort
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if strings.HasPrefix(host, "txt:") {
			records, err := net.LookupTXT(strings.TrimPrefix(host, "txt:"))
			if err != nil {
				continue
			}
			for _, record := range records {
				for _, entry := range strings.FieldsFunc(record, func(r rune) bool { return r == ' ' || r == ',' || r == ';' }) {
					if addr, ok := resolveOne(ctx, entry); ok {
						servers = append(servers, addr)
					}
				}
			}
			continue
		}
		if addr, ok := resolveOne(ctx, host); ok {
			servers = append(servers, addr)
		}
	}
	return servers
}

func resolveOne(ctx context.Context, host string) (netip.AddrPort, bool) {
	if host == "" {
		return netip.AddrPort{}, false
	}
	hostPort := host
	if !strings.Contains(host, ":") {
		hostPort = host + ":" + strconv.Itoa(DefaultSTUNPort)
	}
	if addr, err := netip.ParseAddrPort(hostPort); err == nil {
		return addr, true
	}
	hostname, portRaw, err := net.SplitHostPort(hostPort)
	if err != nil {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portRaw, 10, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(ips[0].IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	return netip.AddrPortFrom(ip, uint16(port)), true
}

func (c *Collector) runUDPDetect(ctx context.Context, servers []netip.AddrPort, sourcePort uint16) (*DetectResult, error) {
	if len(servers) == 0 {
		return nil, errors.New("no STUN servers available")
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(sourcePort)})
	if err != nil {
		return nil, fmt.Errorf("bind UDP probe socket: %w", err)
	}
	defer socket.Close()
	return udpDetect(ctx, socket, servers)
}

func (c *Collector) runTCPDetect(ctx context.Context, servers []netip.AddrPort) *DetectResult {
	if len(servers) == 0 {
		return nil
	}
	result := &DetectResult{Transport: TransportTCP}
	sourcePort := uint16(0)
	for _, server := range servers {
		response, err := tcpBindRequest(ctx, server, sourcePort)
		if err != nil {
			continue
		}
		if sourcePort == 0 {
			sourcePort = response.LocalAddr.Port()
		}
		result.Responses = append(result.Responses, response)
		if len(result.Responses) >= maxTCPSamples {
			break
		}
	}
	if len(result.Responses) == 0 {
		return nil
	}
	result.SourceAddr = result.Responses[0].LocalAddr
	return result
}

// extraBindRequest performs one plain binding from an ephemeral socket.
func extraBindRequest(ctx context.Context, server netip.AddrPort) (BindResponse, error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return BindResponse{}, fmt.Errorf("bind extra probe socket: %w", err)
	}
	defer socket.Close()
	return singleBindRequest(ctx, socket, server)
}

// singleBindRequest sends one no-change binding and waits for its response.
func singleBindRequest(ctx context.Context, socket *net.UDPConn, server netip.AddrPort) (BindResponse, error) {
	demux := newResponseDemux()
	reader := startProbeReader(socket, demux)
	defer func() {
		reader.Stop()
		demux.close()
	}()
	return udpBindRequest(ctx, socket, demux, server, false, false)
}

// GetStunInfo returns the current NAT snapshot as the proto message.
func (c *Collector) GetStunInfo() *common.StunInfo {
	if c == nil {
		return &common.StunInfo{UdpNatType: common.NatType_Unknown, TcpNatType: common.NatType_Unknown}
	}
	c.mu.Lock()
	udpResult, tcpResult, publicV6 := c.udpResult, c.tcpResult, c.publicV6
	c.mu.Unlock()

	info := &common.StunInfo{
		UdpNatType: common.NatType_Unknown,
		TcpNatType: common.NatType_Unknown,
	}
	var publicIPs []string
	seen := make(map[string]struct{})
	addIP := func(ip string) {
		if _, ok := seen[ip]; ok {
			return
		}
		seen[ip] = struct{}{}
		publicIPs = append(publicIPs, ip)
	}
	if udpResult != nil {
		info.UdpNatType = common.NatType(udpResult.NATType())
		info.MinPort = uint32(udpResult.minPort())
		info.MaxPort = uint32(udpResult.maxPort())
		for _, ip := range udpResult.PublicIPs() {
			addIP(ip.String())
		}
	}
	if tcpResult != nil {
		info.TcpNatType = common.NatType(tcpResult.NATType())
		if info.MinPort == 0 {
			info.MinPort = uint32(tcpResult.minPort())
			info.MaxPort = uint32(tcpResult.maxPort())
		}
		for _, ip := range tcpResult.PublicIPs() {
			addIP(ip.String())
		}
	}
	if publicV6.IsValid() {
		addIP(publicV6.String())
	}
	info.LastUpdateTime = c.lastUpdate.Load()
	info.PublicIp = publicIPs
	return info
}

// GetUDPPortMapping maps localPort (0 selects an ephemeral port).
func (c *Collector) GetUDPPortMapping(ctx context.Context, localPort uint16) (netip.AddrPort, error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(localPort)})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bind UDP mapping socket: %w", err)
	}
	defer socket.Close()
	return c.GetUDPPortMappingWithSocket(ctx, socket)
}

// GetUDPPortMappingWithSocket maps an existing socket, preferring servers that
// responded to the last detection round. The socket remains usable.
func (c *Collector) GetUDPPortMappingWithSocket(ctx context.Context, socket *net.UDPConn) (netip.AddrPort, error) {
	if c == nil {
		return netip.AddrPort{}, errors.New("stun collector is nil")
	}
	c.mu.Lock()
	var servers []netip.AddrPort
	if c.udpResult != nil {
		servers = c.udpResult.AvailableServers()
	}
	c.mu.Unlock()

	if len(servers) == 0 {
		servers = pickServers(c.udpServers)
		if len(servers) > 2 {
			servers = servers[:2]
		}
	}
	if len(servers) == 0 {
		return netip.AddrPort{}, errors.New("no STUN servers available")
	}

	for _, server := range servers {
		response, err := singleBindRequest(ctx, socket, server)
		if err != nil {
			continue
		}
		if response.MappedValid {
			return response.MappedAddr, nil
		}
	}
	return netip.AddrPort{}, errors.New("STUN port mapping failed")
}

// GetTCPPortMapping maps a bound local TCP port through a TCP STUN server.
func (c *Collector) GetTCPPortMapping(ctx context.Context, localPort uint16) (netip.AddrPort, error) {
	if c == nil {
		return netip.AddrPort{}, errors.New("stun collector is nil")
	}
	c.mu.Lock()
	var servers []netip.AddrPort
	if c.tcpResult != nil {
		servers = c.tcpResult.AvailableServers()
	}
	c.mu.Unlock()
	if len(servers) == 0 {
		servers = pickServers(c.tcpServers)
		if len(servers) > 2 {
			servers = servers[:2]
		}
	}
	if len(servers) == 0 {
		return netip.AddrPort{}, errors.New("no TCP STUN servers available")
	}
	for _, server := range servers {
		response, err := tcpBindRequest(ctx, server, localPort)
		if err != nil {
			continue
		}
		if response.MappedValid {
			return response.MappedAddr, nil
		}
	}
	return netip.AddrPort{}, errors.New("TCP STUN port mapping failed")
}

// MockSource is a fixed-value Source for tests.
type MockSource struct {
	Info       *common.StunInfo
	MappedAddr netip.AddrPort
}

// GetStunInfo implements Source.
func (m *MockSource) GetStunInfo() *common.StunInfo {
	if m.Info == nil {
		return &common.StunInfo{UdpNatType: common.NatType_Unknown, TcpNatType: common.NatType_Unknown}
	}
	return m.Info
}

// GetUDPPortMapping implements Source.
func (m *MockSource) GetUDPPortMapping(ctx context.Context, localPort uint16) (netip.AddrPort, error) {
	return m.mapping(localPort)
}

// GetUDPPortMappingWithSocket implements Source.
func (m *MockSource) GetUDPPortMappingWithSocket(ctx context.Context, socket *net.UDPConn) (netip.AddrPort, error) {
	local, err := netip.ParseAddrPort(socket.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return m.mapping(local.Port())
}

// GetTCPPortMapping implements Source.
func (m *MockSource) GetTCPPortMapping(ctx context.Context, localPort uint16) (netip.AddrPort, error) {
	return m.mapping(localPort)
}

func (m *MockSource) mapping(localPort uint16) (netip.AddrPort, error) {
	if m.MappedAddr.IsValid() {
		return m.MappedAddr, nil
	}
	if localPort == 0 {
		localPort = 40144
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), localPort), nil
}

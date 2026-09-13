// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/acl"
	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/credential"
	"github.com/EasyTier/EasyTier/go/internal/dns"
	"github.com/EasyTier/EasyTier/go/internal/gateway"
	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/peercenter"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/publicipv6"
	"github.com/EasyTier/EasyTier/go/internal/ratelimit"
	"github.com/EasyTier/EasyTier/go/internal/route"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/stats"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"github.com/EasyTier/EasyTier/go/internal/tun"
	"github.com/EasyTier/EasyTier/go/internal/webclient"
)

// PacketHandler receives packets routed to this node. It is called after the
// built-in RPC and TUN delivery paths have had an opportunity to consume them.
type PacketHandler func(context.Context, protocol.Packet) error

// PortalForwarder sinks mesh IP packets into a VPN portal client (stock
// WireGuard return path). It is implemented by vpnportal.Portal; the
// interface keeps core decoupled from the portal package.
type PortalForwarder interface {
	DeliverToClient(ctx context.Context, ipPacket []byte) (bool, error)
}

// NodeOptions wires the production network vertical slice together. A TCP
// listener is always created; UDP and the optional management/web services are
// created only when configured by the caller.
type NodeOptions struct {
	Address    string
	UDPAddress string
	MaxFrame   int

	PeerManager      peer.PeerConnectionManagerConfig
	Peers            []string
	ReconnectInitial time.Duration
	ReconnectMax     time.Duration
	RouteEngine      *route.Engine
	RouteRefresh     time.Duration
	ACL              *acl.Policy
	ReceiveLimiter   *ratelimit.Limiter
	Stats            *stats.Counters

	PacketHandler PacketHandler
	RPCHandler    rpc.Handler
	RPCServer     *rpc.Server
	WebClient     *webclient.Client
	WebServer     *webclient.Server
	WebSocket     *transport.WebSocketListener
	DNS           *dns.Server

	// PeerCenterNetworkName enables the peer-center RPC service and periodic
	// jobs when non-empty. The RPC service is scoped to this network name.
	PeerCenterNetworkName string

	// P2P enables the NAT traversal stack (STUN, hole punching, direct and
	// manual connectors) when non-nil.
	P2P *P2PConfig

	TUN              tun.Device
	TUNMTU           int
	TUNDestination   uint32
	NoTUN            bool
	EnableEncryption bool
	// NetworkSecret is the raw network identity secret; it verifies OSPF
	// credential proofs. Empty on credential nodes.
	NetworkSecret string
	// TrustedCredentials are the locally managed credentials this admin node
	// vouches for; they are signed and published in its OSPF LSA, and their
	// public keys classify connecting noise peers as credential peers.
	TrustedCredentials []credential.Credential
	DHCP               bool
	IPv4               string
	IPv6               string
	TunAddresses       *tun.AssignedAddresses

	// EnableOSPF starts the OSPF LSA flooder (route/flood.go) and feeds its
	// converged routes into the peer router. LSA flooding runs over the
	// peer-RPC mesh. OSPFDomain scopes the OSPF RPC service; it defaults to
	// PeerCenterNetworkName, then to "easytier".
	EnableOSPF bool
	OSPFDomain string

	// EnableICMPProxy installs gateway.IcmpProxy into the inbound packet
	// path (Rust PeerPacketFilter equivalent). ICMPProxyMappings carries
	// optional CIDR translations; ICMPExitNode marks this node as exit.
	EnableICMPProxy   bool
	ICMPProxyMappings []gateway.CIDRMapping
	ICMPExitNode      bool

	// RAAnnounceInterval paces IPv6 router advertisements towards the local
	// network (also in NoTUN mode, where the RA is cached for management).
	// Zero selects DefaultRAAnnounceInterval.
	RAAnnounceInterval time.Duration

	// Portal sinks mesh IP packets addressed to VPN portal clients.
	Portal PortalForwarder
}

// DefaultRAAnnounceInterval paces periodic router advertisements.
const DefaultRAAnnounceInterval = 30 * time.Second

// ListenWithOptions creates a node with the configured peer manager and
// transports. PeerManager.LocalPeerID must be non-zero; use Listen or
// ListenWithIdentity for the deliberately minimal compatibility modes.
func ListenWithOptions(options NodeOptions) (*Node, error) {
	if options.Address == "" {
		return nil, errors.New("node TCP address is required")
	}
	if options.MaxFrame == 0 {
		options.MaxFrame = protocol.DefaultMaxStreamFrameSize
	}
	if options.PeerManager.LocalPeerID == 0 {
		return nil, errors.New("node peer manager local peer ID is required")
	}
	// No-TUN mode: skip TUN creation but still expose management.
	if options.NoTUN {
		options.TUN = nil
		options.TUNMTU = 0
		options.TUNDestination = 0
	}
	// Resolve MTU and DHCP/static assignments when a TUN device is present.
	if options.TUN != nil {
		rawMTU := options.TUNMTU
		hasAddrs := options.DHCP || strings.TrimSpace(options.IPv4) != "" || strings.TrimSpace(options.IPv6) != ""
		if hasAddrs {
			used := usedAddrsFromRoutes(options.RouteEngine)
			tunCfg := tun.TunConfig{
				IPv4:             options.IPv4,
				IPv6:             options.IPv6,
				DHCP:             options.DHCP,
				NoTUN:            options.NoTUN,
				MTU:              uint32(rawMTU),
				EnableEncryption: options.EnableEncryption,
			}
			assigned, err := tun.ResolveAssigned(tunCfg, used)
			if err != nil {
				return nil, fmt.Errorf("resolve TUN addresses: %w", err)
			}
			options.TunAddresses = &assigned
			if md, ok := options.TUN.(*tun.MemoryDevice); ok {
				if assigned.IPv4 != nil {
					_ = md.AssignIPv4(*assigned.IPv4)
				}
				if assigned.IPv6 != nil {
					_ = md.AssignIPv6(*assigned.IPv6)
				}
			}
			// Keep MTU in sync with assigned value.
			if assigned.MTU > 0 {
				options.TUNMTU = assigned.MTU
				if md, ok := options.TUN.(*tun.MemoryDevice); ok {
					_ = md.SetMTU(assigned.MTU)
				}
			} else if rawMTU > 0 {
				options.TUNMTU = rawMTU
			} else {
				options.TUNMTU = tun.EffectiveMTU(uint32(rawMTU), options.EnableEncryption)
			}
		} else {
			// No address assignment requested, just normalize MTU
			if options.TUNMTU <= 0 {
				options.TUNMTU = tun.EffectiveMTU(uint32(rawMTU), options.EnableEncryption)
				if options.TUNMTU <= 0 {
					options.TUNMTU = tun.DefaultMTU
				}
			}
			if md, ok := options.TUN.(*tun.MemoryDevice); ok && options.TUNMTU > 0 {
				_ = md.SetMTU(options.TUNMTU)
			}
		}
	} else if options.DHCP {
		// DHCP without TUN: still allocate an address for management visibility.
		used := usedAddrsFromRoutes(options.RouteEngine)
		tunCfg := tun.TunConfig{
			DHCP:             true,
			NoTUN:            true,
			MTU:              uint32(options.TUNMTU),
			EnableEncryption: options.EnableEncryption,
		}
		assigned, err := tun.ResolveAssigned(tunCfg, used)
		if err == nil {
			options.TunAddresses = &assigned
		}
	}
	peerConfig := options.PeerManager
	if options.RouteEngine != nil && peerConfig.Router == nil {
		peerConfig.Routes = routeMap(options.RouteEngine.Snapshot())
	}
	if options.ACL != nil {
		peerConfig.ACL = options.ACL
	}
	if options.ReceiveLimiter != nil {
		peerConfig.RecvLimiter = options.ReceiveLimiter
	}
	if options.Stats != nil {
		peerConfig.Stats = options.Stats
	}
	manager, err := peer.NewPeerConnectionManager(peerConfig)
	if err != nil {
		return nil, fmt.Errorf("create peer connection manager: %w", err)
	}
	listener, err := net.Listen("tcp", options.Address)
	if err != nil {
		_ = manager.Close()
		return nil, fmt.Errorf("listen on %q: %w", options.Address, err)
	}
	var udpService *transport.UDPService
	if options.UDPAddress != "" {
		udpService, err = transport.ListenUDP(options.UDPAddress)
		if err != nil {
			_ = listener.Close()
			_ = manager.Close()
			return nil, err
		}
	}
	if options.TUN != nil {
		// NoTUN already handled above; ensure MTU is valid. Destination may be
		// zero for dynamic routing (route by packet IP) to allow daemon auto-creation.
		if options.TUNMTU <= 0 {
			_ = listener.Close()
			if udpService != nil {
				_ = udpService.Close()
			}
			_ = manager.Close()
			return nil, errors.New("TUN requires a positive MTU")
		}
		// Validate MTU bounds for TUN (packetTooLarge check mirrors tun.ValidatePacket)
		if options.TUNMTU < tun.MinMTU || options.TUNMTU > tun.MaxMTU {
			_ = listener.Close()
			if udpService != nil {
				_ = udpService.Close()
			}
			_ = manager.Close()
			return nil, fmt.Errorf("%w: %d", tun.ErrInvalidMTU, options.TUNMTU)
		}
	}
	// Advertise the node's own listeners for direct-connector discovery.
	if options.P2P != nil {
		options.P2P.ExtraListeners = append(options.P2P.ExtraListeners, "tcp://"+listener.Addr().String())
		if udpService != nil {
			options.P2P.ExtraListeners = append(options.P2P.ExtraListeners, "udp://"+udpService.Address().String())
		}
	}
	return &Node{
		listener:    listener,
		maxFrame:    options.MaxFrame,
		connections: make(map[net.Conn]struct{}),
		runtime: &nodeRuntime{
			manager:            manager,
			udp:                udpService,
			peers:              append([]string(nil), options.Peers...),
			reconnectInitial:   options.ReconnectInitial,
			reconnectMax:       options.ReconnectMax,
			routeEngine:        options.RouteEngine,
			routeRefresh:       options.RouteRefresh,
			centerDomain:       options.PeerCenterNetworkName,
			p2pConfig:          options.P2P,
			p2pDomain:          options.PeerCenterNetworkName,
			packetHandler:      options.PacketHandler,
			rpcHandler:         options.RPCHandler,
			rpcServer:          options.RPCServer,
			webClient:          options.WebClient,
			webServer:          options.WebServer,
			webSocket:          options.WebSocket,
			dns:                options.DNS,
			stats:              options.Stats,
			acl:                options.ACL,
			receiveLimiter:     options.ReceiveLimiter,
			tun:                options.TUN,
			tunMTU:             options.TUNMTU,
			tunDestination:     options.TUNDestination,
			noTun:              options.NoTUN,
			networkSecret:      options.NetworkSecret,
			trustedCredentials: options.TrustedCredentials,
			tunAddresses:       options.TunAddresses,
			ospfEnabled:        options.EnableOSPF,
			ospfDomain:         options.OSPFDomain,
			icmpEnabled:        options.EnableICMPProxy,
			icmpMappings:       append([]gateway.CIDRMapping(nil), options.ICMPProxyMappings...),
			icmpExitNode:       options.ICMPExitNode,
			raInterval:         options.RAAnnounceInterval,
			portal:             options.Portal,
		},
	}, nil
}

type nodeRuntime struct {
	manager          *peer.PeerConnectionManager
	udp              *transport.UDPService
	peers            []string
	reconnectInitial time.Duration
	reconnectMax     time.Duration

	packetHandler  PacketHandler
	rpcHandler     rpc.Handler
	rpcServer      *rpc.Server
	webClient      *webclient.Client
	webServer      *webclient.Server
	webSocket      *transport.WebSocketListener
	dns            *dns.Server
	stats          *stats.Counters
	acl            *acl.Policy
	receiveLimiter *ratelimit.Limiter
	routeEngine    *route.Engine
	routeRefresh   time.Duration

	peerRPC      *rpc.PeerRpcManager
	center       *peercenter.Instance
	centerDomain string

	// p2pConfig and p2p carry the NAT traversal stack. p2pDomain scopes its
	// peer RPC services; p2p is published by the serve goroutine.
	p2pConfig          *P2PConfig
	networkSecret      string
	trustedCredentials []credential.Credential
	p2pDomain          string
	p2p                *p2pRuntime

	portal PortalForwarder

	ospfEnabled bool
	ospfDomain  string
	ospf        *route.Flooder
	ospfLinks   map[uint32]uint32

	icmpEnabled  bool
	icmpMappings []gateway.CIDRMapping
	icmpExitNode bool
	icmpProxy    *gateway.IcmpProxy

	raInterval time.Duration
	raProvider *publicipv6.Provider
	raCancel   context.CancelFunc
	raMu       sync.Mutex
	lastRA     []byte

	// auxCancel stops auxiliary loops (route refresh). serveCtx cannot be
	// used for them: it is canceled only when serveManaged returns, which
	// waits for those same loops via n.wg.
	auxMu     sync.Mutex
	auxCancel context.CancelFunc

	tun            tun.Device
	tunMTU         int
	tunDestination uint32
	tunPackets     chan []byte
	noTun          bool
	tunAddresses   *tun.AssignedAddresses

	// stateMu guards the lifecycle fields that are published by the serve
	// goroutine while Close and external observers may read them.
	stateMu   sync.RWMutex
	closeOnce sync.Once
	closeErr  error
}

// DHCP pool used when allocating addresses for TUN devices.
var dhcpPool = tun.DHCPPool

// EffectiveTUNMTU returns the effective TUN MTU after accounting for encryption
// overhead, matching Rust's mtu_in_config - 20 logic.
func EffectiveTUNMTU(mtu uint32, encryption bool) int {
	return tun.EffectiveMTU(mtu, encryption)
}

// usedAddrsFromRoutes extracts used IPv4 addresses from the route engine for
// DHCP conflict avoidance. The Go route engine stores peer IDs, so we synthesize
// placeholder addresses from the route destinations for collision testing. When
// the engine is nil, an empty set is returned.
func usedAddrsFromRoutes(engine *route.Engine) []netip.Addr {
	if engine == nil {
		return nil
	}
	routes := engine.Snapshot()
	addrs := make([]netip.Addr, 0, len(routes))
	for _, r := range routes {
		// Derive a deterministic pseudo-IP for the route's destination peer to
		// exercise conflict avoidance. This keeps allocation deterministic while
		// still avoiding clashes in tests that seed routes.
		ip := pseudoIPForPeer(r.Destination)
		if ip.IsValid() {
			addrs = append(addrs, ip)
		}
	}
	return addrs
}

func pseudoIPForPeer(peerID uint32) netip.Addr {
	// Map peerID to 10.144.144.x deterministically for conflict tests.
	// Skip .0 and .255, use low bytes.
	if peerID == 0 {
		return netip.Addr{}
	}
	last := byte(peerID % 254)
	if last == 0 {
		last = 1
	}
	// Avoid colliding with .0/.255; offset by 1
	octet := last + 1
	if octet == 255 {
		octet = 254
	}
	return netip.AddrFrom4([4]byte{10, 144, 144, octet})
}

// ResolveTUNAddresses is a convenience wrapper that resolves static/DHCP
// assignment for callers that already have a tun.TunConfig.
func ResolveTUNAddresses(cfg tun.TunConfig, used []netip.Addr) (*tun.AssignedAddresses, error) {
	assigned, err := tun.ResolveAssigned(cfg, used)
	if err != nil {
		return nil, err
	}
	return &assigned, nil
}

// TUNAddresses returns the assigned TUN addresses for this node, if any.
func (n *Node) TUNAddresses() *tun.AssignedAddresses {
	if n == nil || n.runtime == nil {
		return nil
	}
	return n.runtime.tunAddresses
}

// IsNoTUN reports whether the node was started in no-TUN mode.
func (n *Node) IsNoTUN() bool {
	if n == nil || n.runtime == nil {
		return false
	}
	return n.runtime.noTun
}

func (n *Node) serveManaged(ctx context.Context) error {
	if ctx == nil {
		return errors.New("node serve context is nil")
	}
	r := n.runtime
	if err := r.manager.Start(ctx); err != nil {
		return fmt.Errorf("start peer connection manager: %w", err)
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopClose := context.AfterFunc(ctx, func() { _ = n.Close() })
	defer stopClose()

	auxCtx, auxCancel := context.WithCancel(context.Background())
	r.setAuxCancel(auxCancel)
	defer auxCancel()

	if err := r.initCenter(serveCtx); err != nil {
		return err
	}
	if err := r.initFlooder(serveCtx); err != nil {
		return err
	}
	if err := r.initICMPProxy(); err != nil {
		return err
	}
	if err := r.initP2P(auxCtx); err != nil {
		return err
	}
	// The packet channel must exist before the RA announcer starts: its
	// goroutine reads r.tunPackets without further synchronization.
	if r.packetHandler != nil || r.rpcHandler != nil || r.center != nil || r.tun != nil {
		r.tunPackets = make(chan []byte, 128)
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			r.packetLoop(serveCtx)
		}()
	}
	r.startRAAnnouncer(serveCtx, &n.wg)

	if (r.routeEngine != nil || r.ospf != nil) && r.manager.Router != nil {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			r.refreshRoutes(auxCtx)
		}()
	}
	if r.tun != nil {
		runner, err := tun.NewRunner(r.tun, r.tunMTU, r.tunIngress, r.tunEgress)
		if err != nil {
			return fmt.Errorf("create TUN runner: %w", err)
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			_ = runner.Run(serveCtx)
		}()
	}
	if r.udp != nil {
		n.wg.Add(2)
		go func() {
			defer n.wg.Done()
			_ = r.udp.Serve(serveCtx)
		}()
		go func() {
			defer n.wg.Done()
			r.acceptUDP(serveCtx, &n.wg)
		}()
	}
	if r.rpcServer != nil {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			_ = r.rpcServer.Serve(serveCtx)
		}()
	}
	if r.webServer != nil && r.webServer.Addr() != nil {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			_ = r.webServer.Serve(serveCtx)
		}()
	}
	if r.webClient != nil {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			_ = r.webClient.Run(serveCtx)
		}()
	}
	if r.webSocket != nil {
		n.wg.Add(2)
		go func() {
			defer n.wg.Done()
			_ = r.webSocket.Serve(serveCtx)
		}()
		go func() {
			defer n.wg.Done()
			r.acceptWebSocket(serveCtx, &n.wg)
		}()
	}
	if r.dns != nil {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			_ = r.dns.Serve(serveCtx)
		}()
	}
	if len(r.peers) != 0 {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			// auxCtx (not serveCtx): the reconnect loop must die on
			// Close, which runs before serveManaged returns.
			r.connectPeers(auxCtx, n.maxFrame)
		}()
	}

	for {
		connection, err := n.listener.Accept()
		if err != nil {
			if n.isClosed() || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				n.wg.Wait()
				return nil
			}
			return fmt.Errorf("accept TCP tunnel: %w", err)
		}
		if !n.registerConnection(connection) {
			_ = connection.Close()
			continue
		}
		n.wg.Add(1)
		go func(connection net.Conn) {
			defer n.wg.Done()
			defer n.unregisterConnection(connection)
			channel, err := transport.NewTCPPacketChannel(connection, n.maxFrame)
			if err != nil {
				_ = connection.Close()
				return
			}
			if err := r.manager.Accept(serveCtx, channel); err != nil {
				_ = channel.Close()
			}
		}(connection)
	}
}

func (r *nodeRuntime) acceptUDP(ctx context.Context, wg *sync.WaitGroup) {
	for {
		session, err := r.udp.Accept(ctx)
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.manager.Accept(ctx, session)
		}()
	}
}

func (r *nodeRuntime) acceptWebSocket(ctx context.Context, wg *sync.WaitGroup) {
	for {
		channel, err := r.webSocket.Accept(ctx)
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.manager.Accept(ctx, channel)
		}()
	}
}

func (r *nodeRuntime) connectPeers(ctx context.Context, maxFrame int) {
	var peers sync.WaitGroup
	for _, raw := range r.peers {
		endpoint, err := parsePeerEndpoint(raw)
		if err != nil {
			continue
		}
		peers.Add(1)
		go func() {
			defer peers.Done()
			r.connectPeer(ctx, endpoint, maxFrame)
		}()
	}
	peers.Wait()
}

func (r *nodeRuntime) connectPeer(ctx context.Context, endpoint config.Endpoint, maxFrame int) {
	initial := r.reconnectInitial
	if initial <= 0 {
		initial = 250 * time.Millisecond
	}
	maximum := r.reconnectMax
	if maximum <= 0 {
		maximum = 5 * time.Second
	}
	backoff := initial
	for ctx.Err() == nil {
		channel, err := dialPeer(ctx, endpoint, maxFrame)
		if err != nil {
			if !waitReconnect(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, maximum)
			continue
		}
		observed := &observedPacketChannel{PacketChannel: channel, done: make(chan struct{})}
		if err := r.manager.Connect(ctx, observed); err != nil {
			_ = observed.Close()
			if !waitReconnect(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, maximum)
			continue
		}
		backoff = initial
		select {
		case <-observed.done:
		case <-ctx.Done():
			return
		}
	}
}

func dialPeer(ctx context.Context, endpoint config.Endpoint, maxFrame int) (peer.PacketChannel, error) {
	address := endpoint.Address()
	if endpoint.Protocol == config.ProtocolUnix {
		address = endpoint.Path
	}
	if endpoint.Protocol == config.ProtocolWS || endpoint.Protocol == config.ProtocolWSS {
		address = endpoint.String()
	}
	// The endpoint URL path carries the bind device (wg://host:port/eth0),
	// mirroring TunnelUrl::bind_dev in the Rust oracle.
	return transport.DialPacketChannel(ctx, string(endpoint.Protocol), address, maxFrame,
		transport.BindDevice(strings.TrimPrefix(endpoint.Path, "/")))
}

func waitReconnect(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current <= 0 || current >= maximum {
		return maximum
	}
	if current > maximum/2 {
		return maximum
	}
	return current * 2
}

type observedPacketChannel struct {
	peer.PacketChannel
	done      chan struct{}
	doneOnce  sync.Once
	closeOnce sync.Once
}

func (c *observedPacketChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	packet, err := c.PacketChannel.Receive(ctx)
	if err != nil {
		c.doneOnce.Do(func() { close(c.done) })
	}
	return packet, err
}

func (c *observedPacketChannel) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.doneOnce.Do(func() { close(c.done) })
		if closer, ok := c.PacketChannel.(interface{ Close() error }); ok {
			err = closer.Close()
		}
	})
	return err
}

func parsePeerEndpoint(raw string) (config.Endpoint, error) {
	if !strings.Contains(raw, "://") {
		raw = "tcp://" + raw
	}
	return config.ParseEndpoint(raw)
}

func (r *nodeRuntime) packetLoop(ctx context.Context) {
	merger := rpc.NewFragmentMerger()
	for {
		packet, err := r.manager.Receive(ctx)
		if err != nil {
			return
		}
		if r.stats != nil {
			r.stats.Add("runtime_packets_received", 1)
			r.stats.Add("runtime_bytes_received", uint64(len(packet.Payload)))
		}
		if (packet.Header.PacketType == protocol.PacketTypeRPCRequest || packet.Header.PacketType == protocol.PacketTypeRPCResponse) && r.peerRPC != nil {
			if err := r.peerRPC.HandlePacket(ctx, packet); err != nil {
				r.addStat("peer_rpc_dispatch_errors", 1)
			}
			continue
		}
		if packet.Header.PacketType == protocol.PacketTypeData && r.icmpProxy != nil {
			// Rust PeerPacketFilter equivalent: ICMP echo requests are
			// proxied (NAT) and consumed here instead of reaching TUN.
			if _, consumed := r.icmpProxy.TryProcessPacketFromPeer(packet); consumed {
				r.addStat("runtime_icmp_proxied", 1)
				continue
			}
		}
		if packet.Header.PacketType == protocol.PacketTypeRPCRequest && r.rpcHandler != nil {
			rpcPacket, err := rpc.UnmarshalRpcPacket(packet.Payload)
			if err == nil {
				complete, mergeErr := merger.Add(rpcPacket)
				if mergeErr == nil && complete != nil {
					r.handleRPC(ctx, packet, *complete)
				}
			}
		}
		if packet.Header.PacketType == protocol.PacketTypeData && r.portal != nil {
			// Stock portal clients own their IPs: divert before TUN
			// (works with and without a TUN device).
			if handled, err := r.portal.DeliverToClient(ctx, packet.Payload); err != nil {
				r.addStat("portal_deliver_errors", 1)
			} else if handled {
				r.addStat("portal_delivered", 1)
				continue
			}
		}
		if packet.Header.PacketType == protocol.PacketTypeData && r.tun != nil && packet.Header.Flags&protocol.FlagNotSendToTUN == 0 {
			select {
			case r.tunPackets <- append([]byte(nil), packet.Payload...):
			case <-ctx.Done():
				return
			}
		}
		if r.packetHandler != nil {
			if err := r.packetHandler(ctx, packet); err != nil {
				return
			}
		}
	}
}

func (r *nodeRuntime) refreshRoutes(ctx context.Context) {
	if ctx == nil {
		return
	}
	interval := r.routeRefresh
	if interval <= 0 {
		interval = time.Second
	}
	refresh := func() {
		routes := make(map[uint32]uint32)
		if r.routeEngine != nil {
			routes = routeMap(r.routeEngine.Snapshot())
		}
		if r.ospf != nil {
			// Sync direct links (cost = smoothed latency in ms) and
			// re-originate only when the adjacency changes; the
			// flooder's own loop handles periodic re-announce.
			links := r.directLinkCosts()
			if !equalLinkCosts(links, r.ospfLinks) {
				r.ospf.SetLinks(links)
				r.ospfLinks = links
				originateCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				_, err := r.ospf.Originate(originateCtx)
				cancel()
				if err != nil {
					r.addStat("ospf_originate_errors", 1)
				}
			}
			// Flooded routes win over the static engine snapshot.
			for _, item := range r.ospf.Routes() {
				routes[item.Destination] = item.NextHop
			}
		}
		_ = r.manager.Router.SetRoutes(routes)
	}
	refresh()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			refresh()
		case <-ctx.Done():
			return
		}
	}
}

func routeMap(routes []route.Route) map[uint32]uint32 {
	result := make(map[uint32]uint32, len(routes))
	for _, item := range routes {
		result[item.Destination] = item.NextHop
	}
	return result
}

// runtimeRpcTransport adapts the peer center RPC manager to the node's peer
// mesh. Direct sessions are used first so RPC reaches neighbors even before
// any route is installed; otherwise the packet goes through the mesh router,
// which handles forwarded multi-hop RPC traffic.
type runtimeRpcTransport struct {
	localPeerID uint32
	send        func(ctx context.Context, dstPeerID uint32, packet protocol.Packet) error
}

func (t *runtimeRpcTransport) MyPeerID() uint32 { return t.localPeerID }

func (t *runtimeRpcTransport) Send(ctx context.Context, dstPeerID uint32, packet protocol.Packet) error {
	return t.send(ctx, dstPeerID, packet)
}

// directThenRoutedSend prefers the direct session (works with an empty
// routing table) and falls back to routed delivery for multi-hop peers.
func (r *nodeRuntime) directThenRoutedSend(ctx context.Context, dstPeerID uint32, packet protocol.Packet) error {
	if err := r.manager.Send(ctx, dstPeerID, packet); err == nil {
		return nil
	} else if !errors.Is(err, peer.ErrPeerNotFound) {
		return err
	}
	return r.manager.SendPacket(ctx, packet)
}

// runtimePeerInfoProvider is the PeerInfoProvider implementation backed by the
// node runtime's peer manager and route engine.
type runtimePeerInfoProvider struct {
	runtime *nodeRuntime
}

func (p *runtimePeerInfoProvider) MyPeerID() uint32 {
	return p.runtime.manager.LocalPeerID()
}

func (p *runtimePeerInfoProvider) ListDirectPeers() map[uint32]peercenter.DirectPeerInfo {
	sessions := p.runtime.manager.Peers()
	result := make(map[uint32]peercenter.DirectPeerInfo, len(sessions))
	for peerID := range sessions {
		result[peerID] = peercenter.DirectPeerInfo{LatencyMS: p.runtime.manager.PeerLatencyMS(peerID)}
	}
	return result
}

func (p *runtimePeerInfoProvider) ListRoutes() []peercenter.PeerRoute {
	if p.runtime.routeEngine == nil {
		return nil
	}
	routes := p.runtime.routeEngine.Snapshot()
	result := make([]peercenter.PeerRoute, 0, len(routes))
	for _, item := range routes {
		result = append(result, peercenter.PeerRoute{PeerID: item.Destination})
	}
	return result
}

// installRPCPipeline routes locally-destined RPC packets through the
// manager pipeline into peer-RPC dispatch (mirroring Rust's peer-RPC
// transport plugged into the peer manager). Packets unknown to the
// registry complete with an error envelope instead of stalling.
func (r *nodeRuntime) installRPCPipeline() {
	if r.peerRPC == nil {
		return
	}
	peerRPC := r.peerRPC
	r.manager.SetRPCHandler(func(ctx context.Context, packet protocol.Packet) bool {
		if err := peerRPC.HandlePacket(ctx, packet); err != nil {
			r.addStat("peer_rpc_dispatch_errors", 1)
		}
		return true
	})
}

// ensurePeerRPC creates the mesh RPC manager when no other subsystem has.
// It mirrors runtimeRpcTransport usage in initCenter.
func (r *nodeRuntime) ensurePeerRPC() (*rpc.PeerRpcManager, error) {
	r.stateMu.RLock()
	if r.peerRPC != nil {
		peerRPC := r.peerRPC
		r.stateMu.RUnlock()
		return peerRPC, nil
	}
	r.stateMu.RUnlock()
	transport := &runtimeRpcTransport{
		localPeerID: r.manager.LocalPeerID(),
		send: func(ctx context.Context, dstPeerID uint32, packet protocol.Packet) error {
			return r.directThenRoutedSend(ctx, dstPeerID, packet)
		},
	}
	peerRPC, err := rpc.NewPeerRpcManager(transport)
	if err != nil {
		return nil, fmt.Errorf("create peer rpc manager: %w", err)
	}
	r.stateMu.Lock()
	r.peerRPC = peerRPC
	r.stateMu.Unlock()
	return peerRPC, nil
}

// ospfRPCDomain scopes the OSPF RPC service.
func (r *nodeRuntime) ospfRPCDomain() string {
	if r.ospfDomain != "" {
		return r.ospfDomain
	}
	if r.centerDomain != "" {
		return r.centerDomain
	}
	return "easytier"
}

// initFlooder builds the OSPF LSA flooder over the peer-RPC mesh and wires
// RPC dispatch into the manager pipeline. It is a no-op when OSPF is
// disabled or already started.
func (r *nodeRuntime) initFlooder(ctx context.Context) error {
	r.stateMu.RLock()
	enabled, started := r.ospfEnabled, r.ospf != nil
	r.stateMu.RUnlock()
	if !enabled || started {
		return nil
	}
	peerRPC, err := r.ensurePeerRPC()
	if err != nil {
		return err
	}
	domain := r.ospfRPCDomain()
	neighbors := func() []uint32 {
		sessions := r.manager.Peers()
		peers := make([]uint32, 0, len(sessions))
		for peerID := range sessions {
			peers = append(peers, peerID)
		}
		return peers
	}
	sessionID := route.NewSessionID()
	flooder, err := route.NewFlooder(r.manager.LocalPeerID(), nil, route.MeshBroadcast(peerRPC, domain, neighbors, sessionID))
	if err != nil {
		return fmt.Errorf("create ospf flooder: %w", err)
	}
	flooder.SetSessionID(sessionID)
	// Publish the admin-signed trust list and classify connecting peers
	// against it (reference credential enforcement).
	if len(r.trustedCredentials) != 0 {
		proofs, err := route.SignManagedCredentials(r.trustedCredentials, r.networkSecret)
		if err != nil {
			return fmt.Errorf("sign trusted credentials: %w", err)
		}
		flooder.SetTrustedCredentials(proofs)
	}
	if err := peerRPC.Register(domain, route.NewOSPFService(flooder, &route.OSPFServiceConfig{
		NetworkSecret: r.networkSecret,
		IsCredentialPeer: func(peerID uint32) bool {
			identity, ok := r.manager.IdentityOf(peerID)
			return ok && identity == peer.PeerIdentityCredential
		},
	})); err != nil {
		return fmt.Errorf("register ospf rpc service: %w", err)
	}
	r.stateMu.Lock()
	r.ospf = flooder
	r.stateMu.Unlock()
	r.installRPCPipeline()
	flooder.Start(ctx)
	return nil
}

// directLinkCosts reports current direct peers with the smoothed RTT
// (PeerLatencyMS, floor 1) as the OSPF link cost.
func (r *nodeRuntime) directLinkCosts() map[uint32]uint32 {
	sessions := r.manager.Peers()
	links := make(map[uint32]uint32, len(sessions))
	for peerID := range sessions {
		cost := uint32(r.manager.PeerLatencyMS(peerID))
		if cost == 0 {
			cost = 1
		}
		links[peerID] = cost
	}
	return links
}

func equalLinkCosts(a, b map[uint32]uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for peerID, cost := range a {
		if b[peerID] != cost {
			return false
		}
	}
	return true
}

// initICMPProxy builds the ICMP NAT proxy (Rust PeerPacketFilter
// equivalent) and attaches it to the inbound packet path. It is a no-op
// when disabled or already started.
func (r *nodeRuntime) initICMPProxy() error {
	r.stateMu.RLock()
	enabled, started := r.icmpEnabled, r.icmpProxy != nil
	r.stateMu.RUnlock()
	if !enabled || started {
		return nil
	}
	var v4 [4]byte
	if r.tunAddresses != nil && r.tunAddresses.IPv4 != nil {
		v4 = r.tunAddresses.IPv4.Addr().As4()
	}
	proxy, err := gateway.NewIcmpProxy(gateway.IcmpProxyConfig{
		MyPeerID:     r.manager.LocalPeerID(),
		IPv4Addr:     v4,
		CIDRMappings: append([]gateway.CIDRMapping(nil), r.icmpMappings...),
		ExitNode:     r.icmpExitNode,
		NoTUN:        r.noTun,
		SendPacket: func(ctx context.Context, peerID uint32, packet protocol.Packet) error {
			return r.manager.Send(ctx, peerID, packet)
		},
	})
	if err != nil {
		return fmt.Errorf("create icmp proxy: %w", err)
	}
	proxy.Start()
	r.stateMu.Lock()
	r.icmpProxy = proxy
	r.stateMu.Unlock()
	return nil
}

// setAuxCancel records the auxiliary-loop cancel func.
func (r *nodeRuntime) setAuxCancel(cancel context.CancelFunc) {
	r.auxMu.Lock()
	defer r.auxMu.Unlock()
	r.auxCancel = cancel
}

func (r *nodeRuntime) stopAux() {
	r.auxMu.Lock()
	defer r.auxMu.Unlock()
	if r.auxCancel != nil {
		r.auxCancel()
	}
}

// raPrefix returns the IPv6 prefix used for router advertisements.
func (r *nodeRuntime) raPrefix() (netip.Prefix, bool) {
	if r.tunAddresses != nil && r.tunAddresses.IPv6 != nil {
		return *r.tunAddresses.IPv6, true
	}
	return netip.Prefix{}, false
}

// startRAAnnouncer emits periodic IPv6 router advertisements (RFC 4861)
// towards the local network. With a TUN device the RA is injected into the
// device so the host can SLAAC; in NoTUN mode the RA is still maintained
// and cached for management via LastRA.
func (r *nodeRuntime) startRAAnnouncer(ctx context.Context, wg *sync.WaitGroup) {
	prefix, ok := r.raPrefix()
	if !ok || r.raCancel != nil {
		return
	}
	provider, err := publicipv6.NewProvider(prefix)
	if err != nil {
		r.addStat("ra_provider_errors", 1)
		return
	}
	if _, err := provider.Acquire("local"); err != nil {
		r.addStat("ra_provider_errors", 1)
		return
	}
	r.stateMu.Lock()
	r.raProvider = provider
	r.stateMu.Unlock()
	interval := r.raInterval
	if interval <= 0 {
		interval = DefaultRAAnnounceInterval
	}
	// Independent lifecycle: serveCtx is canceled only when serveManaged
	// returns, which waits for this goroutine via wg. Stop via close().
	raCtx, raCancel := context.WithCancel(context.Background())
	r.stateMu.Lock()
	r.raCancel = raCancel
	r.stateMu.Unlock()
	stopOnParent := context.AfterFunc(ctx, func() { raCancel() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stopOnParent()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		r.announceRA(prefix)
		for {
			select {
			case <-ticker.C:
				r.announceRA(prefix)
			case <-raCtx.Done():
				return
			}
		}
	}()
}

// announceRA builds one router advertisement for prefix, caches it, and
// injects it into the TUN device when present.
func (r *nodeRuntime) announceRA(prefix netip.Prefix) {
	masked := prefix.Masked()
	advertisement := publicipv6.RouterAdvertisement{
		CurrentHopLimit:   64,
		RouterLifetime:    3 * DefaultRAAnnounceInterval,
		Prefix:            masked,
		ValidLifetime:     time.Hour,
		PreferredLifetime: 30 * time.Minute,
	}
	src := prefix.Addr()
	dst, err := netip.ParseAddr("ff02::1")
	if err != nil {
		return
	}
	message, err := advertisement.Marshal(src, dst)
	if err != nil {
		r.addStat("ra_build_errors", 1)
		return
	}
	frame := buildIPv6Packet(src, dst, 58, message)
	r.raMu.Lock()
	r.lastRA = frame
	r.raMu.Unlock()
	if r.tun == nil || r.tunPackets == nil {
		return
	}
	select {
	case r.tunPackets <- append([]byte(nil), frame...):
	default:
		r.addStat("ra_dropped", 1)
	}
}

// LastRA returns the most recently built router advertisement frame.
func (r *nodeRuntime) LastRA() []byte {
	r.raMu.Lock()
	defer r.raMu.Unlock()
	return append([]byte(nil), r.lastRA...)
}

// OSPF returns the OSPF flooder once the serve goroutine has published it.
func (r *nodeRuntime) OSPF() *route.Flooder {
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	return r.ospf
}

// PeerRPC returns the mesh RPC manager once the serve goroutine has
// published it.
func (r *nodeRuntime) PeerRPC() *rpc.PeerRpcManager {
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	return r.peerRPC
}

// buildIPv6Packet wraps payload in a minimal IPv6 header (hop limit 255
// per RFC 4861 section 7.1.2 for router advertisements).
func buildIPv6Packet(src, dst netip.Addr, nextHeader byte, payload []byte) []byte {
	src16 := src.As16()
	dst16 := dst.As16()
	frame := make([]byte, 40+len(payload))
	frame[0] = 0x60
	frame[6] = nextHeader
	frame[7] = 255
	frame[4] = byte(len(payload) >> 8)
	frame[5] = byte(len(payload))
	copy(frame[8:24], src16[:])
	copy(frame[24:40], dst16[:])
	copy(frame[40:], payload)
	return frame
}

// initCenter builds the peer-center RPC manager and instance when a network name
// is configured. It is a no-op when disabled or already started.
func (r *nodeRuntime) initCenter(ctx context.Context) error {
	r.stateMu.RLock()
	configured, peerRPCReady := r.centerDomain != "", r.peerRPC != nil
	r.stateMu.RUnlock()
	if !configured || peerRPCReady {
		return nil
	}
	transport := &runtimeRpcTransport{
		localPeerID: r.manager.LocalPeerID(),
		send: func(ctx context.Context, dstPeerID uint32, packet protocol.Packet) error {
			return r.directThenRoutedSend(ctx, dstPeerID, packet)
		},
	}
	peerRPC, err := rpc.NewPeerRpcManager(transport)
	if err != nil {
		return fmt.Errorf("create peer-center rpc manager: %w", err)
	}
	r.stateMu.Lock()
	r.peerRPC = peerRPC
	r.stateMu.Unlock()
	r.installRPCPipeline()
	center, err := peercenter.NewInstance(&runtimePeerInfoProvider{runtime: r}, peerRPC, r.centerDomain)
	if err != nil {
		return fmt.Errorf("create peer-center instance: %w", err)
	}
	r.stateMu.Lock()
	r.center = center
	r.stateMu.Unlock()
	return center.Start(ctx)
}

func (r *nodeRuntime) handleRPC(ctx context.Context, packet protocol.Packet, request rpc.RpcPacket) {
	response, err := r.rpcHandler(ctx, request)
	if err != nil {
		body, marshalErr := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
		if marshalErr != nil {
			return
		}
		response = rpc.RpcPacket{Descriptor: request.Descriptor, Body: body}
	}
	response.FromPeer = packet.Header.ToPeerID
	response.ToPeer = packet.Header.FromPeerID
	response.TransactionID = request.TransactionID
	response.IsRequest = false
	if response.Descriptor == nil && request.Descriptor != nil {
		descriptor := *request.Descriptor
		response.Descriptor = &descriptor
	}
	compression := rpc.RpcCompressionInfo{}
	if response.CompressionInfo != nil {
		compression = *response.CompressionInfo
	}
	descriptor := rpc.RpcDescriptor{}
	if response.Descriptor != nil {
		descriptor = *response.Descriptor
	}
	packets, err := rpc.BuildRPCPackets(rpc.BuildRPCPacketArgs{
		FromPeer:        response.FromPeer,
		ToPeer:          response.ToPeer,
		RPCDesc:         descriptor,
		TransactionID:   response.TransactionID,
		IsRequest:       false,
		Content:         response.Body,
		TraceID:         response.TraceID,
		CompressionInfo: compression,
	})
	if err != nil {
		return
	}
	for _, responsePacket := range packets {
		if err := r.manager.Send(ctx, packet.Header.FromPeerID, responsePacket); err != nil {
			return
		}
	}
}

func (r *nodeRuntime) tunIngress(ctx context.Context, packet []byte) error {
	if r.acl != nil {
		metadata, err := gateway.ParsePacket(packet, acl.DirectionOutbound)
		if err != nil || r.acl.Evaluate(metadata).Action != acl.ActionAllow {
			r.addStat("runtime_acl_dropped", 1)
			return nil
		}
	}
	if r.receiveLimiter != nil {
		if err := r.receiveLimiter.Wait(ctx, int64(len(packet))); err != nil {
			return err
		}
	}
	destination := r.tunDestination
	if destination == 0 {
		destination = r.resolvePeerForPacket(packet)
		if destination == 0 {
			// No route for packet's destination IP; drop silently to avoid
			// forwarding loops, matching Rust's subnet-proxy loop prevention.
			return nil
		}
	}
	return r.manager.Send(ctx, destination, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: append([]byte(nil), packet...),
	})
}

func (r *nodeRuntime) resolvePeerForPacket(packet []byte) uint32 {
	if len(packet) == 0 {
		return 0
	}
	var destAddr netip.Addr
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return 0
		}
		destAddr = netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	case 6:
		if len(packet) < 40 {
			return 0
		}
		destAddr = netip.AddrFrom16([16]byte{
			packet[24], packet[25], packet[26], packet[27],
			packet[28], packet[29], packet[30], packet[31],
			packet[32], packet[33], packet[34], packet[35],
			packet[36], packet[37], packet[38], packet[39],
		})
	default:
		return 0
	}
	// Try route engine first: if destination IP matches a pseudo-IP for a peer,
	// pick that peer. For DHCP pool 10.144.144.0/24 we map last octet to peerID.
	if destAddr.Is4() && destAddr.IsValid() {
		// Check DHCP pool mapping: 10.144.144.x -> try to find peer with pseudo IP
		if r.routeEngine != nil {
			for _, route := range r.routeEngine.Snapshot() {
				if pseudoIPForPeer(route.Destination) == destAddr {
					return route.Destination
				}
			}
		}
		// Also check manager peers directly
		for id := range r.manager.Peers() {
			if pseudoIPForPeer(id) == destAddr {
				return id
			}
		}
	}
	// Fallback to first available peer/route (useful for single-peer tests)
	peers := r.manager.Peers()
	for id := range peers {
		return id
	}
	if r.routeEngine != nil {
		if routes := r.routeEngine.Snapshot(); len(routes) > 0 {
			return routes[0].Destination
		}
	}
	return 0
}

func (r *nodeRuntime) addStat(name string, value uint64) {
	if r.stats != nil {
		r.stats.Add(name, value)
	}
}

func (r *nodeRuntime) tunEgress(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-r.tunPackets:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *nodeRuntime) close() error {
	r.closeOnce.Do(func() {
		r.stateMu.RLock()
		center, ospf, icmpProxy, raCancel, peerRPC := r.center, r.ospf, r.icmpProxy, r.raCancel, r.peerRPC
		r.stateMu.RUnlock()
		if center != nil {
			center.Stop()
		}
		if ospf != nil {
			ospf.Stop()
		}
		if icmpProxy != nil {
			icmpProxy.Stop()
		}
		r.stopP2P()
		if raCancel != nil {
			raCancel()
		}
		r.stopAux()
		if peerRPC != nil {
			peerRPC.Close()
		}
		if r.manager != nil {
			r.closeErr = errors.Join(r.closeErr, r.manager.Close())
		}
		if r.udp != nil {
			r.closeErr = errors.Join(r.closeErr, r.udp.Close())
		}
		if r.rpcServer != nil {
			r.closeErr = errors.Join(r.closeErr, r.rpcServer.Close())
		}
		if r.webServer != nil {
			r.closeErr = errors.Join(r.closeErr, r.webServer.Close())
		}
		if r.webClient != nil {
			r.closeErr = errors.Join(r.closeErr, r.webClient.Close())
		}
		if r.webSocket != nil {
			r.closeErr = errors.Join(r.closeErr, r.webSocket.Close())
		}
		if r.dns != nil {
			r.closeErr = errors.Join(r.closeErr, r.dns.Close())
		}
		if r.tun != nil {
			r.closeErr = errors.Join(r.closeErr, r.tun.Close())
		}
	})
	return r.closeErr
}

// SendIPPacket injects one local IP packet into the mesh (portal decapsulated
// traffic path). It mirrors tunIngress: ACL, rate limit, peer resolution.
func (n *Node) SendIPPacket(ctx context.Context, ipPacket []byte) error {
	if n == nil || n.runtime == nil {
		return errors.New("node runtime is not configured")
	}
	return n.runtime.tunIngress(ctx, ipPacket)
}

// SetPortal attaches the VPN portal return path. It must be called before
// Serve starts the packet loop.
func (n *Node) SetPortal(portal PortalForwarder) {
	if n == nil || n.runtime == nil {
		return
	}
	n.runtime.portal = portal
}

// PeerManager returns the live manager used by this node.
func (n *Node) PeerManager() *peer.PeerConnectionManager {
	if n == nil || n.runtime == nil {
		return nil
	}
	return n.runtime.manager
}

// Send sends a packet through the node's authenticated peer manager.
func (n *Node) Send(ctx context.Context, peerID uint32, packet protocol.Packet) error {
	manager := n.PeerManager()
	if manager == nil {
		return errors.New("node peer manager is not configured")
	}
	return manager.Send(ctx, peerID, packet)
}

// Receive returns the next packet routed locally by the node's peer manager.
// It is primarily useful to embedders that do not configure PacketHandler.
func (n *Node) Receive(ctx context.Context) (protocol.Packet, error) {
	manager := n.PeerManager()
	if manager == nil {
		return protocol.Packet{}, errors.New("node peer manager is not configured")
	}
	return manager.Receive(ctx)
}

// UDPAddress returns the bound UDP address when UDP transport is enabled.
func (n *Node) UDPAddress() net.Addr {
	if n == nil || n.runtime == nil || n.runtime.udp == nil {
		return nil
	}
	return n.runtime.udp.Address()
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package core

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/directconn"
	"github.com/EasyTier/EasyTier/go/internal/mapping"
	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/punch"
	"github.com/EasyTier/EasyTier/go/internal/stun"
	"github.com/EasyTier/EasyTier/go/internal/tcphole"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

// P2PConfig enables the NAT traversal stack: STUN detection, UDP hole
// punching, TCP hole punching, the direct connector, and manual connectors.
type P2PConfig struct {
	// NetworkName scopes the peer RPC services; it defaults to the
	// PeerCenter network name.
	NetworkName string

	// Stun server lists; empty selects the reference defaults.
	UDPServers   []string
	TCPServers   []string
	UDPServersV6 []string

	// Disable* flags mirror the reference feature flags.
	DisableP2P             bool
	NeedP2P                bool
	LazyP2P                bool
	DisableUDPHolePunching bool
	DisableTCPHolePunching bool
	DisableSymHolePunching bool
	DisableUPnP            bool

	// DefaultProtocol and EnableIPv6 drive listener expansion.
	DefaultProtocol string
	EnableIPv6      bool

	// ManualConnectors lists URLs the manual manager keeps alive.
	ManualConnectors []string

	// ExtraListeners are advertised listener URLs beyond the node's own
	// TCP/UDP listeners (for example mapped listeners).
	ExtraListeners []string

	// MaxFrame is the tunnel frame limit for dialed connections.
	MaxFrame int
}

// p2pRuntime holds the live NAT traversal components.
type p2pRuntime struct {
	config *P2PConfig

	stunCollector *stun.Collector
	punchCoord    *punch.Coordinator
	directConn    *directconn.Connector
	manual        *directconn.ManualManager
	tcpInitiator  *tcphole.Initiator

	// cancel stops every p2p goroutine (including the TCP punch driver)
	// without depending on outer lifecycle ordering.
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// P2P returns the p2p runtime once the serve goroutine has published it.
func (r *nodeRuntime) P2P() *p2pRuntime {
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	return r.p2p
}

// OSPF returns the route flooder once the serve goroutine published it.
func (n *Node) OSPF() *route.Flooder {
	if n == nil || n.runtime == nil {
		return nil
	}
	return n.runtime.OSPF()
}

// StunInfo returns the latest NAT snapshot from the collector.
func (n *Node) StunInfo() *common.StunInfo {
	if n == nil || n.runtime == nil {
		return nil
	}
	runtime := n.runtime.P2P()
	if runtime == nil || runtime.stunCollector == nil {
		return nil
	}
	return runtime.stunCollector.GetStunInfo()
}

// initP2P starts the NAT traversal components when configured. It is a
// no-op when disabled or already started.
func (r *nodeRuntime) initP2P(ctx context.Context) error {
	r.stateMu.RLock()
	enabled, started := r.p2pConfig != nil, r.p2p != nil
	domain, centerDomain := r.p2pDomain, r.centerDomain
	r.stateMu.RUnlock()
	if !enabled || started {
		return nil
	}
	if domain == "" {
		domain = centerDomain
	}

	collector := stun.NewCollector(r.p2pConfig.UDPServers, r.p2pConfig.TCPServers, r.p2pConfig.UDPServersV6)
	collector.Start(ctx)

	// Feed the local NAT classification into OSPF LSAs so remote peers
	// learn it through RoutePeerInfo.udp_nat_type.
	if ospf := r.OSPF(); ospf != nil {
		ospf.SetNATTypeFn(func() common.NatType {
			return collector.GetStunInfo().GetUdpNatType()
		})
	}

	peerRPC, err := r.ensurePeerRPC()
	if err != nil {
		return err
	}

	// Punch listener sessions arrive authenticated from remote initiators.
	// UPnP leases a public port for the pool unless disabled.
	var poolMapper punch.PortMapper
	if !r.p2pConfig.DisableUPnP {
		poolMapper = newUPnPPortMapper(mapping.NewMapper(mapping.MapperOptions{}), func() netip.Addr {
			info := collector.GetStunInfo()
			if len(info.GetPublicIp()) == 0 {
				return netip.Addr{}
			}
			ip, err := netip.ParseAddr(info.GetPublicIp()[0])
			if err != nil {
				return netip.Addr{}
			}
			return ip.Unmap()
		})
	}
	punchPool := punch.NewListenerPool(collector, poolMapper, func(session *transport.UDPSession) {
		acceptCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := r.manager.Accept(acceptCtx, session); err != nil {
			_ = session.Close()
			r.addStat("p2p_punch_accept_errors", 1)
		}
	})
	punchService := punch.NewService(punchPool, collector)

	candidates := r.p2pCandidates()
	punchCoordinator := punch.NewCoordinator(punch.Config{
		MyPeerID:               r.manager.LocalPeerID(),
		Domain:                 domain,
		RPC:                    peerRPC,
		Stun:                   collector,
		DisableUDPHolePunching: r.p2pConfig.DisableUDPHolePunching,
		DisableSymHolePunching: r.p2pConfig.DisableSymHolePunching,
		DisableP2P:             r.p2pConfig.DisableP2P,
		NeedP2P:                r.p2pConfig.NeedP2P,
		LazyP2P:                r.p2pConfig.LazyP2P,
		Candidates:             candidates,
		OnClientSession: func(ctx context.Context, session *transport.UDPSession, dstPeerID uint32) error {
			return r.connectPunchedSession(ctx, session, dstPeerID)
		},
		OnServerSession: nil,
	})
	if err := peerRPC.Register(domain, punchService); err != nil {
		return fmt.Errorf("register udp hole punch service: %w", err)
	}
	if err := punchCoordinator.Start(ctx); err != nil {
		return fmt.Errorf("start udp hole punch coordinator: %w", err)
	}

	// TCP hole punch responder.
	tcpHandoff := tcphole.Handoff{
		OnClientConn: func(ctx context.Context, conn net.Conn) error {
			return r.connectTCPConn(ctx, conn, 0)
		},
		OnServerConn: func(ctx context.Context, conn net.Conn) error {
			return r.acceptTCPConn(ctx, conn)
		},
	}
	tcpService := tcphole.NewService(collector, tcpHandoff)
	if err := peerRPC.Register(domain, tcpService); err != nil {
		return fmt.Errorf("register tcp hole punch service: %w", err)
	}
	tcpInitiator := tcphole.NewInitiator(peerRPC, domain, collector, tcpHandoff)

	// Direct connector: address discovery + dial loop.
	ipListService := directconn.NewIPListService(collector, r.p2pListenerURLs)
	if err := peerRPC.Register(domain, ipListService); err != nil {
		return fmt.Errorf("register direct connector service: %w", err)
	}
	directConnector := directconn.NewConnector(directconn.ConnectorConfig{
		MyPeerID:        r.manager.LocalPeerID(),
		Domain:          domain,
		RPC:             peerRPC,
		Stun:            collector,
		Candidates:      r.p2pCandidateIDs,
		HasDirectConn:   r.hasDirectPeer,
		EnableIPv6:      r.p2pConfig.EnableIPv6,
		DefaultProtocol: r.p2pConfig.DefaultProtocol,
		MaxFrame:        r.p2pConfig.MaxFrame,
		Handoff: func(ctx context.Context, channel peer.PacketChannel, dstPeerID uint32) error {
			return r.handoffDialedChannel(ctx, channel, dstPeerID)
		},
	})
	directConnector.Start(ctx)

	// Manual connectors keep configured peer URLs alive.
	manual := directconn.NewManualManager(directconn.ManualConfig{
		Dial: func(ctx context.Context, rawURL string) (peer.PacketChannel, error) {
			return dialPeer(ctx, mustEndpoint(rawURL), r.p2pFrameLimit())
		},
		Handoff: func(ctx context.Context, channel peer.PacketChannel) error {
			return r.manager.Connect(ctx, channel)
		},
		MaxFrame: r.p2pFrameLimit(),
	})
	manual.Start(ctx)
	for _, raw := range r.p2pConfig.ManualConnectors {
		if err := manual.AddConnector(raw); err != nil {
			r.addStat("p2p_manual_connector_errors", 1)
		}
	}

	// TCP punch driver: reuse the direct connector candidate set. It runs
	// under the p2p-owned context so Stop can always reclaim it.
	p2pCtx, p2pCancel := context.WithCancel(ctx)
	runtime := &p2pRuntime{
		config:        r.p2pConfig,
		stunCollector: collector,
		punchCoord:    punchCoordinator,
		directConn:    directConnector,
		manual:        manual,
		tcpInitiator:  tcpInitiator,
		cancel:        p2pCancel,
	}
	runtime.wg.Add(1)
	go func() {
		defer runtime.wg.Done()
		r.driveTCPPunch(p2pCtx, tcpInitiator, candidates)
	}()

	r.stateMu.Lock()
	r.p2p = runtime
	r.stateMu.Unlock()
	return nil
}

// stopP2P tears down the NAT traversal components.
func (r *nodeRuntime) stopP2P() {
	r.stateMu.RLock()
	runtime := r.p2p
	r.stateMu.RUnlock()
	if runtime == nil {
		return
	}
	runtime.cancel()
	runtime.punchCoord.Stop()
	runtime.directConn.Stop()
	runtime.manual.Stop()
	runtime.stunCollector.Stop()
	runtime.wg.Wait()
}

// connectPunchedSession upgrades a client-side punched session into an
// authenticated peer connection and verifies the authenticated peer.
func (r *nodeRuntime) connectPunchedSession(ctx context.Context, session *transport.UDPSession, dstPeerID uint32) error {
	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := r.manager.Connect(connectCtx, session); err != nil {
		_ = session.Close()
		return fmt.Errorf("authenticate punched session with peer %d: %w", dstPeerID, err)
	}
	if _, ok := r.manager.Peers()[dstPeerID]; !ok {
		_ = session.Close()
		return fmt.Errorf("punched session authenticated as a different peer, want %d", dstPeerID)
	}
	return nil
}

// connectTCPConn upgrades an outbound punched TCP connection.
func (r *nodeRuntime) connectTCPConn(ctx context.Context, conn net.Conn, maxFrame int) error {
	if maxFrame <= 0 {
		maxFrame = protocol.DefaultMaxStreamFrameSize
	}
	channel, err := transport.NewTCPPacketChannel(conn, maxFrame)
	if err != nil {
		_ = conn.Close()
		return err
	}
	if err := r.manager.Connect(ctx, channel); err != nil {
		_ = channel.Close()
		return err
	}
	return nil
}

// acceptTCPConn upgrades an inbound punched TCP connection.
func (r *nodeRuntime) acceptTCPConn(ctx context.Context, conn net.Conn) error {
	channel, err := transport.NewTCPPacketChannel(conn, protocol.DefaultMaxStreamFrameSize)
	if err != nil {
		_ = conn.Close()
		return err
	}
	if err := r.manager.Accept(ctx, channel); err != nil {
		_ = channel.Close()
		return err
	}
	return nil
}

// handoffDialedChannel authenticates a direct-connector dial and verifies
// the resulting peer identity.
func (r *nodeRuntime) handoffDialedChannel(ctx context.Context, channel peer.PacketChannel, dstPeerID uint32) error {
	handoffCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := r.manager.Connect(handoffCtx, channel); err != nil {
		return fmt.Errorf("authenticate connection to peer %d: %w", dstPeerID, err)
	}
	if _, ok := r.manager.Peers()[dstPeerID]; !ok {
		return fmt.Errorf("connection authenticated as a different peer, want %d", dstPeerID)
	}
	return nil
}

// hasDirectPeer reports whether an authenticated session already exists.
func (r *nodeRuntime) hasDirectPeer(peerID uint32) bool {
	_, ok := r.manager.Peers()[peerID]
	return ok
}

// p2pCandidates builds the punch candidate list: routed peers plus global
// map entries, excluding already-direct sessions. Remote NAT types come from
// the OSPF-flooded RoutePeerInfo.udp_nat_type and default to Unknown until a
// peer advertises its classification.
func (r *nodeRuntime) p2pCandidates() func() []punch.Candidate {
	return func() []punch.Candidate {
		ids := r.p2pCandidateIDs()
		ospf := r.OSPF()
		out := make([]punch.Candidate, 0, len(ids))
		for _, id := range ids {
			natType := common.NatType_Unknown
			if ospf != nil {
				natType = ospf.UDPNatType(id)
			}
			out = append(out, punch.Candidate{PeerID: id, UDPNatType: natType})
		}
		return out
	}
}

// p2pCandidateIDs unions route-engine destinations, OSPF routes, and the
// peer-center global map, minus directly connected sessions.
func (r *nodeRuntime) p2pCandidateIDs() []uint32 {
	candidates := make(map[uint32]struct{})
	if r.routeEngine != nil {
		for _, item := range r.routeEngine.Snapshot() {
			candidates[item.Destination] = struct{}{}
		}
	}
	r.stateMu.RLock()
	ospf := r.ospf
	center := r.center
	r.stateMu.RUnlock()
	if ospf != nil {
		for _, item := range ospf.Routes() {
			candidates[item.Destination] = struct{}{}
		}
	}
	if center != nil {
		for peerID, entry := range center.GlobalPeerMap() {
			candidates[peerID] = struct{}{}
			for dst := range entry.DirectPeers {
				candidates[dst] = struct{}{}
			}
		}
	}
	for id := range r.manager.Peers() {
		delete(candidates, id)
	}
	delete(candidates, r.manager.LocalPeerID())
	out := make([]uint32, 0, len(candidates))
	for id := range candidates {
		out = append(out, id)
	}
	return out
}

// driveTCPPunch periodically collects candidates and runs the TCP punch
// initiator toward peers that still lack direct connections.
func (r *nodeRuntime) driveTCPPunch(ctx context.Context, initiator *tcphole.Initiator, candidates func() []punch.Candidate) {
	if r.p2pConfig.DisableTCPHolePunching || r.p2pConfig.DisableP2P {
		return
	}
	ticker := time.NewTicker(punch.DefaultLoopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if initiator.Stun.GetStunInfo().GetTcpNatType() == common.NatType_Unknown {
			continue
		}
		for _, candidate := range candidates() {
			if r.hasDirectPeer(candidate.PeerID) {
				continue
			}
			go initiator.PunchPeer(ctx, candidate.PeerID)
		}
	}
}

// p2pFrameLimit returns the configured frame limit with the protocol
// default applied.
func (r *nodeRuntime) p2pFrameLimit() int {
	r.stateMu.RLock()
	config := r.p2pConfig
	r.stateMu.RUnlock()
	if config == nil || config.MaxFrame <= 0 {
		return protocol.DefaultMaxStreamFrameSize
	}
	return config.MaxFrame
}

// p2pListenerURLs advertises the node's own listeners for address discovery.
// The node's TCP/UDP listener URLs are pre-populated into ExtraListeners by
// ListenWithOptions, so only the configured extras are returned here.
func (r *nodeRuntime) p2pListenerURLs() []string {
	r.stateMu.RLock()
	config := r.p2pConfig
	r.stateMu.RUnlock()
	if config == nil {
		return nil
	}
	return append([]string(nil), config.ExtraListeners...)
}

// mustEndpoint parses a connector URL, defaulting the scheme to TCP.
func mustEndpoint(rawURL string) config.Endpoint {
	if rawURL == "" {
		return config.Endpoint{}
	}
	if !containsScheme(rawURL) {
		rawURL = "tcp://" + rawURL
	}
	endpoint, err := config.ParseEndpoint(rawURL)
	if err != nil {
		return config.Endpoint{}
	}
	return endpoint
}

func containsScheme(rawURL string) bool {
	for i := 0; i+2 < len(rawURL); i++ {
		if rawURL[i] == ':' && rawURL[i+1] == '/' && rawURL[i+2] == '/' {
			return true
		}
	}
	return false
}

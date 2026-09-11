// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/acl"
	"github.com/EasyTier/EasyTier/go/internal/gateway"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/ratelimit"
	"github.com/EasyTier/EasyTier/go/internal/stats"
)

var (
	ErrPeerConnectionManagerClosed = errors.New("peer connection manager is closed")
	ErrPeerLimit                   = errors.New("peer connection limit reached")
	ErrPeerNotFound                = errors.New("peer is not connected")
)

const DefaultMaxPeers = 128

// HandshakeMode selects the handshake used for newly accepted connections.
type HandshakeMode uint8

const (
	HandshakeModeLegacy HandshakeMode = iota
	HandshakeModeDirectNoise
)

// PeerConnectionManagerConfig configures one local peer manager.
type PeerConnectionManagerConfig struct {
	LocalPeerID uint32
	// DataCompressAlgo is used for data packets before session encryption.
	DataCompressAlgo protocol.CompressionAlgorithm

	HandshakeMode   HandshakeMode
	UseDirectNoise  bool
	LegacyIdentity  LegacyIdentity
	DirectHandshake DirectPeerHandshakeConfig

	MaxPeers    int
	PacketQueue int
	Routes      map[uint32]uint32
	Router      *PacketRouter
	ACL         *acl.Policy
	RecvLimiter *ratelimit.Limiter
	Stats       *stats.Counters

	// PingerEnabled starts an adaptive PeerConnPinger for every established
	// session. Pingers feed PeerLatencyMS, which the peer-center report job
	// uses instead of a placeholder latency.
	PingerEnabled bool
}

// PeerSession is one authenticated connection to a remote peer.
type PeerSession struct {
	PeerID              uint32
	Channel             PacketChannel
	Router              *PacketRouter
	Secure              *SecureDatagramSession
	AuthenticationLevel AuthenticationLevel
	DataCompressAlgo    protocol.CompressionAlgorithm
	ACL                 *acl.Policy
	RecvLimiter         *ratelimit.Limiter
	Stats               *stats.Counters

	closeOnce sync.Once
	sendMu    sync.Mutex
}

// Send sends a packet on this session, encrypting it when the session used the
// direct Noise handshake.
func (s *PeerSession) Send(ctx context.Context, packet protocol.Packet) error {
	if ctx == nil {
		return errors.New("peer send context is nil")
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if shouldCompressPeerPacket(packet.Header.PacketType) {
		if err := protocol.CompressPacket(&packet, s.DataCompressAlgo); err != nil {
			return err
		}
	}
	if s.Secure != nil {
		payload, err := s.Secure.Seal(packet.Payload)
		if err != nil {
			return err
		}
		packet.Payload = payload
		packet.Header.Flags |= protocol.FlagEncrypted
	}
	return s.Channel.Send(ctx, packet)
}

// Close closes the underlying channel when it supports closing.
func (s *PeerSession) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if closer, ok := s.Channel.(interface{ Close() error }); ok {
			err = closer.Close()
		}
	})
	return err
}

// PeerConnectionManager owns authenticated peer sessions and their receive
// loops. Connections may be added concurrently.
type PeerConnectionManager struct {
	localPeerID      uint32
	mode             HandshakeMode
	legacy           LegacyIdentity
	direct           DirectPeerHandshakeConfig
	maxPeers         int
	dataCompressAlgo protocol.CompressionAlgorithm
	router           *PacketRouter
	Router           *PacketRouter
	packets          chan protocol.Packet
	acl              *acl.Policy
	recvLimiter      *ratelimit.Limiter
	stats            *stats.Counters

	ctx    context.Context
	cancel context.CancelFunc

	mu            sync.RWMutex
	closed        bool
	started       bool
	peers         map[uint32]*PeerSession
	pending       map[*pendingConnection]struct{}
	wg            sync.WaitGroup
	pingerEnabled bool
	pingers       map[uint32]*PeerConnPinger

	// rpcHandler consumes locally-destined RPC packets inside the manager
	// pipeline (peer-RPC dispatch). When nil, RPC packets are delivered to
	// Receive for the embedding runtime to dispatch.
	rpcMu      sync.RWMutex
	rpcHandler RPCHandlerFunc
}

// RPCHandlerFunc handles one locally-destined RPC packet. It reports whether
// the packet was consumed (true) or must be delivered to Receive (false).
type RPCHandlerFunc func(context.Context, protocol.Packet) bool

// SetRPCHandler installs the manager-pipeline RPC handler. It is safe to
// call concurrently with traffic; a nil handler restores delivery to
// Receive.
func (m *PeerConnectionManager) SetRPCHandler(handler RPCHandlerFunc) {
	m.rpcMu.Lock()
	defer m.rpcMu.Unlock()
	m.rpcHandler = handler
}

func (m *PeerConnectionManager) getRPCHandler() RPCHandlerFunc {
	m.rpcMu.RLock()
	defer m.rpcMu.RUnlock()
	return m.rpcHandler
}

type pendingConnection struct {
	channel PacketChannel
}

// NewPeerConnectionManager validates and creates a manager.
func NewPeerConnectionManager(config PeerConnectionManagerConfig) (*PeerConnectionManager, error) {
	if config.LocalPeerID == 0 {
		return nil, errors.New("local peer ID must not be zero")
	}
	if config.MaxPeers < 0 {
		return nil, errors.New("maximum peer count must not be negative")
	}
	maxPeers := config.MaxPeers
	if maxPeers == 0 {
		maxPeers = DefaultMaxPeers
	}
	mode := config.HandshakeMode
	if config.UseDirectNoise {
		mode = HandshakeModeDirectNoise
	}

	legacy := config.LegacyIdentity
	if legacy.PeerID == 0 {
		legacy.PeerID = config.LocalPeerID
	}
	direct := config.DirectHandshake
	if direct.LocalPeerID == 0 {
		direct.LocalPeerID = config.LocalPeerID
	}
	if mode == HandshakeModeLegacy && (direct.NetworkName != "" || len(direct.StaticKeypair.Private) != 0) {
		mode = HandshakeModeDirectNoise
	}
	if mode == HandshakeModeLegacy {
		if err := legacy.Validate(); err != nil {
			return nil, fmt.Errorf("validate legacy identity: %w", err)
		}
	} else if mode == HandshakeModeDirectNoise {
		if err := direct.validate(); err != nil {
			return nil, fmt.Errorf("validate direct handshake: %w", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported handshake mode %d", mode)
	}

	router := config.Router
	if router == nil {
		var err error
		router, err = NewPacketRouter(config.LocalPeerID, config.Routes)
		if err != nil {
			return nil, fmt.Errorf("create peer router: %w", err)
		}
	}
	queueSize := config.PacketQueue
	if queueSize == 0 {
		queueSize = 64
	}
	if queueSize < 0 {
		return nil, errors.New("packet queue size must not be negative")
	}
	if config.DataCompressAlgo != protocol.CompressionNone && config.DataCompressAlgo != protocol.CompressionZstd {
		return nil, fmt.Errorf("unsupported data compression algorithm %d", config.DataCompressAlgo)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &PeerConnectionManager{
		localPeerID:      config.LocalPeerID,
		mode:             mode,
		legacy:           legacy,
		direct:           direct,
		maxPeers:         maxPeers,
		dataCompressAlgo: config.DataCompressAlgo,
		router:           router,
		Router:           router,
		packets:          make(chan protocol.Packet, queueSize),
		acl:              config.ACL,
		recvLimiter:      config.RecvLimiter,
		stats:            config.Stats,
		ctx:              ctx,
		cancel:           cancel,
		peers:            make(map[uint32]*PeerSession),
		pending:          make(map[*pendingConnection]struct{}),
		pingers:          make(map[uint32]*PeerConnPinger),
		pingerEnabled:    config.PingerEnabled,
	}, nil
}

// Start binds the manager lifecycle to ctx. It is optional when callers only
// use Accept/Connect and Close.
func (m *PeerConnectionManager) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("manager context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrPeerConnectionManagerClosed
	}
	if m.started {
		m.mu.Unlock()
		return errors.New("peer connection manager is already started")
	}
	m.started = true
	m.cancel()
	m.ctx, m.cancel = context.WithCancel(ctx)
	managerContext := m.ctx
	m.mu.Unlock()
	go func() {
		<-managerContext.Done()
		m.shutdown()
	}()
	return nil
}

// Run starts the manager and waits for ctx cancellation.
func (m *PeerConnectionManager) Run(ctx context.Context) error {
	if err := m.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	_ = m.Close()
	return nil
}

// Accept performs a responder handshake and registers the resulting session.
func (m *PeerConnectionManager) Accept(ctx context.Context, channel PacketChannel) error {
	return m.handleConnection(ctx, channel, false)
}

// Connect performs an initiator handshake and registers the resulting session.
func (m *PeerConnectionManager) Connect(ctx context.Context, channel PacketChannel) error {
	return m.handleConnection(ctx, channel, true)
}

// HandleConnection is the role-selecting form of Accept and Connect.
func (m *PeerConnectionManager) HandleConnection(ctx context.Context, channel PacketChannel, initiator bool) error {
	return m.handleConnection(ctx, channel, initiator)
}

func (m *PeerConnectionManager) handleConnection(ctx context.Context, channel PacketChannel, initiator bool) error {
	if ctx == nil {
		return errors.New("connection context is nil")
	}
	if channel == nil {
		return errors.New("packet channel is nil")
	}
	operationContext, stop := m.connectionContext(ctx)
	defer stop()
	pending := &pendingConnection{channel: channel}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrPeerConnectionManagerClosed
	}
	m.pending[pending] = struct{}{}
	m.mu.Unlock()
	defer m.untrackPending(pending)

	tracked := &trackingPacketChannel{PacketChannel: channel}
	var (
		remotePeerID uint32
		secure       *SecureDatagramSession
		level        AuthenticationLevel
		err          error
	)
	if m.mode == HandshakeModeDirectNoise {
		if initiator {
			secure, level, err = InitiateDirectPeerHandshake(operationContext, tracked, m.direct)
		} else {
			secure, level, err = RespondDirectPeerHandshake(operationContext, tracked, m.direct)
		}
		remotePeerID = tracked.remotePeerID()
	} else if initiator {
		var response protocol.HandshakeRequest
		response, err = InitiateLegacyHandshake(operationContext, tracked, m.legacy)
		remotePeerID = response.MyPeerID
	} else {
		var packet protocol.Packet
		packet, err = tracked.Receive(operationContext)
		if err == nil {
			var request protocol.HandshakeRequest
			request, err = RespondLegacyHandshake(operationContext, tracked, m.legacy, packet)
			remotePeerID = request.MyPeerID
		}
	}
	if err != nil {
		return err
	}
	if remotePeerID == 0 || remotePeerID == m.localPeerID {
		return errors.New("handshake returned an invalid remote peer ID")
	}
	session := &PeerSession{
		PeerID:              remotePeerID,
		Channel:             channel,
		Router:              m.router,
		Secure:              secure,
		AuthenticationLevel: level,
		DataCompressAlgo:    m.dataCompressAlgo,
		ACL:                 m.acl,
		RecvLimiter:         m.recvLimiter,
		Stats:               m.stats,
	}
	if err := m.registerSession(session); err != nil {
		_ = session.Close()
		return err
	}
	return nil
}

func (m *PeerConnectionManager) connectionContext(ctx context.Context) (context.Context, func()) {
	combined, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.context(), cancel)
	return combined, func() {
		stop()
		cancel()
	}
}

func (m *PeerConnectionManager) context() context.Context {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ctx
}

func (m *PeerConnectionManager) registerSession(session *PeerSession) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrPeerConnectionManagerClosed
	}
	old := m.peers[session.PeerID]
	if old == nil && len(m.peers) >= m.maxPeers {
		m.mu.Unlock()
		return ErrPeerLimit
	}
	m.peers[session.PeerID] = session
	m.wg.Add(1)
	m.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	if m.pingerEnabled {
		pinger, err := NewPeerConnPinger(PeerConnPingerConfig{
			MyPeerID: m.localPeerID,
			PeerID:   session.PeerID,
			Manager:  m,
		})
		if err == nil {
			m.mu.Lock()
			m.pingers[session.PeerID] = pinger
			m.mu.Unlock()
			pinger.Start()
		}
	}
	go m.receiveSession(session)
	return nil
}

func (m *PeerConnectionManager) receiveSession(session *PeerSession) {
	defer m.wg.Done()
	defer m.removeSession(session)
	for {
		packet, err := session.Channel.Receive(m.context())
		if err != nil {
			return
		}
		// Throughput hook for the adaptive ping controller: every received
		// packet counts as RX activity towards its source peer.
		if pinger := m.pingerFor(packet.Header.FromPeerID); pinger != nil {
			pinger.Throughput().IncRX()
		}
		if session.Secure != nil {
			if packet.Header.Flags&protocol.FlagEncrypted == 0 {
				return
			}
			plaintext, err := session.Secure.Open(packet.Payload)
			if err != nil {
				return
			}
			packet.Payload = plaintext
			packet.Header.Flags &^= protocol.FlagEncrypted
			if !packet.Header.IsCompressed() {
				packet.Header.Length = uint32(len(plaintext))
			}
		}
		if err := protocol.DecompressPacket(&packet); err != nil {
			return
		}
		if !m.allowDataPacket(packet) {
			continue
		}
		decision, err := m.router.Process(packet)
		if err != nil {
			m.addStat("peer_packets_dropped", 1)
			continue
		}
		switch decision.Action {
		case RouteActionForward:
			m.addStat("peer_packets_forwarded", 1)
			if err := m.sendToPeer(m.context(), decision.NextHop, decision.Packet); err != nil {
				if errors.Is(err, ErrPeerConnectionManagerClosed) {
					return
				}
				m.addStat("peer_forward_errors", 1)
				continue
			}
		case RouteActionLocal:
			m.addStat("peer_packets_local", 1)
			if packet.Header.PacketType == protocol.PacketTypePong {
				// Feed the adaptive pinger, then deliver like any other
				// control packet so embedders can observe pong traffic.
				if pinger := m.pingerFor(packet.Header.FromPeerID); pinger != nil {
					pinger.HandlePong(packet)
				}
			}
			if packet.Header.PacketType == protocol.PacketTypePing {
				pong := protocol.Packet{Header: protocol.PeerManagerHeader{
					FromPeerID: m.localPeerID,
					ToPeerID:   packet.Header.FromPeerID,
					PacketType: protocol.PacketTypePong,
				}, Payload: append([]byte(nil), packet.Payload...)}
				if err := m.sendToPeer(m.context(), session.PeerID, pong); err != nil {
					if errors.Is(err, ErrPeerConnectionManagerClosed) {
						return
					}
					m.addStat("peer_pong_errors", 1)
				}
			}
			if packet.Header.PacketType == protocol.PacketTypeRPCRequest ||
				packet.Header.PacketType == protocol.PacketTypeRPCResponse {
				if handler := m.getRPCHandler(); handler != nil {
					if handler(m.context(), packet) {
						m.addStat("peer_rpc_consumed", 1)
						continue
					}
				}
			}
			if err := m.deliver(packet); err != nil {
				if errors.Is(err, ErrPeerConnectionManagerClosed) {
					return
				}
				m.addStat("peer_packets_dropped", 1)
			}
		}
	}
}

func (m *PeerConnectionManager) allowDataPacket(packet protocol.Packet) bool {
	if packet.Header.PacketType != protocol.PacketTypeData {
		return true
	}
	if m.recvLimiter != nil {
		if err := m.recvLimiter.Wait(m.context(), int64(len(packet.Payload))); err != nil {
			return false
		}
	}
	if m.acl == nil {
		m.addStat("peer_data_received", 1)
		m.addStat("peer_bytes_received", uint64(len(packet.Payload)))
		return true
	}
	direction := acl.DirectionForward
	if packet.Header.ToPeerID == m.localPeerID {
		direction = acl.DirectionInbound
	}
	metadata, err := gateway.ParsePacket(packet.Payload, direction)
	if err != nil {
		m.addStat("peer_acl_dropped", 1)
		return false
	}
	if decision := m.acl.Evaluate(metadata); decision.Action != acl.ActionAllow {
		m.addStat("peer_acl_dropped", 1)
		return false
	}
	m.addStat("peer_data_received", 1)
	m.addStat("peer_bytes_received", uint64(len(packet.Payload)))
	return true
}

func (m *PeerConnectionManager) addStat(name string, value uint64) {
	if m.stats != nil {
		m.stats.Add(name, value)
	}
}

func shouldCompressPeerPacket(packetType uint8) bool {
	switch packetType {
	case protocol.PacketTypeData, protocol.PacketTypeKCPSrc, protocol.PacketTypeKCPDst:
		return true
	default:
		return false
	}
}

func (m *PeerConnectionManager) deliver(packet protocol.Packet) error {
	select {
	case m.packets <- packet:
		return nil
	case <-m.context().Done():
		return ErrPeerConnectionManagerClosed
	default:
		return errors.New("peer packet queue is full")
	}
}

func (m *PeerConnectionManager) removeSession(session *PeerSession) {
	_ = session.Close()
	m.mu.Lock()
	if m.peers[session.PeerID] == session {
		delete(m.peers, session.PeerID)
	}
	pinger := m.pingers[session.PeerID]
	delete(m.pingers, session.PeerID)
	m.mu.Unlock()
	if pinger != nil {
		pinger.Stop()
	}
}

func (m *PeerConnectionManager) untrackPending(pending *pendingConnection) {
	m.mu.Lock()
	delete(m.pending, pending)
	m.mu.Unlock()
}

// Send sends a packet directly to peerID. The packet source and destination
// are set to this manager and peerID respectively.
func (m *PeerConnectionManager) Send(ctx context.Context, peerID uint32, packet protocol.Packet) error {
	packet.Header.FromPeerID = m.localPeerID
	packet.Header.ToPeerID = peerID
	return m.sendToPeer(ctx, peerID, packet)
}

// SendPacket routes a packet using this manager's PacketRouter.
func (m *PeerConnectionManager) SendPacket(ctx context.Context, packet protocol.Packet) error {
	packet.Header.FromPeerID = m.localPeerID
	decision, err := m.router.Process(packet)
	if err != nil {
		return err
	}
	if decision.Action == RouteActionLocal {
		return m.deliver(decision.Packet)
	}
	return m.sendToPeer(ctx, decision.NextHop, decision.Packet)
}

func (m *PeerConnectionManager) sendToPeer(ctx context.Context, peerID uint32, packet protocol.Packet) error {
	if ctx == nil {
		return errors.New("send context is nil")
	}
	m.mu.RLock()
	session := m.peers[peerID]
	m.mu.RUnlock()
	if session == nil {
		return fmt.Errorf("%w: %d", ErrPeerNotFound, peerID)
	}
	if err := session.Send(ctx, packet); err != nil {
		m.addStat("peer_send_errors", 1)
		return err
	}
	// Throughput hook for the adaptive ping controller.
	if pinger := m.pingerFor(peerID); pinger != nil {
		pinger.Throughput().IncTX()
	}
	m.addStat("peer_packets_sent", 1)
	m.addStat("peer_bytes_sent", uint64(len(packet.Payload)))
	return nil
}

// Receive returns the next packet delivered locally by the router.
func (m *PeerConnectionManager) Receive(ctx context.Context) (protocol.Packet, error) {
	if ctx == nil {
		return protocol.Packet{}, errors.New("receive context is nil")
	}
	select {
	case packet := <-m.packets:
		return packet, nil
	case <-ctx.Done():
		return protocol.Packet{}, ctx.Err()
	case <-m.context().Done():
		return protocol.Packet{}, ErrPeerConnectionManagerClosed
	}
}

// LocalPeerID returns this manager's local peer ID.
func (m *PeerConnectionManager) LocalPeerID() uint32 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.localPeerID
}

// Peer returns the current session for peerID.
func (m *PeerConnectionManager) Peer(peerID uint32) (*PeerSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	session, ok := m.peers[peerID]
	return session, ok
}

// Peers returns a snapshot of the current peer sessions.
func (m *PeerConnectionManager) Peers() map[uint32]*PeerSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessions := make(map[uint32]*PeerSession, len(m.peers))
	for peerID, session := range m.peers {
		sessions[peerID] = session
	}
	return sessions
}

func (m *PeerConnectionManager) PeerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}

// pingerFor returns the active pinger for peerID, or nil when pingers are
// disabled or the peer has not established a session.
func (m *PeerConnectionManager) pingerFor(peerID uint32) *PeerConnPinger {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pingers[peerID]
}

// PeerLatencyMS returns the smoothed round-trip latency to peerID in
// milliseconds. It returns 1 until the first pong is observed so the
// peer-center report still includes the peer.
func (m *PeerConnectionManager) PeerLatencyMS(peerID uint32) int32 {
	pinger := m.pingerFor(peerID)
	if pinger == nil {
		return 1
	}
	ms := pinger.Latency().Milliseconds()
	if ms <= 0 {
		return 1
	}
	return int32(ms)
}

// Close cancels the manager and closes all pending and established channels.
func (m *PeerConnectionManager) Close() error {
	m.shutdown()
	m.wg.Wait()
	return nil
}

func (m *PeerConnectionManager) shutdown() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.cancel()
	channels := make([]PacketChannel, 0, len(m.pending)+len(m.peers))
	for pending := range m.pending {
		channels = append(channels, pending.channel)
	}
	for _, session := range m.peers {
		channels = append(channels, session.Channel)
	}
	m.pending = make(map[*pendingConnection]struct{})
	m.peers = make(map[uint32]*PeerSession)
	m.mu.Unlock()
	for _, channel := range channels {
		closePacketChannel(channel)
	}
}

func closePacketChannel(channel PacketChannel) {
	if closer, ok := channel.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

type trackingPacketChannel struct {
	PacketChannel
	mu   sync.Mutex
	peer uint32
}

func (c *trackingPacketChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	packet, err := c.PacketChannel.Receive(ctx)
	if err == nil && packet.Header.FromPeerID != 0 {
		c.mu.Lock()
		c.peer = packet.Header.FromPeerID
		c.mu.Unlock()
	}
	return packet, err
}

func (c *trackingPacketChannel) remotePeerID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peer
}

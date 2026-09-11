// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

// Session is a snapshot of one machine known to the configuration server.
// LastSeen is updated when registration or a heartbeat is received.
type Session struct {
	MachineID string
	Name      string
	Version   string
	LastSeen  time.Time
	Connected bool
}

// ServerConfig configures the TCP, UDP, or WebSocket configuration server.
type ServerConfig struct {
	MaxFrameSize   int
	NoiseUpgrader  NoiseUpgrader
	RequireSecure  bool
	DisableNoise   bool
	OnConfigUpdate func(context.Context, Session, ConfigUpdate) error
}

type serverSession struct {
	mu         sync.Mutex
	snapshot   Session
	connection transport.PacketChannel
	cancel     context.CancelFunc
	writeMu    sync.Mutex
}

type packetListener interface {
	Serve(context.Context) error
	Close() error
}

// Server accepts configuration-server sessions and keeps their last-seen
// registry. Records remain available after disconnect with Connected=false.
type Server struct {
	config ServerConfig

	mu          sync.Mutex
	listener    net.Listener
	packet      packetListener
	closed      bool
	closeErr    error
	sessions    map[string]*serverSession
	connections map[transport.PacketChannel]struct{}
	wg          sync.WaitGroup
}

// NewServer creates a configuration-server session registry.
func NewServer(config ServerConfig) (*Server, error) {
	config.MaxFrameSize = normalizedMaxFrameSize(config.MaxFrameSize)
	return &Server{
		config:      config,
		sessions:    make(map[string]*serverSession),
		connections: make(map[transport.PacketChannel]struct{}),
	}, nil
}

// Listen binds the server to a TCP address. It may be called once, before
// Serve.
func (s *Server) Listen(address string) error {
	if s == nil {
		return errors.New("webclient server is nil")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen webclient server on %q: %w", address, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = listener.Close()
		return net.ErrClosed
	}
	if s.listener != nil {
		_ = listener.Close()
		return errors.New("webclient server is already listening")
	}
	if s.packet != nil {
		_ = listener.Close()
		return errors.New("webclient server is already listening")
	}
	s.listener = listener
	return nil
}

// ListenUDP binds a UDP configuration-server listener.
func (s *Server) ListenUDP(address string) error {
	if s == nil {
		return errors.New("webclient server is nil")
	}
	listener, err := transport.ListenUDP(address)
	if err != nil {
		return err
	}
	if err := s.setPacketListener(listener); err != nil {
		_ = listener.Close()
		return err
	}
	return nil
}

// ListenWebSocket binds a WebSocket configuration-server listener.
func (s *Server) ListenWebSocket(address string, options ...transport.WebSocketOptions) error {
	if s == nil {
		return errors.New("webclient server is nil")
	}
	listener, err := transport.ListenWebSocket(address, options...)
	if err != nil {
		return err
	}
	if err := s.setPacketListener(listener); err != nil {
		_ = listener.Close()
		return err
	}
	return nil
}

// ListenWS is an alias for ListenWebSocket.
func (s *Server) ListenWS(address string, options ...transport.WebSocketOptions) error {
	return s.ListenWebSocket(address, options...)
}

func (s *Server) setPacketListener(listener packetListener) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.listener != nil || s.packet != nil {
		return errors.New("webclient server is already listening")
	}
	s.packet = listener
	return nil
}

// Addr returns the bound listener address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		if listener, ok := s.packet.(interface{ Address() net.Addr }); ok {
			return listener.Address()
		}
		return nil
	}
	return s.listener.Addr()
}

// Serve accepts sessions until ctx is canceled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	if s == nil {
		return errors.New("webclient server is nil")
	}
	if ctx == nil {
		return errors.New("webclient server context is nil")
	}
	s.mu.Lock()
	listener := s.listener
	packet := s.packet
	s.mu.Unlock()
	if listener == nil && packet == nil {
		return errors.New("webclient server is not listening")
	}
	stopClose := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stopClose()
	if packet != nil {
		return s.servePacketListener(ctx, packet)
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || s.isClosed() {
				s.wg.Wait()
				return nil
			}
			return fmt.Errorf("accept webclient connection: %w", err)
		}
		channel, err := transport.NewTCPPacketChannel(connection, s.config.MaxFrameSize)
		if err != nil {
			_ = connection.Close()
			continue
		}
		s.wg.Add(1)
		go func(ch transport.PacketChannel) {
			defer s.wg.Done()
			effective := s.maybeUpgradeServerChannel(ctx, ch)
			if effective == nil {
				_ = closePacketChannel(ch)
				return
			}
			if !s.registerConnection(effective) {
				_ = closePacketChannel(effective)
				if effective != ch {
					_ = closePacketChannel(ch)
				}
				return
			}
			defer s.unregisterConnection(effective)
			defer closePacketChannel(effective)
			if effective != ch {
				defer closePacketChannel(ch)
			}
			s.serveChannel(ctx, effective)
		}(channel)
	}
}

func (s *Server) servePacketListener(ctx context.Context, listener packetListener) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	serveResults := make(chan error, 1)
	go func() { serveResults <- listener.Serve(serveCtx) }()
	acceptResults := make(chan packetAcceptResult, 1)
	go func() {
		for {
			channel, err := acceptPacket(serveCtx, listener)
			select {
			case acceptResults <- packetAcceptResult{channel: channel, err: err}:
			case <-serveCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		select {
		case result := <-acceptResults:
			if result.err != nil {
				if ctx.Err() != nil || errors.Is(result.err, net.ErrClosed) || s.isClosed() {
					s.wg.Wait()
					return nil
				}
				return fmt.Errorf("accept webclient session: %w", result.err)
			}
			s.wg.Add(1)
			go func(ch transport.PacketChannel) {
				defer s.wg.Done()
				effective := s.maybeUpgradeServerChannel(ctx, ch)
				if effective == nil {
					_ = closePacketChannel(ch)
					return
				}
				if !s.registerConnection(effective) {
					_ = closePacketChannel(effective)
					if effective != ch {
						_ = closePacketChannel(ch)
					}
					return
				}
				defer s.unregisterConnection(effective)
				defer closePacketChannel(effective)
				if effective != ch {
					defer closePacketChannel(ch)
				}
				s.serveChannel(ctx, effective)
			}(result.channel)
		case err := <-serveResults:
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || s.isClosed() {
				s.wg.Wait()
				return nil
			}
			if err != nil {
				return err
			}
			return nil
		case <-ctx.Done():
			s.wg.Wait()
			return nil
		}
	}
}

func acceptPacket(ctx context.Context, listener packetListener) (transport.PacketChannel, error) {
	switch listener := listener.(type) {
	case *transport.UDPService:
		return listener.Accept(ctx)
	case *transport.WebSocketListener:
		return listener.Accept(ctx)
	default:
		return nil, errors.New("unsupported webclient packet listener")
	}
}

func (s *Server) maybeUpgradeServerChannel(ctx context.Context, ch transport.PacketChannel) transport.PacketChannel {
	if s.config.DisableNoise {
		return ch
	}
	upgraded, _, err := AcceptOrUpgradeServerChannel(ctx, ch, s.config.RequireSecure)
	if err != nil {
		return nil
	}
	return upgraded
}

type packetAcceptResult struct {
	channel transport.PacketChannel
	err     error
}

func (s *Server) serveChannel(ctx context.Context, channel transport.PacketChannel) {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	message, err := readMessage(sessionCtx, channel, s.config.MaxFrameSize)
	if err != nil || message.Type != MessageTypeRegister || message.Registration == nil {
		return
	}
	session := s.registerSession(channel, *message.Registration, cancel)
	if session == nil {
		return
	}
	defer s.disconnectSession(session, channel)
	for {
		message, err := readMessage(sessionCtx, channel, s.config.MaxFrameSize)
		if err != nil {
			return
		}
		switch message.Type {
		case MessageTypeHeartbeat:
			if message.Heartbeat.MachineID != session.snapshotValue().MachineID {
				return
			}
			session.touch()
		case MessageTypeConfigUpdate:
			if s.config.OnConfigUpdate == nil {
				return
			}
			if err := s.config.OnConfigUpdate(sessionCtx, session.snapshotValue(), *message.ConfigUpdate); err != nil {
				return
			}
		default:
			return
		}
	}
}

func (s *Server) registerSession(channel transport.PacketChannel, registration MachineRegistration, cancel context.CancelFunc) *serverSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	current := s.sessions[registration.MachineID]
	if current == nil {
		current = &serverSession{}
		s.sessions[registration.MachineID] = current
	}
	current.mu.Lock()
	oldConnection := current.connection
	oldCancel := current.cancel
	current.connection = channel
	current.cancel = cancel
	current.snapshot = Session{
		MachineID: registration.MachineID,
		Name:      registration.Name,
		Version:   registration.Version,
		LastSeen:  time.Now(),
		Connected: true,
	}
	current.mu.Unlock()
	if oldConnection != nil && oldConnection != channel {
		_ = closePacketChannel(oldConnection)
	}
	if oldCancel != nil && oldConnection != channel {
		oldCancel()
	}
	return current
}

func (s *Server) disconnectSession(session *serverSession, channel transport.PacketChannel) {
	session.mu.Lock()
	if session.connection == channel {
		session.connection = nil
		session.cancel = nil
		session.snapshot.Connected = false
	}
	session.mu.Unlock()
}

func (s *Server) registerConnection(connection transport.PacketChannel) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.connections[connection] = struct{}{}
	return true
}

func (s *Server) unregisterConnection(connection transport.PacketChannel) {
	s.mu.Lock()
	delete(s.connections, connection)
	s.mu.Unlock()
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (session *serverSession) snapshotValue() Session {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.snapshot
}

func (session *serverSession) touch() {
	session.mu.Lock()
	session.snapshot.LastSeen = time.Now()
	session.mu.Unlock()
}

// Sessions returns all known machine records sorted by machine ID.
func (s *Server) Sessions() []Session {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	items := make([]*serverSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		items = append(items, session)
	}
	s.mu.Unlock()
	result := make([]Session, 0, len(items))
	for _, session := range items {
		result = append(result, session.snapshotValue())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].MachineID < result[j].MachineID })
	return result
}

// Session returns a machine record by ID.
func (s *Server) Session(machineID string) (Session, bool) {
	if s == nil {
		return Session{}, false
	}
	s.mu.Lock()
	session, ok := s.sessions[machineID]
	s.mu.Unlock()
	if !ok {
		return Session{}, false
	}
	return session.snapshotValue(), true
}

// SendConfigUpdate sends a configuration update to one connected machine.
func (s *Server) SendConfigUpdate(ctx context.Context, machineID string, update ConfigUpdate) error {
	if ctx == nil {
		return errors.New("webclient config update context is nil")
	}
	s.mu.Lock()
	session, ok := s.sessions[machineID]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("webclient machine %q is not registered", machineID)
	}
	session.mu.Lock()
	connection := session.connection
	session.mu.Unlock()
	if connection == nil {
		return fmt.Errorf("webclient machine %q is not connected", machineID)
	}
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	payload, err := MarshalMessage(NewConfigUpdateMessage(update), s.config.MaxFrameSize)
	if err != nil {
		return err
	}
	if err := connection.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: payload,
	}); err != nil {
		return fmt.Errorf("send webclient config update: %w", err)
	}
	return nil
}

// BroadcastConfigUpdate sends one update to every currently connected machine.
func (s *Server) BroadcastConfigUpdate(ctx context.Context, update ConfigUpdate) error {
	var firstErr error
	for _, session := range s.Sessions() {
		if !session.Connected {
			continue
		}
		if err := s.SendConfigUpdate(ctx, session.MachineID, update); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close stops accepting connections and closes active sessions. It is
// idempotent.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		err := s.closeErr
		s.mu.Unlock()
		return err
	}
	s.closed = true
	if s.listener != nil {
		s.closeErr = s.listener.Close()
	}
	if s.packet != nil {
		s.closeErr = s.packet.Close()
	}
	connections := make([]transport.PacketChannel, 0, len(s.connections))
	cancels := make([]context.CancelFunc, 0, len(s.sessions))
	for connection := range s.connections {
		connections = append(connections, connection)
	}
	for _, session := range s.sessions {
		session.mu.Lock()
		if session.cancel != nil {
			cancels = append(cancels, session.cancel)
		}
		session.connection = nil
		session.cancel = nil
		session.snapshot.Connected = false
		session.mu.Unlock()
	}
	err := s.closeErr
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, connection := range connections {
		_ = closePacketChannel(connection)
	}
	return err
}

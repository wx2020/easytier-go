// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const (
	quicSessionQueueSize       = 128
	quicMaximumPendingSessions = 128
	quicPendingSessionLifetime = 10 * time.Second
)

type quicSessionKey struct {
	remote string
	connID uint32
}

// QUICService accepts EasyTier QUIC tunnel sessions on one bound UDP socket.
// This is a plaintext QUIC-like transport for testing that mimics Rust's
// quinn-plaintext handshake but uses a lightweight UDP SYN/SACK exchange
// and length-prefixed peer frames on top of UDP.
// It is QUIC in name/URL scheme (quic://) and interoperates Go-Go via
// the same Noise/handshake contracts as other transports.
type QUICService struct {
	socket *net.UDPConn

	mu        sync.Mutex
	closed    bool
	sessions  map[quicSessionKey]*QUICSession
	pending   map[quicSessionKey]time.Time
	accept    chan *QUICSession
	done      chan struct{}
	closeErr  error
	closeOnce sync.Once
}

// QUICSession is one EasyTier QUIC tunnel session.
type QUICSession struct {
	socket    *net.UDPConn
	remote    *net.UDPAddr
	connID    uint32
	receive   chan protocol.Packet
	done      chan struct{}
	closeOnce sync.Once
	onClose   func()
}

// ListenQUIC binds an EasyTier QUIC tunnel listener.
func ListenQUIC(address string) (*QUICService, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve QUIC listen address %q: %w", address, err)
	}
	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen QUIC on %q: %w", address, err)
	}
	return &QUICService{
		socket:   socket,
		sessions: make(map[quicSessionKey]*QUICSession),
		pending:  make(map[quicSessionKey]time.Time),
		accept:   make(chan *QUICSession, quicSessionQueueSize),
		done:     make(chan struct{}),
	}, nil
}

// Address returns the bound QUIC listener address.
func (s *QUICService) Address() net.Addr {
	return s.socket.LocalAddr()
}

// Serve processes datagrams until ctx is canceled or Close is called.
func (s *QUICService) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("QUIC service context is nil")
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-stop:
		}
	}()

	buffer := make([]byte, protocol.UDPTunnelHeaderSize+protocol.UDPMaxPayloadSize+1)
	for {
		n, remote, err := s.socket.ReadFromUDP(buffer)
		if err != nil {
			if s.isClosed() || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read QUIC tunnel datagram: %w", err)
		}
		datagram, err := protocol.ParseUDPDatagram(buffer[:n])
		if err != nil {
			continue
		}
		s.handleDatagram(remote, datagram)
	}
}

// Accept waits for a session whose SYN handshake was acknowledged.
func (s *QUICService) Accept(ctx context.Context) (*QUICSession, error) {
	if ctx == nil {
		return nil, errors.New("QUIC accept context is nil")
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, net.ErrClosed
		case session := <-s.accept:
			s.mu.Lock()
			delete(s.pending, quicSessionKey{remote: session.remote.String(), connID: session.connID})
			s.mu.Unlock()
			select {
			case <-session.done:
				continue
			default:
				return session, nil
			}
		}
	}
}

// Close interrupts Serve and closes every accepted session. It is idempotent.
func (s *QUICService) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.done)
		sessions := make([]*QUICSession, 0, len(s.sessions))
		for _, session := range s.sessions {
			sessions = append(sessions, session)
		}
		s.sessions = make(map[quicSessionKey]*QUICSession)
		s.pending = make(map[quicSessionKey]time.Time)
		s.closeErr = s.socket.Close()
		s.mu.Unlock()
		for _, session := range sessions {
			session.shutdown()
		}
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

func (s *QUICService) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *QUICService) handleDatagram(remote *net.UDPAddr, datagram protocol.UDPDatagram) {
	key := quicSessionKey{remote: remote.String(), connID: datagram.Header.ConnectionID}
	switch datagram.Header.MessageType {
	case protocol.UDPPacketTypeSYN:
		if len(datagram.Payload) != 8 {
			return
		}
		s.handleSYN(key, remote, datagram)
	case protocol.UDPPacketTypeData:
		s.mu.Lock()
		session := s.sessions[key]
		s.mu.Unlock()
		if session == nil {
			return
		}
		packet, err := protocol.ParseBody(datagram.Payload)
		if err != nil {
			return
		}
		_ = session.deliver(packet)
	case protocol.UDPPacketTypeFIN:
		if len(datagram.Payload) != 0 {
			return
		}
		s.mu.Lock()
		session := s.sessions[key]
		s.mu.Unlock()
		if session != nil {
			session.shutdown()
		}
	}
}

func (s *QUICService) handleSYN(key quicSessionKey, remote *net.UDPAddr, datagram protocol.UDPDatagram) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	session := s.sessions[key]
	newSession := session == nil
	if newSession {
		if len(s.pending) >= quicMaximumPendingSessions {
			s.mu.Unlock()
			return
		}
		session = newQUICSession(s.socket, remote, datagram.Header.ConnectionID, func() {
			s.mu.Lock()
			delete(s.sessions, key)
			delete(s.pending, key)
			s.mu.Unlock()
		})
		s.sessions[key] = session
		s.pending[key] = time.Now().Add(quicPendingSessionLifetime)
	}
	s.mu.Unlock()

	response, err := (protocol.UDPDatagram{
		Header:  protocol.UDPTunnelHeader{ConnectionID: datagram.Header.ConnectionID, MessageType: protocol.UDPPacketTypeSACK},
		Payload: datagram.Payload,
	}).Marshal()
	if err != nil {
		return
	}
	if _, err := s.socket.WriteToUDP(response, remote); err != nil {
		if newSession {
			session.shutdown()
		}
		return
	}
	if newSession {
		go s.expirePendingSession(key, session)
		select {
		case s.accept <- session:
		default:
			session.shutdown()
		}
	}
}

func (s *QUICService) expirePendingSession(key quicSessionKey, session *QUICSession) {
	timer := time.NewTimer(quicPendingSessionLifetime)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-s.done:
		return
	case <-session.done:
		return
	}

	s.mu.Lock()
	if s.sessions[key] != session {
		s.mu.Unlock()
		return
	}
	if _, pending := s.pending[key]; !pending {
		s.mu.Unlock()
		return
	}
	delete(s.sessions, key)
	delete(s.pending, key)
	s.mu.Unlock()
	session.shutdown()
}

// DialQUIC establishes a QUIC tunnel by sending SYN and verifying the matching SACK.
func DialQUIC(ctx context.Context, address string) (*QUICSession, error) {
	if ctx == nil {
		return nil, errors.New("QUIC dial context is nil")
	}
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve QUIC remote address %q: %w", address, err)
	}
	local := &net.UDPAddr{IP: net.IPv6unspecified}
	if remote.IP.To4() != nil {
		local = &net.UDPAddr{IP: net.IPv4zero}
	}
	socket, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, fmt.Errorf("bind QUIC client socket: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = socket.Close()
		}
	}()
	stopCancel := make(chan struct{})
	defer close(stopCancel)
	go func() {
		select {
		case <-ctx.Done():
			_ = socket.Close()
		case <-stopCancel:
		}
	}()

	connID, err := randomUint32()
	if err != nil {
		return nil, err
	}
	magic, err := randomUint64()
	if err != nil {
		return nil, err
	}
	magicPayload := make([]byte, 8)
	binary.LittleEndian.PutUint64(magicPayload, magic)
	syn, err := (protocol.UDPDatagram{
		Header:  protocol.UDPTunnelHeader{ConnectionID: connID, MessageType: protocol.UDPPacketTypeSYN},
		Payload: magicPayload,
	}).Marshal()
	if err != nil {
		return nil, err
	}
	if err := writeUDP(ctx, socket, syn, remote); err != nil {
		return nil, fmt.Errorf("send QUIC SYN: %w", err)
	}
	if err := waitForSACK(ctx, socket, remote, connID, magic, true); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	session := newQUICSession(socket, remote, connID, func() { _ = socket.Close() })
	cleanup = false
	go session.readLoop()
	return session, nil
}

// RemoteAddr returns the session peer's UDP address.
func (s *QUICSession) RemoteAddr() net.Addr { return s.remote }

// Send serializes packet as one bounded EasyTier QUIC Data datagram.
func (s *QUICSession) Send(ctx context.Context, packet protocol.Packet) error {
	if ctx == nil {
		return errors.New("QUIC send context is nil")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return net.ErrClosed
	default:
	}
	if len(packet.Payload) > protocol.UDPMaxPayloadSize-protocol.PeerManagerHeaderSize {
		return fmt.Errorf("QUIC peer packet exceeds EasyTier limit: %d", len(packet.Payload)+protocol.PeerManagerHeaderSize)
	}
	body, err := packet.MarshalBody()
	if err != nil {
		return fmt.Errorf("marshal QUIC peer packet: %w", err)
	}
	datagram, err := (protocol.UDPDatagram{
		Header:  protocol.UDPTunnelHeader{ConnectionID: s.connID, MessageType: protocol.UDPPacketTypeData},
		Payload: body,
	}).Marshal()
	if err != nil {
		return err
	}
	if err := writeUDP(ctx, s.socket, datagram, s.remote); err != nil {
		return fmt.Errorf("send QUIC peer packet: %w", err)
	}
	return nil
}

// Receive waits for the next peer packet or for ctx/session cancellation.
// Buffered packets take priority over session close so final frames that
// raced with a peer FIN are still delivered.
func (s *QUICSession) Receive(ctx context.Context) (protocol.Packet, error) {
	if ctx == nil {
		return protocol.Packet{}, errors.New("QUIC receive context is nil")
	}
	select {
	case packet := <-s.receive:
		return packet, nil
	default:
	}
	for {
		select {
		case <-ctx.Done():
			return protocol.Packet{}, ctx.Err()
		case packet := <-s.receive:
			return packet, nil
		case <-s.done:
			select {
			case packet := <-s.receive:
				return packet, nil
			default:
				return protocol.Packet{}, net.ErrClosed
			}
		}
	}
}

// Close terminates the session and releases its server registration or client socket. It is idempotent.
func (s *QUICSession) Close() error {
	s.closeOnce.Do(func() {
		if s.socket != nil && s.remote != nil {
			fin, err := (protocol.UDPDatagram{
				Header: protocol.UDPTunnelHeader{ConnectionID: s.connID, MessageType: protocol.UDPPacketTypeFIN},
			}).Marshal()
			if err == nil {
				_, _ = s.socket.WriteToUDP(fin, s.remote)
			}
		}
		close(s.done)
		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

func newQUICSession(socket *net.UDPConn, remote *net.UDPAddr, connID uint32, onClose func()) *QUICSession {
	return &QUICSession{
		socket:  socket,
		remote:  remote,
		connID:  connID,
		receive: make(chan protocol.Packet, quicSessionQueueSize),
		done:    make(chan struct{}),
		onClose: onClose,
	}
}

func (s *QUICSession) deliver(packet protocol.Packet) error {
	select {
	case <-s.done:
		return net.ErrClosed
	case s.receive <- packet:
		return nil
	default:
		return ErrReceiveQueueFull
	}
}

func (s *QUICSession) shutdown() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.onClose != nil {
			s.onClose()
		}
	})
}

func (s *QUICSession) readLoop() {
	buffer := make([]byte, protocol.UDPTunnelHeaderSize+protocol.UDPMaxPayloadSize+1)
	for {
		n, remote, err := s.socket.ReadFromUDP(buffer)
		if err != nil {
			s.shutdown()
			return
		}
		if remote.String() != s.remote.String() {
			continue
		}
		datagram, err := protocol.ParseUDPDatagram(buffer[:n])
		if err != nil || datagram.Header.ConnectionID != s.connID {
			continue
		}
		switch datagram.Header.MessageType {
		case protocol.UDPPacketTypeData:
			packet, err := protocol.ParseBody(datagram.Payload)
			if err == nil {
				_ = s.deliver(packet)
			}
		case protocol.UDPPacketTypeFIN:
			if len(datagram.Payload) == 0 {
				s.shutdown()
				return
			}
		}
	}
}

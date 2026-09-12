// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package transport provides EasyTier network transports.
package transport

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const (
	sessionQueueSize       = 128
	maximumPendingSessions = 128
	pendingSessionLifetime = 10 * time.Second

	// holePunchControlTID and holePunchControlBodyLen shape the punch burst
	// emitted in response to a loopback V4/V6 hole punch control datagram.
	holePunchControlTID     = 1
	holePunchControlBodyLen = 32

	// udpHandshakeTimeout bounds one client-side SYN/SACK exchange.
	udpHandshakeTimeout = 3 * time.Second
)

var ErrReceiveQueueFull = errors.New("UDP session receive queue is full")

type udpSessionKey struct {
	remote string
	connID uint32
}

// UDPService accepts EasyTier UDP tunnel sessions on one bound socket.
type UDPService struct {
	socket *net.UDPConn

	mu        sync.Mutex
	closed    bool
	sessions  map[udpSessionKey]*UDPSession
	pending   map[udpSessionKey]time.Time
	accept    chan *UDPSession
	done      chan struct{}
	closeErr  error
	closeOnce sync.Once
}

// UDPSession is one EasyTier UDP tunnel session.
type UDPSession struct {
	socket  *net.UDPConn
	remote  *net.UDPAddr
	connID  uint32
	receive chan protocol.Packet
	done    chan struct{}
	// anySource accepts datagrams from any address with the matching
	// connection ID; punched sockets may see NAT-rewritten source ports.
	anySource bool

	closeOnce sync.Once
	onClose   func()
}

// ListenUDP binds an EasyTier UDP tunnel listener. Call Serve to process
// datagrams and Accept to obtain newly handshaken sessions.
func ListenUDP(address string) (*UDPService, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP listen address %q: %w", address, err)
	}
	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP on %q: %w", address, err)
	}
	return AdoptUDP(socket), nil
}

// AdoptUDP wraps an already-bound socket into an EasyTier UDP tunnel
// listener. Ownership transfers to the service: Close closes the socket.
func AdoptUDP(socket *net.UDPConn) *UDPService {
	return &UDPService{
		socket:   socket,
		sessions: make(map[udpSessionKey]*UDPSession),
		pending:  make(map[udpSessionKey]time.Time),
		accept:   make(chan *UDPSession, sessionQueueSize),
		done:     make(chan struct{}),
	}
}

// Address returns the bound UDP listener address.
func (s *UDPService) Address() net.Addr {
	return s.socket.LocalAddr()
}

// Serve processes datagrams until ctx is canceled or Close is called.
func (s *UDPService) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("UDP service context is nil")
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

	// The extra byte makes any datagram larger than the protocol maximum fail
	// validation rather than looking like a valid maximum-sized datagram.
	buffer := make([]byte, protocol.UDPTunnelHeaderSize+protocol.UDPMaxPayloadSize+1)
	for {
		n, remote, err := s.socket.ReadFromUDP(buffer)
		if err != nil {
			if s.isClosed() || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read UDP tunnel datagram: %w", err)
		}
		datagram, err := protocol.ParseUDPDatagram(buffer[:n])
		if err != nil {
			continue
		}
		s.handleDatagram(remote, datagram)
	}
}

// Accept waits for a session whose SYN handshake was acknowledged.
func (s *UDPService) Accept(ctx context.Context) (*UDPSession, error) {
	if ctx == nil {
		return nil, errors.New("UDP accept context is nil")
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, net.ErrClosed
		case session := <-s.accept:
			s.mu.Lock()
			delete(s.pending, udpSessionKey{remote: session.remote.String(), connID: session.connID})
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
func (s *UDPService) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.done)
		sessions := make([]*UDPSession, 0, len(s.sessions))
		for _, session := range s.sessions {
			sessions = append(sessions, session)
		}
		s.sessions = make(map[udpSessionKey]*UDPSession)
		s.pending = make(map[udpSessionKey]time.Time)
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

func (s *UDPService) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *UDPService) handleDatagram(remote *net.UDPAddr, datagram protocol.UDPDatagram) {
	key := udpSessionKey{remote: remote.String(), connID: datagram.Header.ConnectionID}
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
		session.deliver(packet)
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
	case protocol.UDPPacketTypeV4HolePunch, protocol.UDPPacketTypeV6HolePunch:
		// Loopback control datagrams direct this listener to send one hole
		// punch burst toward the embedded address from its own socket.
		s.handleHolePunchControl(remote, datagram)
	}
}

// handleHolePunchControl answers a loopback V4/V6 hole punch control datagram
// by emitting one punch packet from the listener socket to the target.
func (s *UDPService) handleHolePunchControl(remote *net.UDPAddr, datagram protocol.UDPDatagram) {
	target, err := protocol.DecodeHolePunchControl(datagram.Header.MessageType, datagram.Payload)
	if err != nil {
		return
	}
	isV4 := datagram.Header.MessageType == protocol.UDPPacketTypeV4HolePunch
	fromV4 := remote.IP.To4() != nil
	if isV4 != fromV4 {
		return
	}
	if !remote.IP.IsLoopback() {
		return
	}

	s.mu.Lock()
	closed := s.closed
	socket := s.socket
	s.mu.Unlock()
	if closed || socket == nil {
		return
	}

	burst, err := (protocol.UDPDatagram{
		Header:  protocol.UDPTunnelHeader{ConnectionID: holePunchControlTID, MessageType: protocol.UDPPacketTypeHolePunch},
		Payload: make([]byte, holePunchControlBodyLen),
	}).Marshal()
	if err != nil {
		return
	}
	_, _ = socket.WriteToUDP(burst, target)
}

func (s *UDPService) handleSYN(key udpSessionKey, remote *net.UDPAddr, datagram protocol.UDPDatagram) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	session := s.sessions[key]
	newSession := session == nil
	if newSession {
		if len(s.pending) >= maximumPendingSessions {
			s.mu.Unlock()
			return
		}
		session = newUDPSession(s.socket, remote, datagram.Header.ConnectionID, func() {
			s.mu.Lock()
			delete(s.sessions, key)
			delete(s.pending, key)
			s.mu.Unlock()
		})
		s.sessions[key] = session
		s.pending[key] = time.Now().Add(pendingSessionLifetime)
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

func (s *UDPService) expirePendingSession(key udpSessionKey, session *UDPSession) {
	timer := time.NewTimer(pendingSessionLifetime)
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

// DialUDP establishes a UDP tunnel by sending SYN and verifying the matching
// SACK from address. The context bounds the entire handshake.
func DialUDP(ctx context.Context, address string) (*UDPSession, error) {
	if ctx == nil {
		return nil, errors.New("UDP dial context is nil")
	}
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP remote address %q: %w", address, err)
	}
	local := &net.UDPAddr{IP: net.IPv6unspecified}
	if remote.IP.To4() != nil {
		local = &net.UDPAddr{IP: net.IPv4zero}
	}
	socket, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, fmt.Errorf("bind UDP client socket: %w", err)
	}
	session, err := dialUDPWithSocket(ctx, socket, remote, true)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	return session, nil
}

// DialUDPWithSocket performs the SYN/SACK handshake over a caller-supplied
// socket (for example a hole-punched one) toward remote. On success the
// session owns the socket: closing it closes the socket. A non-loopback
// remote may answer from any source address; the handshake accepts the first
// matching SACK regardless of source so symmetric-NAT replies survive.
func DialUDPWithSocket(ctx context.Context, socket *net.UDPConn, remote *net.UDPAddr) (*UDPSession, error) {
	if ctx == nil {
		return nil, errors.New("UDP dial context is nil")
	}
	if socket == nil || remote == nil {
		return nil, errors.New("UDP dial socket and remote address are required")
	}
	return dialUDPWithSocket(ctx, socket, remote, false)
}

func dialUDPWithSocket(ctx context.Context, socket *net.UDPConn, remote *net.UDPAddr, requireSourceMatch bool) (*UDPSession, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, udpHandshakeTimeout)
	defer cancel()

	stopCancel := make(chan struct{})
	defer close(stopCancel)
	go func() {
		select {
		case <-handshakeCtx.Done():
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
	if err := writeUDP(handshakeCtx, socket, syn, remote); err != nil {
		return nil, fmt.Errorf("send UDP SYN: %w", err)
	}
	if err := waitForSACK(handshakeCtx, socket, remote, connID, magic, requireSourceMatch); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	session := newUDPSession(socket, remote, connID, func() { _ = socket.Close() })
	session.anySource = !requireSourceMatch
	go session.readLoop()
	return session, nil
}

// RemoteAddr returns the session peer's UDP address.
func (s *UDPSession) RemoteAddr() net.Addr { return s.remote }

// Done returns a channel closed when the session ends.
func (s *UDPSession) Done() <-chan struct{} { return s.done }

// Send serializes packet as one bounded EasyTier UDP Data datagram.
func (s *UDPSession) Send(ctx context.Context, packet protocol.Packet) error {
	if ctx == nil {
		return errors.New("UDP send context is nil")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return net.ErrClosed
	default:
	}
	if len(packet.Payload) > protocol.UDPMaxPayloadSize-protocol.PeerManagerHeaderSize {
		return fmt.Errorf("UDP peer packet exceeds EasyTier limit: %d", len(packet.Payload)+protocol.PeerManagerHeaderSize)
	}
	body, err := packet.MarshalBody()
	if err != nil {
		return fmt.Errorf("marshal UDP peer packet: %w", err)
	}
	datagram, err := (protocol.UDPDatagram{
		Header:  protocol.UDPTunnelHeader{ConnectionID: s.connID, MessageType: protocol.UDPPacketTypeData},
		Payload: body,
	}).Marshal()
	if err != nil {
		return err
	}
	if err := writeUDP(ctx, s.socket, datagram, s.remote); err != nil {
		return fmt.Errorf("send UDP peer packet: %w", err)
	}
	return nil
}

// Receive waits for the next peer packet or for ctx/session cancellation.
// Buffered packets take priority over session close so final frames that
// raced with a peer FIN are still delivered.
func (s *UDPSession) Receive(ctx context.Context) (protocol.Packet, error) {
	if ctx == nil {
		return protocol.Packet{}, errors.New("UDP receive context is nil")
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

// Close terminates the session and releases its server registration or client
// socket. It is idempotent.
func (s *UDPSession) Close() error {
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

func newUDPSession(socket *net.UDPConn, remote *net.UDPAddr, connID uint32, onClose func()) *UDPSession {
	return &UDPSession{
		socket:  socket,
		remote:  remote,
		connID:  connID,
		receive: make(chan protocol.Packet, sessionQueueSize),
		done:    make(chan struct{}),
		onClose: onClose,
	}
}

func (s *UDPSession) deliver(packet protocol.Packet) error {
	select {
	case <-s.done:
		return net.ErrClosed
	case s.receive <- packet:
		return nil
	default:
		return ErrReceiveQueueFull
	}
}

func (s *UDPSession) shutdown() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.onClose != nil {
			s.onClose()
		}
	})
}

func (s *UDPSession) readLoop() {
	buffer := make([]byte, protocol.UDPTunnelHeaderSize+protocol.UDPMaxPayloadSize+1)
	for {
		n, remote, err := s.socket.ReadFromUDP(buffer)
		if err != nil {
			s.shutdown()
			return
		}
		if !s.anySource && remote.String() != s.remote.String() {
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

func waitForSACK(ctx context.Context, socket *net.UDPConn, remote *net.UDPAddr, connID uint32, magic uint64, requireSourceMatch bool) error {
	buffer := make([]byte, protocol.UDPTunnelHeaderSize+protocol.UDPMaxPayloadSize+1)
	for {
		if err := setReadDeadline(ctx, socket); err != nil {
			return err
		}
		n, sender, err := socket.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read UDP SACK: %w", err)
		}
		if requireSourceMatch && sender.String() != remote.String() {
			continue
		}
		if sender.IP.String() != remote.IP.String() {
			continue
		}
		datagram, err := protocol.ParseUDPDatagram(buffer[:n])
		if err != nil || datagram.Header.ConnectionID != connID || datagram.Header.MessageType != protocol.UDPPacketTypeSACK || len(datagram.Payload) != 8 {
			continue
		}
		if binary.LittleEndian.Uint64(datagram.Payload) != magic {
			continue
		}
		_ = socket.SetReadDeadline(timeZero)
		return nil
	}
}

var timeZero = time.Time{}

func writeUDP(ctx context.Context, socket *net.UDPConn, data []byte, remote *net.UDPAddr) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := socket.SetWriteDeadline(deadline); err != nil {
			return err
		}
		defer socket.SetWriteDeadline(timeZero)
	}
	_, err := socket.WriteToUDP(data, remote)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func setReadDeadline(ctx context.Context, socket *net.UDPConn) error {
	if deadline, ok := ctx.Deadline(); ok {
		return socket.SetReadDeadline(deadline)
	}
	return socket.SetReadDeadline(timeZero)
}

func randomUint32() (uint32, error) {
	var data [4]byte
	if _, err := cryptorand.Read(data[:]); err != nil {
		return 0, fmt.Errorf("generate UDP connection ID: %w", err)
	}
	return binary.LittleEndian.Uint32(data[:]), nil
}

func randomUint64() (uint64, error) {
	var data [8]byte
	if _, err := cryptorand.Read(data[:]); err != nil {
		return 0, fmt.Errorf("generate UDP handshake magic: %w", err)
	}
	return binary.LittleEndian.Uint64(data[:]), nil
}

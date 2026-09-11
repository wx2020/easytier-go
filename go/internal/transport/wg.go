// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const wgSessionQueueSize = 128

// wgNativeMagic namespaces EasyTier-native WG bodies so they can never be
// confused with standard WireGuard messages (initiation/response/cookie/
// data, types 1..4). Encrypted sessions always carry it; anything without
// it on a crypto endpoint is routed to the stock-interop path.
const wgNativeMagic = 0xE7

// WGService accepts EasyTier WG tunnel sessions on one bound UDP socket.
// WG transport uses a 20-byte synthetic IPv4 header (see protocol.MarshalWGTunnelHeader)
// wrapping each peer packet, without additional UDP tunnel handshake. When a
// crypto config is installed (ListenWGWithCrypto), the wrapped body is a
// ChaCha20-Poly1305 datagram from WgCryptoState instead of a plaintext peer
// body; undecryptable datagrams are dropped before session creation.
type WGService struct {
	socket *net.UDPConn

	mu        sync.Mutex
	closed    bool
	sessions  map[string]*WGSession
	accept    chan *WGSession
	done      chan struct{}
	closeErr  error
	closeOnce sync.Once

	cryptoCfg *WgCryptoConfig
	// hsResponder answers handshake initiations for all sessions so
	// initiation replays are rejected service-wide.
	hsResponder *WgHandshakeResponder
}

// WGSession is one EasyTier WG tunnel session.
type WGSession struct {
	socket    *net.UDPConn
	remote    *net.UDPAddr
	receive   chan protocol.Packet
	done      chan struct{}
	closeOnce sync.Once
	onClose   func()

	crypto  *WgCryptoState
	sendSeq atomic.Uint64

	// hsPending matches handshake responses to in-flight initiations.
	hsMu      sync.Mutex
	hsPending map[uint32]chan []byte
	// hsCfg retains the static identity for handshakes.
	hsCfg *WgCryptoConfig
}

// ListenWG binds an EasyTier WG tunnel listener.
func ListenWG(address string) (*WGService, error) {
	return ListenWGWithCrypto(address, nil)
}

// ListenWGWithCrypto binds a WG listener whose sessions encrypt with cfg.
// A nil cfg keeps the plaintext framing for compatibility.
func ListenWGWithCrypto(address string, cfg *WgCryptoConfig) (*WGService, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve WG listen address %q: %w", address, err)
	}
	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen WG on %q: %w", address, err)
	}
	service := &WGService{
		socket:    socket,
		sessions:  make(map[string]*WGSession),
		accept:    make(chan *WGSession, wgSessionQueueSize),
		done:      make(chan struct{}),
		cryptoCfg: cfg,
	}
	if cfg != nil {
		service.hsResponder = NewWgHandshakeResponder(*cfg)
	}
	return service, nil
}

// Address returns the bound WG listener address.
func (s *WGService) Address() net.Addr {
	return s.socket.LocalAddr()
}

// Serve processes datagrams until ctx is canceled or Close is called.
func (s *WGService) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("WG service context is nil")
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

	// WG datagram = 20-byte IP header + peer body (up to UDPMaxPayloadSize)
	buffer := make([]byte, protocol.WGTunnelHeaderSize+protocol.UDPMaxPayloadSize+1)
	for {
		n, remote, err := s.socket.ReadFromUDP(buffer)
		if err != nil {
			if s.isClosed() || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read WG tunnel datagram: %w", err)
		}
		s.handleWGDatagram(remote, buffer[:n])
	}
}

// Accept waits for a new WG session.
func (s *WGService) Accept(ctx context.Context) (*WGSession, error) {
	if ctx == nil {
		return nil, errors.New("WG accept context is nil")
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, net.ErrClosed
		case session := <-s.accept:
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
func (s *WGService) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.done)
		sessions := make([]*WGSession, 0, len(s.sessions))
		for _, session := range s.sessions {
			sessions = append(sessions, session)
		}
		s.sessions = make(map[string]*WGSession)
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

func (s *WGService) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// handleHsInit answers one handshake initiation: it authenticates the
// initiator, adopts the session key on the (possibly new) session, replies,
// and surfaces the session via Accept.
func (s *WGService) handleHsInit(remote *net.UDPAddr, body []byte) {
	init, err := ParseHsInit(body)
	if err != nil {
		return
	}
	responder := s.hsResponder
	if responder == nil {
		return
	}
	respDatagram, keys, err := responder.Respond(init)
	if err != nil {
		return
	}
	session, _ := s.sessionForRemote(remote)
	if session == nil || session.crypto == nil {
		return
	}
	session.crypto.AdoptSessionKey(keys.SessionKey)
	header := protocol.MarshalWGTunnelHeader(len(respDatagram) + 1)
	out := make([]byte, 0, len(header)+len(respDatagram)+1)
	out = append(out, header...)
	out = append(out, wgNativeMagic)
	out = append(out, respDatagram...)
	_, _ = s.socket.WriteToUDP(out, remote)
}

// sessionForRemote returns the session for remote, creating (and surfacing
// via Accept) when absent. The boolean reports creation.
func (s *WGService) sessionForRemote(remote *net.UDPAddr) (*WGSession, bool) {
	key := remote.String()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, false
	}
	session := s.sessions[key]
	if session != nil {
		s.mu.Unlock()
		return session, false
	}
	var crypto *WgCryptoState
	if s.cryptoCfg != nil {
		state, err := NewWgCryptoState(*s.cryptoCfg)
		if err != nil {
			s.mu.Unlock()
			return nil, false
		}
		crypto = state
	}
	session = newWGSession(s.socket, remote, crypto, s.cryptoCfg, func() {
		s.mu.Lock()
		delete(s.sessions, key)
		s.mu.Unlock()
	})
	s.sessions[key] = session
	s.mu.Unlock()
	select {
	case s.accept <- session:
	default:
		session.shutdown()
		s.mu.Lock()
		delete(s.sessions, key)
		s.mu.Unlock()
		return nil, false
	}
	return session, true
}

func (s *WGService) handleWGDatagram(remote *net.UDPAddr, data []byte) {
	if len(data) < protocol.WGTunnelHeaderSize+1 {
		return
	}
	header := data[:protocol.WGTunnelHeaderSize]
	if _, err := protocol.ParseWGTunnelHeader(header); err != nil {
		return
	}
	body := data[protocol.WGTunnelHeaderSize:]
	if s.cryptoCfg != nil {
		if len(body) == 0 || body[0] != wgNativeMagic {
			// Standard-shaped datagram without the native magic:
			// routed to the stock-interop path (phase 2), dropped
			// until it is wired.
			return
		}
		// Peek at the native kind without consuming the magic;
		// openDatagram strips it exactly once.
		if native := body[1:]; len(native) > 0 {
			switch native[0] {
			case wgHsTypeInit:
				s.handleHsInit(remote, native)
				return
			case wgHsTypeResp:
				// Servers never initiate; responses to unknown
				// initiations are dropped.
				return
			}
		}
	}
	if len(data) < protocol.WGTunnelHeaderSize+protocol.PeerManagerHeaderSize {
		return
	}
	session, newSession := s.sessionForRemote(remote)
	if session == nil {
		return
	}
	packet, err := session.openDatagram(body)
	if err != nil {
		if newSession {
			// Undecryptable first datagram: drop the session so junk
			// remotes (e.g. wrong network secret) leave no state.
			session.shutdown()
			s.mu.Lock()
			delete(s.sessions, remote.String())
			s.mu.Unlock()
		}
		return
	}
	// Deliver first.
	_ = session.deliver(packet)
}

// DialWG establishes a WG tunnel session to address.
// It creates a client UDP socket and returns a session that wraps packets
// with the synthetic IPv4 header.
func DialWG(ctx context.Context, address string) (*WGSession, error) {
	return DialWGWithCrypto(ctx, address, nil)
}

// DialWGWithCrypto dials like DialWG but encrypts the session with cfg.
// A nil cfg keeps the plaintext framing for compatibility.
func DialWGWithCrypto(ctx context.Context, address string, cfg *WgCryptoConfig) (*WGSession, error) {
	if ctx == nil {
		return nil, errors.New("WG dial context is nil")
	}
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve WG remote address %q: %w", address, err)
	}
	local := &net.UDPAddr{IP: net.IPv6unspecified}
	if remote.IP.To4() != nil {
		local = &net.UDPAddr{IP: net.IPv4zero}
	}
	socket, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, fmt.Errorf("bind WG client socket: %w", err)
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var crypto *WgCryptoState
	if cfg != nil {
		state, err := NewWgCryptoState(*cfg)
		if err != nil {
			return nil, err
		}
		crypto = state
	}
	session := newWGSession(socket, remote, crypto, cfg, func() { _ = socket.Close() })
	cleanup = false
	go session.readLoop()
	return session, nil
}

// RemoteAddr returns the session peer's UDP address.
func (s *WGSession) RemoteAddr() net.Addr { return s.remote }

// Send serializes packet as one bounded EasyTier WG datagram with synthetic header.
// When the session carries crypto, the peer body is sealed first.
func (s *WGSession) Send(ctx context.Context, packet protocol.Packet) error {
	if ctx == nil {
		return errors.New("WG send context is nil")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return net.ErrClosed
	default:
	}
	body, err := s.sealDatagram(packet)
	if err != nil {
		return err
	}
	header := protocol.MarshalWGTunnelHeader(len(body))
	datagram := make([]byte, 0, len(header)+len(body))
	datagram = append(datagram, header...)
	datagram = append(datagram, body...)
	if err := writeUDP(ctx, s.socket, datagram, s.remote); err != nil {
		return fmt.Errorf("send WG peer packet: %w", err)
	}
	return nil
}

// sealDatagram marshals packet, sealing it when the session is encrypted.
func (s *WGSession) sealDatagram(packet protocol.Packet) ([]byte, error) {
	if s.crypto == nil {
		body, err := packet.MarshalBody()
		if err != nil {
			return nil, fmt.Errorf("marshal WG peer packet: %w", err)
		}
		if len(body) > protocol.UDPMaxPayloadSize {
			return nil, fmt.Errorf("WG peer packet exceeds limit: %d", len(body))
		}
		return body, nil
	}
	seq := s.sendSeq.Add(1)
	sealed, err := s.crypto.SealPeerPacket(seq, packet)
	if err != nil {
		return nil, fmt.Errorf("seal WG peer packet: %w", err)
	}
	return append([]byte{wgNativeMagic}, sealed...), nil
}

// openDatagram recovers one peer packet from a received body, decrypting
// when the session is encrypted.
func (s *WGSession) openDatagram(body []byte) (protocol.Packet, error) {
	if s.crypto == nil {
		return protocol.ParseBody(body)
	}
	if len(body) == 0 || body[0] != wgNativeMagic {
		return protocol.Packet{}, errors.New("WG body is missing the native magic")
	}
	plaintext, err := s.crypto.Open(body[1:])
	if err != nil {
		return protocol.Packet{}, err
	}
	return protocol.ParseBody(plaintext)
}

// Receive waits for the next peer packet or for ctx/session cancellation.
func (s *WGSession) Receive(ctx context.Context) (protocol.Packet, error) {
	if ctx == nil {
		return protocol.Packet{}, errors.New("WG receive context is nil")
	}
	select {
	case <-ctx.Done():
		return protocol.Packet{}, ctx.Err()
	case <-s.done:
		return protocol.Packet{}, net.ErrClosed
	case packet := <-s.receive:
		return packet, nil
	}
}

// Close terminates the session and releases its registration or socket. It is idempotent.
func (s *WGSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

func newWGSession(socket *net.UDPConn, remote *net.UDPAddr, crypto *WgCryptoState, hsCfg *WgCryptoConfig, onClose func()) *WGSession {
	return &WGSession{
		socket:  socket,
		remote:  remote,
		crypto:  crypto,
		hsCfg:   hsCfg,
		receive: make(chan protocol.Packet, wgSessionQueueSize),
		done:    make(chan struct{}),
		onClose: onClose,
	}
}

func (s *WGSession) deliver(packet protocol.Packet) error {
	select {
	case <-s.done:
		return net.ErrClosed
	case s.receive <- packet:
		return nil
	default:
		return ErrReceiveQueueFull
	}
}

func (s *WGSession) shutdown() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.onClose != nil {
			s.onClose()
		}
	})
}

func (s *WGSession) readLoop() {
	buffer := make([]byte, protocol.WGTunnelHeaderSize+protocol.UDPMaxPayloadSize+1)
	for {
		n, remote, err := s.socket.ReadFromUDP(buffer)
		if err != nil {
			s.shutdown()
			return
		}
		if remote.String() != s.remote.String() {
			continue
		}
		if n < protocol.WGTunnelHeaderSize+1 {
			continue
		}
		header := buffer[:protocol.WGTunnelHeaderSize]
		if _, err := protocol.ParseWGTunnelHeader(header); err != nil {
			continue
		}
		body := buffer[protocol.WGTunnelHeaderSize:n]
		if s.crypto != nil {
			if len(body) == 0 || body[0] != wgNativeMagic {
				continue
			}
			if native := body[1:]; len(native) > 0 && native[0] == wgHsTypeResp {
				s.routeHsResp(append([]byte(nil), native...))
				continue
			}
		}
		if n < protocol.WGTunnelHeaderSize+protocol.PeerManagerHeaderSize {
			continue
		}
		packet, err := s.openDatagram(body)
		if err != nil {
			continue
		}
		_ = s.deliver(packet)
	}
}

// routeHsResp completes a pending client handshake, if any.
func (s *WGSession) routeHsResp(body []byte) {
	s.hsMu.Lock()
	defer s.hsMu.Unlock()
	if len(s.hsPending) == 0 {
		return
	}
	resp, err := ParseHsResp(body)
	if err != nil {
		return
	}
	if ch, ok := s.hsPending[resp.senderIdx]; ok {
		select {
		case ch <- body:
		default:
		}
	}
}

// Handshake performs the ephemeral Noise handshake with the remote,
// adopting the session key for forward secrecy. Data sent before the
// handshake uses the static identity keys; after success both sides move
// to the handshaked key. Without session crypto it returns an error.
func (s *WGSession) Handshake(ctx context.Context) error {
	if ctx == nil {
		return errors.New("WG handshake context is nil")
	}
	if s.crypto == nil || s.hsCfg == nil {
		return errors.New("WG handshake requires session crypto")
	}
	var idxBytes [4]byte
	if _, err := rand.Read(idxBytes[:]); err != nil {
		return fmt.Errorf("WG handshake index: %w", err)
	}
	senderIdx := binary.LittleEndian.Uint32(idxBytes[:])
	init, ePriv, err := BuildHsInit(*s.hsCfg, senderIdx)
	if err != nil {
		return err
	}
	reply := make(chan []byte, 1)
	s.hsMu.Lock()
	if s.hsPending == nil {
		s.hsPending = make(map[uint32]chan []byte)
	}
	s.hsPending[senderIdx] = reply
	s.hsMu.Unlock()
	defer func() {
		s.hsMu.Lock()
		delete(s.hsPending, senderIdx)
		s.hsMu.Unlock()
	}()
	header := protocol.MarshalWGTunnelHeader(len(init) + 1)
	out := make([]byte, 0, len(header)+len(init)+1)
	out = append(out, header...)
	out = append(out, wgNativeMagic)
	out = append(out, init...)
	if err := writeUDP(ctx, s.socket, out, s.remote); err != nil {
		return fmt.Errorf("send WG handshake initiation: %w", err)
	}
	select {
	case respBytes := <-reply:
		resp, err := ParseHsResp(respBytes)
		if err != nil {
			return err
		}
		keys, err := CompleteInit(*s.hsCfg, ePriv, senderIdx, resp)
		if err != nil {
			return err
		}
		s.crypto.AdoptSessionKey(keys.SessionKey)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return net.ErrClosed
	}
}

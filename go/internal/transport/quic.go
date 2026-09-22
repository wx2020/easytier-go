// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport/quicwire"
)

// QUICService accepts EasyTier QUIC tunnel sessions on one bound UDP socket.
// It uses quicwire to speak the exact RFC 9000 quinn-plaintext 0.3.0 wire contract,
// interoperating with EasyTier Rust 2.6.4 nodes.
type QUICService struct {
	ep *quicwire.Endpoint
}

// QUICSession represents one EasyTier QUIC tunnel session.
// It serializes sending and receiving to maintain 4-byte length-prefixed stream framing
// over QUIC stream 0.
type QUICSession struct {
	conn      *quicwire.Connection
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
}

// ListenQUIC binds an EasyTier QUIC tunnel listener. Optional BindOption
// pins the socket to a network interface.
func ListenQUIC(address string, opts ...BindOption) (*QUICService, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve QUIC listen address %q: %w", address, err)
	}
	_, dev := resolveBindOption(address, opts)
	network := "udp"
	if dev != "" {
		network = udpNetworkForAddr(addr)
	}
	socket, err := listenUDPWithBind(network, addr, dev)
	if err != nil {
		return nil, fmt.Errorf("listen QUIC on %q: %w", address, err)
	}

	ep := quicwire.NewEndpointWithSocket(socket)
	return &QUICService{ep: ep}, nil
}

// Address returns the bound QUIC listener address.
func (s *QUICService) Address() net.Addr {
	return s.ep.LocalAddr()
}

// Serve processes datagrams until ctx is canceled or Close is called.
func (s *QUICService) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("QUIC service context is nil")
	}
	select {
	case <-ctx.Done():
		_ = s.Close()
		return ctx.Err()
	case <-s.ep.Done():
		return nil
	}
}

// Accept waits for the next accepted QUIC session.
func (s *QUICService) Accept(ctx context.Context) (*QUICSession, error) {
	if ctx == nil {
		return nil, errors.New("QUIC accept context is nil")
	}
	conn, err := s.ep.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return newQUICSession(conn), nil
}

// Close closes the listener endpoint.
func (s *QUICService) Close() error {
	return s.ep.Close()
}

// DialQUIC establishes a QUIC tunnel by performing the quinn-plaintext handshake
// to the remote endpoint. Optional BindOption pins the socket to a network interface.
func DialQUIC(ctx context.Context, address string, opts ...BindOption) (*QUICSession, error) {
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
	_, dev := resolveBindOption(address, opts)
	network := "udp"
	if dev != "" {
		network = udpNetworkForAddr(local)
	}
	socket, err := listenUDPWithBind(network, local, dev)
	if err != nil {
		return nil, fmt.Errorf("bind QUIC client socket: %w", err)
	}

	ep := quicwire.NewEndpointWithSocket(socket)
	conn, err := ep.Dial(ctx, remote)
	if err != nil {
		_ = ep.Close()
		return nil, fmt.Errorf("dial QUIC tunnel %q: %w", address, err)
	}

	return newQUICSession(conn), nil
}

func newQUICSession(conn *quicwire.Connection) *QUICSession {
	return &QUICSession{
		conn: conn,
	}
}

// LocalAddr returns the local socket address.
func (s *QUICSession) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the session peer's UDP address.
func (s *QUICSession) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

// Send serializes and writes one complete EasyTier frame over QUIC stream 0.
func (s *QUICSession) Send(ctx context.Context, packet protocol.Packet) error {
	if ctx == nil {
		return errors.New("QUIC send context is nil")
	}
	if err := lockWithContext(ctx, &s.writeMu); err != nil {
		return err
	}
	defer s.writeMu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.conn.Done():
		return net.ErrClosed
	default:
	}

	if err := protocol.WriteStreamFrame(s.conn, packet); err != nil {
		return mapContextError(ctx, err)
	}
	return nil
}

// Receive reads one bounded EasyTier frame from QUIC stream 0.
func (s *QUICSession) Receive(ctx context.Context) (protocol.Packet, error) {
	if ctx == nil {
		return protocol.Packet{}, errors.New("QUIC receive context is nil")
	}
	if err := lockWithContext(ctx, &s.readMu); err != nil {
		return protocol.Packet{}, err
	}
	defer s.readMu.Unlock()

	select {
	case <-ctx.Done():
		return protocol.Packet{}, ctx.Err()
	case <-s.conn.Done():
		return protocol.Packet{}, net.ErrClosed
	default:
	}

	// Stream frames can be read up to DefaultMaxStreamFrameSize (2000) or larger
	packet, err := protocol.ReadStreamFrame(s.conn, 65535)
	if err != nil {
		return protocol.Packet{}, mapContextError(ctx, err)
	}
	return packet, nil
}

// Close terminates the session.
func (s *QUICSession) Close() error {
	s.closeOnce.Do(func() {
		_ = s.conn.Close()
	})
	return nil
}

// Done returns a channel closed when the session terminates.
func (s *QUICSession) Done() <-chan struct{} {
	return s.conn.Done()
}

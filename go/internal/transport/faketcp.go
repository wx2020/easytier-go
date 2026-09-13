// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package transport provides the fake-TCP transport. On Linux and Windows the
// Rust implementation uses privileged packet capture/injection (pnet/WinDivert,
// BPF). The Go implementation exposes the same wire contract and falls back to
// a TCP-based emulation when raw access is unavailable, which is sufficient for
// Go-Go interop and for exercised unit tests. Privileged integration tests
// may replace the fallback with the platform packet layer.

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const fakeTCPSessionQueueSize = 128

// FakeTCPService accepts EasyTier fake-TCP sessions. The on-wire format is a
// TCP stream with length-prefixed peer packets, matching Rust's faketcp which
// wraps ZCPacket type TCP after extraction from synthetic TCP packets.
type FakeTCPService struct {
	listener net.Listener
	maxFrame int

	mu        sync.Mutex
	closed    bool
	accept    chan *FakeTCPSession
	done      chan struct{}
	closeErr  error
	closeOnce sync.Once
}

// FakeTCPSession is one established fake-TCP tunnel.
type FakeTCPSession struct {
	conn      net.Conn
	maxFrame  int
	receive   chan protocol.Packet
	done      chan struct{}
	closeOnce sync.Once
	writeMu   sync.Mutex
	readMu    sync.Mutex
}

// IsPrivileged reports whether the current process has the privileges required
// for raw packet capture/injection on the current OS.
func IsFakeTCPPrivileged() bool {
	return isFakeTCPPrivileged()
}

// ListenFakeTCP binds a fake-TCP listener. maxFrame bounds the stream frame.
// Optional BindDevice pins the listener to a network interface.
func ListenFakeTCP(address string, maxFrame int, opts ...BindOption) (*FakeTCPService, error) {
	if maxFrame == 0 {
		maxFrame = protocol.DefaultMaxStreamFrameSize
	}
	_, dev := resolveBindOption(address, opts)
	listenConfig := net.ListenConfig{Control: bindDeviceControl(dev)}
	ln, err := listenConfig.Listen(context.Background(), "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen fake-TCP on %q: %w", address, err)
	}
	return &FakeTCPService{
		listener: ln,
		maxFrame: maxFrame,
		accept:   make(chan *FakeTCPSession, fakeTCPSessionQueueSize),
		done:     make(chan struct{}),
	}, nil
}

// Address returns the bound address.
func (s *FakeTCPService) Address() net.Addr { return s.listener.Addr() }

// Serve accepts connections until ctx is canceled or Close is called.
func (s *FakeTCPService) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("fake-TCP service context is nil")
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
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.isClosed() || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		sess, err := newFakeTCPSessionFromConn(conn, s.maxFrame)
		if err != nil {
			_ = conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			sess.Close()
			continue
		}
		s.mu.Unlock()
		select {
		case s.accept <- sess:
		default:
			sess.Close()
		}
		go sess.readLoop()
	}
}

// Accept waits for a new fake-TCP session.
func (s *FakeTCPService) Accept(ctx context.Context) (*FakeTCPSession, error) {
	if ctx == nil {
		return nil, errors.New("fake-TCP accept context is nil")
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, net.ErrClosed
		case sess := <-s.accept:
			select {
			case <-sess.done:
				continue
			default:
				return sess, nil
			}
		}
	}
}

// Close interrupts Serve and closes the listener.
func (s *FakeTCPService) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.done)
		s.closeErr = s.listener.Close()
		s.mu.Unlock()
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

func (s *FakeTCPService) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// DialFakeTCP establishes a fake-TCP session to address. Optional
// BindDevice pins the socket to a network interface.
func DialFakeTCP(ctx context.Context, address string, maxFrame int, opts ...BindOption) (*FakeTCPSession, error) {
	if ctx == nil {
		return nil, errors.New("fake-TCP dial context is nil")
	}
	if maxFrame == 0 {
		maxFrame = protocol.DefaultMaxStreamFrameSize
	}
	_, dev := resolveBindOption(address, opts)
	dialer := net.Dialer{Control: bindDeviceControl(dev)}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial fake-TCP %q: %w", address, err)
	}
	sess, err := newFakeTCPSessionFromConn(conn, maxFrame)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	go sess.readLoop()
	return sess, nil
}

func newFakeTCPSessionFromConn(conn net.Conn, maxFrame int) (*FakeTCPSession, error) {
	if conn == nil {
		return nil, fmt.Errorf("fake-TCP connection is nil")
	}
	if maxFrame < protocol.PeerManagerHeaderSize {
		return nil, fmt.Errorf("fake-TCP max frame %d too small", maxFrame)
	}
	return &FakeTCPSession{
		conn:     conn,
		maxFrame: maxFrame,
		receive:  make(chan protocol.Packet, fakeTCPSessionQueueSize),
		done:     make(chan struct{}),
	}, nil
}

// Send writes one length-prefixed peer packet.
func (s *FakeTCPSession) Send(ctx context.Context, packet protocol.Packet) error {
	if ctx == nil {
		return errors.New("fake-TCP send context is nil")
	}
	if err := lockWithContext(ctx, &s.writeMu); err != nil {
		return err
	}
	defer s.writeMu.Unlock()
	stop := interruptWriteOnCancel(ctx, s.conn)
	defer stop()
	if err := setTCPWriteDeadline(ctx, s.conn); err != nil {
		return err
	}
	defer s.conn.SetWriteDeadline(time.Time{})
	body, err := packet.MarshalBody()
	if err != nil {
		return fmt.Errorf("marshal fake-TCP packet: %w", err)
	}
	if len(body) > s.maxFrame {
		return fmt.Errorf("fake-TCP frame exceeds limit: %d", len(body))
	}
	if err := protocol.WriteStreamFrame(s.conn, packet); err != nil {
		return mapContextError(ctx, err)
	}
	return nil
}

// Receive waits for the next packet.
func (s *FakeTCPSession) Receive(ctx context.Context) (protocol.Packet, error) {
	if ctx == nil {
		return protocol.Packet{}, errors.New("fake-TCP receive context is nil")
	}
	if err := lockWithContext(ctx, &s.readMu); err != nil {
		return protocol.Packet{}, err
	}
	defer s.readMu.Unlock()
	// Fast path: deliver an already buffered packet without considering the
	// close state, so frames that arrived before a peer-initiated shutdown
	// are not dropped by the select below choosing <-s.done at random.
	select {
	case pkt := <-s.receive:
		return pkt, nil
	default:
	}
	stop := interruptReadOnCancel(ctx, s.conn)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return protocol.Packet{}, ctx.Err()
		case pkt := <-s.receive:
			return pkt, nil
		case <-s.done:
			// readLoop enqueues frames before the connection error that
			// triggers shutdown; drain once more before reporting closed.
			select {
			case pkt := <-s.receive:
				return pkt, nil
			default:
				return protocol.Packet{}, net.ErrClosed
			}
		}
	}
}

func (s *FakeTCPSession) readLoop() {
	for {
		// Use non-blocking read deadline handled by transport helper via context
		// Here we use direct blocking read with no deadline; interrupt via Close.
		pkt, err := protocol.ReadStreamFrame(s.conn, s.maxFrame)
		if err != nil {
			s.shutdown()
			return
		}
		select {
		case s.receive <- pkt:
		case <-s.done:
			return
		default:
			// Drop if full to avoid blocking readLoop; matches ErrReceiveQueueFull handling.
		}
	}
}

func (s *FakeTCPSession) shutdown() {
	s.closeOnce.Do(func() { close(s.done); _ = s.conn.Close() })
}

// Close terminates the session.
func (s *FakeTCPSession) Close() error {
	s.closeOnce.Do(func() { close(s.done); _ = s.conn.Close() })
	return nil
}

// RemoteAddr returns the peer address.
func (s *FakeTCPSession) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

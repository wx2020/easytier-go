// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// PacketListener is the transport-neutral accept contract used by listeners.
type PacketListener interface {
	Accept(context.Context) (PacketChannel, error)
	Close() error
	Address() net.Addr
}

// PacketChannel is the transport-neutral packet contract shared by TCP, UDP,
// Unix and WebSocket sessions.
type PacketChannel interface {
	Send(context.Context, protocol.Packet) error
	Receive(context.Context) (protocol.Packet, error)
}

// DialPacketChannel selects a transport without making callers duplicate the
// transport-specific handshake and framing choices.
func DialPacketChannel(ctx context.Context, scheme, address string, maxFrame int) (PacketChannel, error) {
	if ctx == nil {
		return nil, fmt.Errorf("packet channel context is nil")
	}
	switch strings.ToLower(scheme) {
	case "tcp":
		return DialTCP(ctx, address, maxFrame)
	case "udp":
		return DialUDP(ctx, address)
	case "ws", "wss":
		return DialWebSocket(ctx, address)
	case "unix":
		return DialUnix(ctx, address, maxFrame)
	case "wg":
		return DialWG(ctx, address)
	case "quic":
		return DialQUIC(ctx, address)
	case "faketcp", "fake-tcp":
		return DialFakeTCP(ctx, address, maxFrame)
	default:
		return nil, fmt.Errorf("unsupported packet channel transport %q", scheme)
	}
}

// ListenPacketChannel creates a listener for the given transport scheme.
// The returned listener's Accept method yields PacketChannel sessions.
// For datagram transports the listener is started in the background.
func ListenPacketChannel(scheme, address string) (PacketListener, error) {
	return ListenPacketChannelWithContext(context.Background(), scheme, address, 0)
}

// ListenPacketChannelWithContext creates a listener using the provided context
// for background serving of datagram transports.
func ListenPacketChannelWithContext(ctx context.Context, scheme, address string, maxFrame int) (PacketListener, error) {
	switch strings.ToLower(scheme) {
	case "tcp":
		ln, err := net.Listen("tcp", address)
		if err != nil {
			return nil, err
		}
		if maxFrame == 0 {
			maxFrame = protocol.DefaultMaxStreamFrameSize
		}
		return &tcpPacketListener{listener: ln, maxFrame: maxFrame, done: make(chan struct{})}, nil
	case "udp":
		svc, err := ListenUDP(address)
		if err != nil {
			return nil, err
		}
		if ctx == nil {
			ctx = context.Background()
		}
		go func() { _ = svc.Serve(ctx) }()
		return &udpPacketListener{service: svc}, nil
	case "wg":
		svc, err := ListenWG(address)
		if err != nil {
			return nil, err
		}
		if ctx == nil {
			ctx = context.Background()
		}
		go func() { _ = svc.Serve(ctx) }()
		return &wgPacketListener{service: svc}, nil
	case "quic":
		svc, err := ListenQUIC(address)
		if err != nil {
			return nil, err
		}
		if ctx == nil {
			ctx = context.Background()
		}
		go func() { _ = svc.Serve(ctx) }()
		return &quicPacketListener{service: svc}, nil
	case "faketcp", "fake-tcp":
		svc, err := ListenFakeTCP(address, maxFrame)
		if err != nil {
			return nil, err
		}
		if ctx == nil {
			ctx = context.Background()
		}
		go func() { _ = svc.Serve(ctx) }()
		return &fakeTCPListener{service: svc}, nil
	case "ws", "wss":
		ln, err := ListenWebSocket(address)
		if err != nil {
			return nil, err
		}
		if ctx == nil {
			ctx = context.Background()
		}
		go func() { _ = ln.Serve(ctx) }()
		return &wsPacketListener{listener: ln}, nil
	case "unix":
		if maxFrame == 0 {
			maxFrame = protocol.DefaultMaxStreamFrameSize
		}
		ln, err := ListenUnix(address, maxFrame)
		if err != nil {
			return nil, err
		}
		return &unixPacketListener{listener: ln}, nil
	default:
		return nil, fmt.Errorf("unsupported packet channel transport %q", scheme)
	}
}

type tcpPacketListener struct {
	listener net.Listener
	maxFrame int
	done     chan struct{}
}

func (l *tcpPacketListener) Accept(ctx context.Context) (PacketChannel, error) {
	if ctx == nil {
		return nil, fmt.Errorf("accept context is nil")
	}
	// Use goroutine to make Accept interruptible via context.
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, e := l.listener.Accept()
		ch <- result{c, e}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return NewTCPPacketChannel(r.conn, l.maxFrame)
	}
}

func (l *tcpPacketListener) Close() error      { return l.listener.Close() }
func (l *tcpPacketListener) Address() net.Addr { return l.listener.Addr() }

type udpPacketListener struct{ service *UDPService }

func (l *udpPacketListener) Accept(ctx context.Context) (PacketChannel, error) {
	return l.service.Accept(ctx)
}
func (l *udpPacketListener) Close() error      { return l.service.Close() }
func (l *udpPacketListener) Address() net.Addr { return l.service.Address() }

type wgPacketListener struct{ service *WGService }

func (l *wgPacketListener) Accept(ctx context.Context) (PacketChannel, error) {
	return l.service.Accept(ctx)
}
func (l *wgPacketListener) Close() error      { return l.service.Close() }
func (l *wgPacketListener) Address() net.Addr { return l.service.Address() }

type quicPacketListener struct{ service *QUICService }

func (l *quicPacketListener) Accept(ctx context.Context) (PacketChannel, error) {
	return l.service.Accept(ctx)
}
func (l *quicPacketListener) Close() error      { return l.service.Close() }
func (l *quicPacketListener) Address() net.Addr { return l.service.Address() }

type wsPacketListener struct{ listener *WebSocketListener }

func (l *wsPacketListener) Accept(ctx context.Context) (PacketChannel, error) {
	return l.listener.Accept(ctx)
}
func (l *wsPacketListener) Close() error      { return l.listener.Close() }
func (l *wsPacketListener) Address() net.Addr { return l.listener.Address() }

type unixPacketListener struct{ listener *UnixListener }

func (l *unixPacketListener) Accept(ctx context.Context) (PacketChannel, error) {
	return l.listener.Accept(ctx)
}
func (l *unixPacketListener) Close() error      { return l.listener.Close() }
func (l *unixPacketListener) Address() net.Addr { return l.listener.Address() }

type fakeTCPListener struct{ service *FakeTCPService }

func (l *fakeTCPListener) Accept(ctx context.Context) (PacketChannel, error) {
	return l.service.Accept(ctx)
}
func (l *fakeTCPListener) Close() error      { return l.service.Close() }
func (l *fakeTCPListener) Address() net.Addr { return l.service.Address() }

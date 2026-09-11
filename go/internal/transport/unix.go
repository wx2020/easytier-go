// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// UnixPacketChannel adapts one Unix-domain stream to the packet-channel
// contract. It uses the same framed stream implementation as TCP.
type UnixPacketChannel struct {
	*TCPPacketChannel

	onClose   func()
	closeOnce sync.Once
}

// NewUnixPacketChannel wraps an accepted or dialed Unix-domain stream.
func NewUnixPacketChannel(connection net.Conn, maxFrame int) (*UnixPacketChannel, error) {
	if connection == nil {
		return nil, fmt.Errorf("Unix connection is nil")
	}
	if maxFrame == 0 {
		maxFrame = protocol.DefaultMaxStreamFrameSize
	}
	if maxFrame < protocol.PeerManagerHeaderSize {
		return nil, fmt.Errorf("maximum Unix frame size %d is too small", maxFrame)
	}
	return &UnixPacketChannel{
		TCPPacketChannel: &TCPPacketChannel{connection: connection, maxFrame: maxFrame},
	}, nil
}

// DialUnix connects to a Unix-domain tunnel endpoint with a context deadline.
func DialUnix(ctx context.Context, address string, maxFrame int) (*UnixPacketChannel, error) {
	if ctx == nil {
		return nil, errors.New("Unix dial context is nil")
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", address)
	if err != nil {
		return nil, fmt.Errorf("dial Unix tunnel %q: %w", address, err)
	}
	channel, err := NewUnixPacketChannel(connection, maxFrame)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return channel, nil
}

// Send writes one bounded EasyTier stream frame.
func (c *UnixPacketChannel) Send(ctx context.Context, packet protocol.Packet) error {
	body, err := packet.MarshalBody()
	if err != nil {
		return fmt.Errorf("marshal Unix peer packet: %w", err)
	}
	if len(body) > c.maxFrame {
		return fmt.Errorf("Unix peer packet exceeds frame limit: %d", len(body))
	}
	return c.TCPPacketChannel.Send(ctx, packet)
}

// Close terminates the stream and is safe to call repeatedly.
func (c *UnixPacketChannel) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.TCPPacketChannel.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

// UnixListener accepts Unix-domain packet channels and owns the socket path.
type UnixListener struct {
	listener *net.UnixListener
	path     string
	maxFrame int
	done     chan struct{}

	mu          sync.Mutex
	closed      bool
	closeErr    error
	connections map[*UnixPacketChannel]struct{}
	closeOnce   sync.Once
}

// ListenUnix binds an EasyTier Unix-domain tunnel listener.
func ListenUnix(address string, maxFrame int) (*UnixListener, error) {
	if maxFrame == 0 {
		maxFrame = protocol.DefaultMaxStreamFrameSize
	}
	if maxFrame < protocol.PeerManagerHeaderSize {
		return nil, fmt.Errorf("maximum Unix frame size %d is too small", maxFrame)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen Unix tunnel on %q: %w", address, err)
	}
	return &UnixListener{
		listener:    listener,
		path:        address,
		maxFrame:    maxFrame,
		done:        make(chan struct{}),
		connections: make(map[*UnixPacketChannel]struct{}),
	}, nil
}

// Address returns the bound Unix listener address.
func (l *UnixListener) Address() net.Addr { return l.listener.Addr() }

// Accept waits for the next Unix packet channel or context cancellation.
func (l *UnixListener) Accept(ctx context.Context) (*UnixPacketChannel, error) {
	if ctx == nil {
		return nil, errors.New("Unix accept context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-l.done:
		return nil, net.ErrClosed
	default:
	}

	stop := context.AfterFunc(ctx, func() { _ = l.listener.SetDeadline(time.Now()) })
	defer stop()
	defer l.listener.SetDeadline(time.Time{})
	connection, err := l.listener.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if l.isClosed() || errors.Is(err, net.ErrClosed) {
			return nil, net.ErrClosed
		}
		return nil, fmt.Errorf("accept Unix tunnel: %w", err)
	}

	channel, err := NewUnixPacketChannel(connection, l.maxFrame)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	channel.onClose = func() {
		l.mu.Lock()
		delete(l.connections, channel)
		l.mu.Unlock()
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = channel.Close()
		return nil, net.ErrClosed
	}
	l.connections[channel] = struct{}{}
	l.mu.Unlock()
	return channel, nil
}

// Close stops accepting, closes accepted channels, and removes the socket
// path. It is idempotent.
func (l *UnixListener) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		close(l.done)
		listenerErr := l.listener.Close()
		connections := make([]*UnixPacketChannel, 0, len(l.connections))
		for channel := range l.connections {
			connections = append(connections, channel)
		}
		l.mu.Unlock()

		pathErr := os.Remove(l.path)
		if errors.Is(pathErr, os.ErrNotExist) {
			pathErr = nil
		}
		l.mu.Lock()
		l.closeErr = errors.Join(listenerErr, pathErr)
		l.mu.Unlock()
		for _, channel := range connections {
			_ = channel.Close()
		}
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closeErr
}

func (l *UnixListener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

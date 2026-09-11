// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

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

// TCPPacketChannel adapts one EasyTier TCP tunnel to the packet-channel
// contract used by peer sessions. Sending is serialized to preserve framing.
type TCPPacketChannel struct {
	connection net.Conn
	maxFrame   int
	readMu     sync.Mutex
	writeMu    sync.Mutex
	closeOnce  sync.Once
}

// NewTCPPacketChannel wraps an accepted or dialed TCP tunnel connection.
func NewTCPPacketChannel(connection net.Conn, maxFrame int) (*TCPPacketChannel, error) {
	if connection == nil {
		return nil, fmt.Errorf("TCP connection is nil")
	}
	if maxFrame == 0 {
		maxFrame = protocol.DefaultMaxStreamFrameSize
	}
	if maxFrame < protocol.PeerManagerHeaderSize {
		return nil, fmt.Errorf("maximum TCP frame size %d is too small", maxFrame)
	}
	return &TCPPacketChannel{connection: connection, maxFrame: maxFrame}, nil
}

// DialTCP connects to an EasyTier TCP tunnel endpoint with a context deadline.
func DialTCP(ctx context.Context, address string, maxFrame int) (*TCPPacketChannel, error) {
	if ctx == nil {
		return nil, errors.New("TCP dial context is nil")
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial TCP tunnel %q: %w", address, err)
	}
	channel, err := NewTCPPacketChannel(connection, maxFrame)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return channel, nil
}

func (c *TCPPacketChannel) Send(ctx context.Context, packet protocol.Packet) error {
	if ctx == nil {
		return errors.New("TCP send context is nil")
	}
	if err := lockWithContext(ctx, &c.writeMu); err != nil {
		return err
	}
	defer c.writeMu.Unlock()
	stop := interruptWriteOnCancel(ctx, c.connection)
	defer stop()
	if err := setTCPWriteDeadline(ctx, c.connection); err != nil {
		return err
	}
	defer c.connection.SetWriteDeadline(time.Time{})
	body, err := packet.MarshalBody()
	if err != nil {
		return fmt.Errorf("marshal TCP peer packet: %w", err)
	}
	if len(body) > c.maxFrame {
		return fmt.Errorf("TCP peer frame exceeds limit: %d", len(body))
	}
	if err := protocol.WriteStreamFrame(c.connection, packet); err != nil {
		return mapContextError(ctx, err)
	}
	return nil
}

func (c *TCPPacketChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	if ctx == nil {
		return protocol.Packet{}, errors.New("TCP receive context is nil")
	}
	if err := lockWithContext(ctx, &c.readMu); err != nil {
		return protocol.Packet{}, err
	}
	defer c.readMu.Unlock()
	stop := interruptReadOnCancel(ctx, c.connection)
	defer stop()
	if err := setTCPReadDeadline(ctx, c.connection); err != nil {
		return protocol.Packet{}, err
	}
	defer c.connection.SetReadDeadline(time.Time{})
	packet, err := protocol.ReadStreamFrame(c.connection, c.maxFrame)
	if err != nil {
		return protocol.Packet{}, mapContextError(ctx, err)
	}
	return packet, err
}

func mapContextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}

func lockWithContext(ctx context.Context, mutex *sync.Mutex) error {
	if ctx == nil {
		return errors.New("transport context is nil")
	}
	locked := make(chan struct{}, 1)
	go func() {
		mutex.Lock()
		locked <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		go func() {
			<-locked
			mutex.Unlock()
		}()
		return ctx.Err()
	case <-locked:
		return nil
	}
}

func interruptReadOnCancel(ctx context.Context, connection net.Conn) func() {
	stop := context.AfterFunc(ctx, func() { _ = connection.SetReadDeadline(time.Now()) })
	return func() { stop() }
}

func interruptWriteOnCancel(ctx context.Context, connection net.Conn) func() {
	stop := context.AfterFunc(ctx, func() { _ = connection.SetWriteDeadline(time.Now()) })
	return func() { stop() }
}

// Close interrupts reads and writes. It is idempotent.
func (c *TCPPacketChannel) Close() error {
	var err error
	c.closeOnce.Do(func() { err = c.connection.Close() })
	return err
}

func setTCPReadDeadline(ctx context.Context, connection net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		return connection.SetReadDeadline(deadline)
	}
	return connection.SetReadDeadline(time.Time{})
}

func setTCPWriteDeadline(ctx context.Context, connection net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		return connection.SetWriteDeadline(deadline)
	}
	return connection.SetWriteDeadline(time.Time{})
}

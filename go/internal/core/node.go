// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package core owns the lifecycle of one Go EasyTier instance.
package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

// Node is the first networked vertical slice of the Go daemon. It owns a TCP
// listener and handles reference-compatible Ping/Pong peer packets.
type Node struct {
	listener net.Listener
	maxFrame int
	identity *peer.LegacyIdentity
	runtime  *nodeRuntime

	mu          sync.Mutex
	closed      bool
	closeErr    error
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup
}

// Listen starts an EasyTier TCP transport listener. An address with port zero
// is supported for deterministic integration tests and embedders.
func Listen(address string, maxFrame int) (*Node, error) {
	return ListenWithIdentity(address, maxFrame, nil)
}

// ListenWithIdentity starts a TCP listener that also accepts legacy EasyTier
// handshakes for identity. A nil identity keeps the listener in ping-only mode.
func ListenWithIdentity(address string, maxFrame int, identity *peer.LegacyIdentity) (*Node, error) {
	if maxFrame == 0 {
		maxFrame = protocol.DefaultMaxStreamFrameSize
	}
	if maxFrame < protocol.PeerManagerHeaderSize {
		return nil, fmt.Errorf("maximum frame size %d is too small", maxFrame)
	}
	if identity != nil {
		if err := identity.Validate(); err != nil {
			return nil, fmt.Errorf("validate listener identity: %w", err)
		}
		identityCopy := *identity
		identity = &identityCopy
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", address, err)
	}
	node := &Node{listener: listener, maxFrame: maxFrame, identity: identity, connections: make(map[net.Conn]struct{})}
	if identity != nil {
		manager, err := peer.NewPeerConnectionManager(peer.PeerConnectionManagerConfig{
			LocalPeerID:    identity.PeerID,
			LegacyIdentity: *identity,
			HandshakeMode:  peer.HandshakeModeLegacy,
			PacketQueue:    128,
		})
		if err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("create peer connection manager: %w", err)
		}
		node.runtime = &nodeRuntime{manager: manager}
	}
	return node, nil
}

// Address returns the bound TCP listener address.
func (n *Node) Address() net.Addr {
	return n.listener.Addr()
}

// Serve accepts connections until the context is canceled or Close is called.
func (n *Node) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("node serve context is nil")
	}
	if n.runtime != nil {
		return n.serveManaged(ctx)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = n.Close()
		case <-stop:
		}
	}()

	for {
		connection, err := n.listener.Accept()
		if err != nil {
			if n.isClosed() || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				n.wg.Wait()
				return nil
			}
			return fmt.Errorf("accept TCP tunnel: %w", err)
		}
		if !n.registerConnection(connection) {
			_ = connection.Close()
			continue
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			defer n.unregisterConnection(connection)
			defer connection.Close()
			n.serveConnection(connection)
		}()
	}
}

func (n *Node) serveConnection(connection net.Conn) {
	channel, err := transport.NewTCPPacketChannel(connection, n.maxFrame)
	if err != nil {
		return
	}
	for {
		packet, err := channel.Receive(context.Background())
		if err != nil {
			return
		}
		switch packet.Header.PacketType {
		case protocol.PacketTypePing:
			response := protocol.Packet{
				Header: protocol.PeerManagerHeader{
					FromPeerID: packet.Header.ToPeerID,
					ToPeerID:   packet.Header.FromPeerID,
					PacketType: protocol.PacketTypePong,
				},
				Payload: packet.Payload,
			}
			if err := channel.Send(context.Background(), response); err != nil {
				return
			}
		case protocol.PacketTypeHandshake:
			if n.identity == nil {
				return
			}
			if _, err := peer.RespondLegacyHandshake(context.Background(), channel, *n.identity, packet); err != nil {
				return
			}
		}
	}
}

// Close is idempotent and interrupts all accepted connections.
func (n *Node) Close() error {
	n.mu.Lock()
	if n.closed {
		err := n.closeErr
		n.mu.Unlock()
		return err
	}
	n.closed = true
	n.closeErr = n.listener.Close()
	connections := make([]net.Conn, 0, len(n.connections))
	for connection := range n.connections {
		connections = append(connections, connection)
	}
	err := n.closeErr
	n.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	if n.runtime != nil {
		err = errors.Join(err, n.runtime.close())
	}
	return err
}

func (n *Node) isClosed() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closed
}

func (n *Node) registerConnection(connection net.Conn) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return false
	}
	n.connections[connection] = struct{}{}
	return true
}

func (n *Node) unregisterConnection(connection net.Conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.connections, connection)
}

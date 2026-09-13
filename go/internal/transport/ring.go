// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// In-memory ring tunnel for tests and in-process wiring.
//
// Rust reference: easytier/src/tunnel/ring.rs. A ring tunnel connects two
// ends through bounded in-memory queues: one queue per direction, each
// created with RING_TUNNEL_CAP (128). The listener registers a lookup id
// (ring://<uuid>) in a global map; the connector creates both direction
// queues, hands the server end to the listener through the map, and keeps
// the client end. create_ring_tunnel_pair builds the same pair without the
// registry.
package transport

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// ringTunnelCap mirrors RING_TUNNEL_CAP: the queue depth of each direction.
const ringTunnelCap = 128

// RingPacketChannel is one end of a ring tunnel. It satisfies PacketChannel;
// each end carries the traffic of exactly one direction, as in the oracle.
type RingPacketChannel struct {
	id       string
	receive  chan protocol.Packet
	send     chan protocol.Packet
	done     chan struct{}
	peerDone chan struct{}
	sendSeq  atomic.Uint64

	closeOnce sync.Once
	closeErr  error
}

// CreateRingTunnelPair builds a connected ring tunnel pair and returns the
// server end and the client end.
func CreateRingTunnelPair() (*RingPacketChannel, *RingPacketChannel) {
	clientToServer := make(chan protocol.Packet, ringTunnelCap)
	serverToClient := make(chan protocol.Packet, ringTunnelCap)
	serverDone := make(chan struct{})
	clientDone := make(chan struct{})
	server := &RingPacketChannel{
		id:       newRingID(),
		receive:  clientToServer,
		send:     serverToClient,
		done:     serverDone,
		peerDone: clientDone,
	}
	client := &RingPacketChannel{
		id:       newRingID(),
		receive:  serverToClient,
		send:     clientToServer,
		done:     clientDone,
		peerDone: serverDone,
	}
	return server, client
}

func newRingID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ID reports the synthetic tunnel id (ring://<id> in the tunnel URL).
func (r *RingPacketChannel) ID() string { return r.id }

// Send enqueues one packet for the peer end. It blocks while the direction
// queue is full, exiting on ctx or when either end closes.
func (r *RingPacketChannel) Send(ctx context.Context, packet protocol.Packet) error {
	if ctx == nil {
		return fmt.Errorf("ring send context is nil")
	}
	body, err := packet.MarshalBody()
	if err != nil {
		return fmt.Errorf("marshal ring packet: %w", err)
	}
	if len(body) > protocol.UDPMaxPayloadSize {
		return fmt.Errorf("ring packet exceeds limit: %d", len(body))
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return net.ErrClosed
	case <-r.peerDone:
		return net.ErrClosed
	default:
	}
	select {
	case r.send <- packet:
		r.sendSeq.Add(1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return net.ErrClosed
	case <-r.peerDone:
		return net.ErrClosed
	}
}

// Receive waits for the next packet from the peer end. Draining takes
// priority over close so final frames are still delivered.
func (r *RingPacketChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	if ctx == nil {
		return protocol.Packet{}, fmt.Errorf("ring receive context is nil")
	}
	select {
	case packet := <-r.receive:
		return packet, nil
	default:
	}
	for {
		select {
		case <-ctx.Done():
			return protocol.Packet{}, ctx.Err()
		case packet := <-r.receive:
			return packet, nil
		case <-r.done:
			select {
			case packet := <-r.receive:
				return packet, nil
			default:
				return protocol.Packet{}, net.ErrClosed
			}
		case <-r.peerDone:
			select {
			case packet := <-r.receive:
				return packet, nil
			default:
				return protocol.Packet{}, net.ErrClosed
			}
		}
	}
}

// Close terminates this end; the peer observes closure on its next operation.
func (r *RingPacketChannel) Close() error {
	r.closeOnce.Do(func() {
		close(r.done)
	})
	return r.closeErr
}

// ringAddr is the synthetic net.Addr for ring tunnel endpoints.
type ringAddr struct{ id string }

func (a ringAddr) Network() string { return "ring" }
func (a ringAddr) String() string  { return "ring://" + a.id }

// ringRegistry maps listener ids to their accept queues, mirroring
// CONNECTION_MAP in the oracle.
type ringRegistry struct {
	mu      sync.Mutex
	pending map[string]chan *RingPacketChannel
}

var rings = &ringRegistry{pending: make(map[string]chan *RingPacketChannel)}

func (r *ringRegistry) register(id string) (chan *RingPacketChannel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.pending[id]; ok {
		return nil, fmt.Errorf("ring listener %q already registered", id)
	}
	accept := make(chan *RingPacketChannel, 1)
	r.pending[id] = accept
	return accept, nil
}

func (r *ringRegistry) lookup(id string) (chan *RingPacketChannel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	accept, ok := r.pending[id]
	if !ok {
		return nil, fmt.Errorf("ring listener %q is not registered", id)
	}
	return accept, nil
}

func (r *ringRegistry) unregister(id string) {
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
}

// ringListener accepts ring connections registered under one id.
type ringListener struct {
	id     string
	accept chan *RingPacketChannel
	done   chan struct{}

	closeOnce sync.Once
}

// ListenRing registers a ring listener for id (a ring:// URL or bare id).
func ListenRing(address string) (*ringListener, error) {
	id := ringIDFromAddress(address)
	if id == "" {
		return nil, fmt.Errorf("ring listener requires an id, got %q", address)
	}
	accept, err := rings.register(id)
	if err != nil {
		return nil, err
	}
	return &ringListener{id: id, accept: accept, done: make(chan struct{})}, nil
}

func ringIDFromAddress(address string) string {
	id := address
	if parsed, err := parseRingURL(address); err == nil {
		id = parsed
	}
	return strings.Trim(id, "/")
}

func parseRingURL(address string) (string, error) {
	trimmed := strings.TrimPrefix(address, "ring://")
	if trimmed == address {
		return "", fmt.Errorf("address %q is not a ring URL", address)
	}
	return trimmed, nil
}

// Accept waits for a connector to hand over the server end.
func (l *ringListener) Accept(ctx context.Context) (PacketChannel, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ring accept context is nil")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.done:
		return nil, net.ErrClosed
	case channel := <-l.accept:
		return channel, nil
	}
}

// Close unregisters the listener id.
func (l *ringListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	rings.unregister(l.id)
	return nil
}

// Address reports the synthetic listener address.
func (l *ringListener) Address() net.Addr { return ringAddr{id: l.id} }

// DialRing connects to a registered ring listener, returning the client end
// after handing the server end to the listener (mirroring
// RingTunnelConnector::connect).
func DialRing(ctx context.Context, address string) (*RingPacketChannel, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ring dial context is nil")
	}
	id := ringIDFromAddress(address)
	if id == "" {
		return nil, fmt.Errorf("ring dial requires an id, got %q", address)
	}
	accept, err := rings.lookup(id)
	if err != nil {
		return nil, err
	}
	clientToServer := make(chan protocol.Packet, ringTunnelCap)
	serverToClient := make(chan protocol.Packet, ringTunnelCap)
	serverDone := make(chan struct{})
	clientDone := make(chan struct{})
	server := &RingPacketChannel{
		id:       id,
		receive:  clientToServer,
		send:     serverToClient,
		done:     serverDone,
		peerDone: clientDone,
	}
	client := &RingPacketChannel{
		id:       newRingID(),
		receive:  serverToClient,
		send:     clientToServer,
		done:     clientDone,
		peerDone: serverDone,
	}
	select {
	case accept <- server:
		return client, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("ring listener %q is not accepting", id)
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package broadcast

import (
	"net"
	"sync"
	"time"
)

const (
	// peerTTL is how long a discovered peer stays in the relay table before
	// it is re-discovered or removed.
	peerTTL = 2 * time.Minute
)

// Relay forwards UDP broadcast and multicast packets over the overlay network.
// It keeps a lightweight peer table keyed by peer ID so that broadcast frames
// reach every member without any central coordination.
type Relay struct {
	mu      sync.Mutex
	enabled bool
	peers   map[string]*RelayPeer
}

// RelayPeer tracks one remote peer endpoint and its last-seen time.
type RelayPeer struct {
	Addr     *net.UDPAddr
	LastSeen time.Time
}

func New(enabled bool) *Relay {
	return &Relay{enabled: enabled, peers: make(map[string]*RelayPeer)}
}

func (r *Relay) Enabled() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.enabled }

func (r *Relay) SetEnabled(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = enabled
}

// AddPeer records or refreshes a relay peer endpoint.
func (r *Relay) AddPeer(id string, addr *net.UDPAddr) {
	r.mu.Lock()
	r.peers[id] = &RelayPeer{Addr: addr, LastSeen: time.Now()}
	r.mu.Unlock()
}

// Touch refreshes the last-seen time of an already registered peer.
func (r *Relay) Touch(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if peer, ok := r.peers[id]; ok {
		peer.LastSeen = time.Now()
	}
}

func (r *Relay) RemovePeer(id string) {
	r.mu.Lock()
	delete(r.peers, id)
	r.mu.Unlock()
}

// RemoveExpired drops peers that have not been seen within the TTL.
func (r *Relay) RemoveExpired(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-peerTTL)
	for id, peer := range r.peers {
		if peer.LastSeen.Before(cutoff) {
			delete(r.peers, id)
		}
	}
}

func (r *Relay) Peers() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.peers)
}

// PeersSnapshot returns a copy of the current relay table.
func (r *Relay) PeersSnapshot() map[string]*RelayPeer {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := make(map[string]*RelayPeer, len(r.peers))
	for id, peer := range r.peers {
		copy[id] = &RelayPeer{Addr: peer.Addr, LastSeen: peer.LastSeen}
	}
	return copy
}

// HasPeer reports whether a peer is present in the relay table.
func (r *Relay) HasPeer(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.peers[id]
	return ok
}

// isBroadcastFrame reports whether a packet is a broadcast or multicast frame
// destined for the LAN, which is the traffic this relay forwards.
func isBroadcastFrame(dst net.IP) bool {
	if dst == nil {
		return false
	}
	return dst.Equal(net.IPv4bcast) || dst.IsMulticast() || dst.Equal(net.IPv6linklocalallnodes)
}

// ShouldRelay reports whether an incoming frame should be relayed to peers.
// A nil or unspecified source is a broadcast that locally originated; it is
// relayed only when it targets a broadcast/multicast address.
func (r *Relay) ShouldRelay(dst net.IP) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enabled && isBroadcastFrame(dst)
}

// RelayPacket forwards one broadcast frame to every registered peer.
// fn is invoked once per peer with the packet copy; it must be safe for
// concurrent delivery (for example it writes over a UDP socket).
func (r *Relay) RelayPacket(packet []byte, fn func(id string, addr *net.UDPAddr, payload []byte) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enabled {
		return nil
	}
	for id, peer := range r.peers {
		if err := fn(id, peer.Addr, packet); err != nil {
			return err
		}
	}
	return nil
}

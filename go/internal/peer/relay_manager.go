// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"sync"
	"time"
)

const (
	relayHandshakeTimeout   = 5 * time.Second
	relayRetryBaseMs        = 200 * time.Millisecond
	relayMaxAttempts        = 3
	maxPendingPacketsPerPeer = 32
)

// RelayManager tracks relay IK sessions with raced handshake resolution,
// retry backoff and timeout semantics matching Rust relay_peer_map.

type RelayManager struct {
	mu    sync.Mutex
	state map[uint32]*relayPeerState
	// pending handshake signals
	pending map[uint32]chan struct{}
	// buffered packets waiting for handshake
	pendingPackets map[uint32][]pendingEntry

	localPeerID uint32
}

type relayPeerState struct {
	lastActive  time.Time
	failureCount uint32
	nextRetryAt *time.Time
}

type pendingEntry struct {
	packet protocolPacket
}

// protocolPacket is a minimal packet used for pending queue; we reuse protocol.Packet.
type protocolPacket = struct {
	From uint32
	To   uint32
	Type uint8
	Data []byte
}

// NewRelayManager creates a manager for localPeerID.
func NewRelayManager(localPeerID uint32) *RelayManager {
	return &RelayManager{
		state:          make(map[uint32]*relayPeerState),
		pending:        make(map[uint32]chan struct{}),
		pendingPackets: make(map[uint32][]pendingEntry),
		localPeerID:    localPeerID,
	}
}

// ShouldInitiate reports whether this peer should act as initiator in a
// bidirectional race, using the deterministic rule: smaller peer ID initiates.
// Returns true if local should initiate, false if it should yield.
func (m *RelayManager) ShouldInitiate(remotePeerID uint32) bool {
	return m.localPeerID < remotePeerID
}

// TryInitiate attempts to claim handshake initiation for remotePeerID.
// If another handshake is already pending, it checks the race rule.
// Returns true if the caller should proceed as initiator, false if it should
// yield and act as responder.
func (m *RelayManager) TryInitiate(remotePeerID uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch, ok := m.pending[remotePeerID]; ok && ch != nil {
		// Already pending as initiator
		if remotePeerID < m.localPeerID {
			// Remote has smaller ID, we should yield.
			close(ch)
			delete(m.pending, remotePeerID)
			return false
		}
		// We keep initiator role.
		return false
	}
	// No pending, claim initiator.
	ch := make(chan struct{})
	m.pending[remotePeerID] = ch
	return true
}

// CompleteHandshake marks success and clears pending/backoff.
func (m *RelayManager) CompleteHandshake(remotePeerID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pending, remotePeerID)
	st := m.state[remotePeerID]
	if st == nil {
		st = &relayPeerState{}
		m.state[remotePeerID] = st
	}
	st.failureCount = 0
	st.nextRetryAt = nil
	st.lastActive = time.Now()
}

// FailHandshake records a failure and sets backoff.
func (m *RelayManager) FailHandshake(remotePeerID uint32, attempt uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.state[remotePeerID]
	if st == nil {
		st = &relayPeerState{}
		m.state[remotePeerID] = st
	}
	st.failureCount++
	backoff := relayRetryBaseMs * time.Duration(1<<attempt)
	t := time.Now().Add(backoff)
	st.nextRetryAt = &t
	// Clear pending so future attempts can retry after backoff.
	delete(m.pending, remotePeerID)
}

// IsBackoffActive reports whether the peer is in backoff.
func (m *RelayManager) IsBackoffActive(remotePeerID uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.state[remotePeerID]
	if st == nil || st.nextRetryAt == nil {
		return false
	}
	return time.Now().Before(*st.nextRetryAt)
}

// BufferPacket buffers a packet for later flush when handshake completes.
func (m *RelayManager) BufferPacket(remotePeerID uint32, pkt protocolPacket) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pendingPackets[remotePeerID]) >= maxPendingPacketsPerPeer {
		return false
	}
	m.pendingPackets[remotePeerID] = append(m.pendingPackets[remotePeerID], pendingEntry{packet: pkt})
	return true
}

// FlushPending returns and clears buffered packets for the peer.
func (m *RelayManager) FlushPending(remotePeerID uint32) []protocolPacket {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.pendingPackets[remotePeerID]
	delete(m.pendingPackets, remotePeerID)
	out := make([]protocolPacket, 0, len(list))
	for _, e := range list {
		out = append(out, e.packet)
	}
	return out
}

// WithTimeout executes an operation with relay handshake timeout semantics.
// It mirrors Rust's timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), rx).
func WithRelayTimeout(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	if timeout == 0 {
		timeout = relayHandshakeTimeout
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- fn(tctx) }()
	select {
	case <-tctx.Done():
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return context.DeadlineExceeded
	case err := <-done:
		return err
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import "sync"

// SessionTracker mirrors the reference per-peer sync-session state: every
// node stamps its SyncRouteInfo requests with a random session identifier,
// and the receiver tracks the last identifier seen from each peer. A changed
// identifier means the peer restarted its route service, so any per-peer
// saved sync state must be forgotten.
type SessionTracker struct {
	mu          sync.Mutex
	dstSessions map[uint32]uint64
}

// NewSessionTracker creates an empty tracker.
func NewSessionTracker() *SessionTracker {
	return &SessionTracker{dstSessions: make(map[uint32]uint64)}
}

// Observe records the sender's session identifier and reports whether it
// changed since the previous request from that peer.
func (t *SessionTracker) Observe(peerID, sessionID uint64) (changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if previous, ok := t.dstSessions[peerID]; ok && previous == sessionID {
		return false
	}
	t.dstSessions[peerID] = sessionID
	return true
}

// SessionOf returns the last session identifier observed for peerID.
func (t *SessionTracker) SessionOf(peerID uint32) (uint64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	sessionID, ok := t.dstSessions[peerID]
	return sessionID, ok
}

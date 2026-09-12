// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package punch

import (
	"context"
	"sync"
	"time"
)

// TimedSet is a peer blacklist whose entries expire after a fixed timeout.
type TimedSet struct {
	timeout time.Duration

	mu      sync.Mutex
	entries map[uint32]time.Time
}

// NewTimedSet builds a blacklist with the given entry timeout.
func NewTimedSet(timeout time.Duration) *TimedSet {
	return &TimedSet{timeout: timeout, entries: make(map[uint32]time.Time)}
}

// Insert adds or refreshes one peer entry.
func (s *TimedSet) Insert(peerID uint32) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.entries[peerID] = time.Now()
	s.mu.Unlock()
}

// Contains reports whether an unexpired entry exists for the peer.
func (s *TimedSet) Contains(peerID uint32) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inserted, ok := s.entries[peerID]
	if !ok {
		return false
	}
	if time.Since(inserted) >= s.timeout {
		delete(s.entries, peerID)
		return false
	}
	return true
}

// Cleanup drops expired entries.
func (s *TimedSet) Cleanup() {
	if s == nil {
		return
	}
	s.mu.Lock()
	for peerID, inserted := range s.entries {
		if time.Since(inserted) >= s.timeout {
			delete(s.entries, peerID)
		}
	}
	s.mu.Unlock()
}

// BackOff is a capped ladder of retry delays. next advances the index until
// the last rung; rollback steps one rung back.
type BackOff struct {
	ladder []time.Duration
	index  int
}

// NewBackOff builds a backoff ladder from millisecond values.
func NewBackOff(millis []int) *BackOff {
	ladder := make([]time.Duration, len(millis))
	for i, ms := range millis {
		ladder[i] = time.Duration(ms) * time.Millisecond
	}
	return &BackOff{ladder: ladder}
}

// Next returns the current delay and advances (capped at the last rung).
func (b *BackOff) Next() time.Duration {
	if b == nil || len(b.ladder) == 0 {
		return 0
	}
	delay := b.ladder[b.index]
	if b.index < len(b.ladder)-1 {
		b.index++
	}
	return delay
}

// Rollback steps one rung back.
func (b *BackOff) Rollback() {
	if b == nil || b.index == 0 {
		return
	}
	b.index--
}

// Sleep waits for delay, honoring context cancellation.
func Sleep(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

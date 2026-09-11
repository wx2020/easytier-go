// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package relay

import (
	"sync"
	"time"
)

// TokenBucket implements a classic token-bucket limiter for foreign-network
// relay bandwidth. It mirrors Rust's TokenBucket with burst=1 and refill
// every 10ms.
type TokenBucket struct {
	mu       sync.Mutex
	capacity uint64
	fillRate uint64 // bytes per second
	tokens   float64
	last     time.Time
	now      func() time.Time
}

// NewTokenBucket creates a bucket with capacity==fillRate bytes and an
// initial full burst. bps==^uint64(0) is treated as unlimited.
func NewTokenBucket(bps uint64) *TokenBucket {
	if bps == ^uint64(0) {
		return nil
	}
	if bps == 0 {
		bps = 0
	}
	now := time.Now
	return &TokenBucket{
		capacity: bps,
		fillRate: bps,
		tokens:   float64(bps),
		last:     now(),
		now:      now,
	}
}

// NewTokenBucketWithClock is used for deterministic tests.
func NewTokenBucketWithClock(bps uint64, now func() time.Time) *TokenBucket {
	if bps == ^uint64(0) {
		return nil
	}
	t := now()
	return &TokenBucket{
		capacity: bps,
		fillRate: bps,
		tokens:   float64(bps),
		last:     t,
		now:      now,
	}
}

func (b *TokenBucket) refillLocked(now time.Time) {
	if b.fillRate == 0 {
		return
	}
	if now.Before(b.last) {
		b.last = now
		return
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed <= 0 {
		return
	}
	b.tokens += elapsed * float64(b.fillRate)
	if b.tokens > float64(b.capacity) {
		b.tokens = float64(b.capacity)
	}
	b.last = now
}

// TryConsume attempts to consume n bytes without blocking.
func (b *TokenBucket) TryConsume(n uint64) bool {
	if b == nil {
		return true
	}
	if n > b.capacity {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.refillLocked(now)
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// Available returns current tokens for debugging.
func (b *TokenBucket) Available() float64 {
	if b == nil {
		return float64(^uint64(0))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked(b.now())
	return b.tokens
}

// BucketManager keeps per-network buckets sharing the same bps limit.
type BucketManager struct {
	mu       sync.Mutex
	bpsLimit uint64
	buckets  map[string]*TokenBucket
	now      func() time.Time
}

// NewBucketManager creates a manager. bps==MaxUint64 means unlimited.
func NewBucketManager(bpsLimit uint64) *BucketManager {
	return &BucketManager{bpsLimit: bpsLimit, buckets: make(map[string]*TokenBucket), now: time.Now}
}

// NewBucketManagerWithClock is for tests.
func NewBucketManagerWithClock(bpsLimit uint64, now func() time.Time) *BucketManager {
	return &BucketManager{bpsLimit: bpsLimit, buckets: make(map[string]*TokenBucket), now: now}
}

// TryConsume checks and consumes n bytes for network. Returns true if allowed.
func (m *BucketManager) TryConsume(network string, n uint64) bool {
	if m.bpsLimit == ^uint64(0) {
		return true
	}
	m.mu.Lock()
	bucket, ok := m.buckets[network]
	if !ok {
		if m.now != nil {
			bucket = NewTokenBucketWithClock(m.bpsLimit, m.now)
		} else {
			bucket = NewTokenBucket(m.bpsLimit)
		}
		m.buckets[network] = bucket
	}
	m.mu.Unlock()
	if bucket == nil {
		return true
	}
	return bucket.TryConsume(n)
}

// SetBPSLimit updates global limit and recreates buckets.
func (m *BucketManager) SetBPSLimit(bps uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bpsLimit = bps
	m.buckets = make(map[string]*TokenBucket)
}

// GetBucket returns bucket for network (for inspection).
func (m *BucketManager) GetBucket(network string) *TokenBucket {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buckets[network]
}

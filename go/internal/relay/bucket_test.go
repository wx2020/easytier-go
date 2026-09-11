// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package relay

import (
	"testing"
	"time"
)

func TestTokenBucketBasic(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	b := NewTokenBucketWithClock(100, clock)
	if !b.TryConsume(100) {
		t.Fatal("should consume full capacity")
	}
	if b.TryConsume(1) {
		t.Fatal("should be empty")
	}
	// Refill after 500ms -> 50 tokens
	now = now.Add(500 * time.Millisecond)
	if !b.TryConsume(50) {
		t.Fatal("should have 50 after 500ms")
	}
	if b.TryConsume(1) {
		t.Fatal("should be empty again")
	}
	// Oversized
	if b.TryConsume(200) {
		t.Fatal("oversized should fail")
	}
	// Full refill after 2 sec
	now = now.Add(2 * time.Second)
	if !b.TryConsume(100) {
		t.Fatal("should refill to capacity")
	}
}

func TestTokenBucketUnlimited(t *testing.T) {
	var unlimited uint64 = ^uint64(0)
	b := NewTokenBucket(unlimited)
	if b != nil {
		t.Fatal("unlimited should be nil")
	}
	// TryConsume on nil should succeed
	var nilBucket *TokenBucket
	if !nilBucket.TryConsume(1000000) {
		t.Fatal("nil bucket should allow")
	}
}

func TestBucketManagerPerNetwork(t *testing.T) {
	start := time.Now()
	now := start
	clock := func() time.Time { return now }
	mgr := NewBucketManagerWithClock(100, clock)
	// Each network has separate bucket
	if !mgr.TryConsume("net1", 100) {
		t.Fatal("net1 first")
	}
	if !mgr.TryConsume("net2", 100) {
		t.Fatal("net2 separate bucket should still allow")
	}
	if mgr.TryConsume("net1", 1) {
		t.Fatal("net1 should be empty")
	}
	// After refill, net1 should allow again but net2 still empty
	now = now.Add(time.Second)
	if !mgr.TryConsume("net1", 100) {
		t.Fatal("net1 after refill")
	}
	if !mgr.TryConsume("net2", 100) {
		t.Fatal("net2 after refill should also allow")
	}
	// Unlimited manager
	unlimited := NewBucketManager(^uint64(0))
	if !unlimited.TryConsume("any", 100000) {
		t.Fatal("unlimited should allow")
	}
}

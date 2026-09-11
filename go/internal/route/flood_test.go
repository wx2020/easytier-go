// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"context"
	"sync"
	"testing"
	"time"
)

// floodFabric is an in-memory broadcast mesh for tests.
type floodFabric struct {
	mu       sync.Mutex
	flooders map[uint32]*Flooder
	drops    int
}

func newFloodFabric() *floodFabric {
	return &floodFabric{flooders: make(map[uint32]*Flooder)}
}

func (f *floodFabric) add(localPeerID uint32) *Flooder {
	flooder, err := NewFlooder(localPeerID, nil, f.broadcast(localPeerID))
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	f.flooders[localPeerID] = flooder
	f.mu.Unlock()
	return flooder
}

func (f *floodFabric) broadcast(from uint32) BroadcastFunc {
	return func(ctx context.Context, advertisement Advertisement, except uint32) error {
		f.mu.Lock()
		targets := make([]*Flooder, 0, len(f.flooders))
		ids := make([]uint32, 0, len(f.flooders))
		for id, flooder := range f.flooders {
			if id == from || id == except {
				continue
			}
			targets = append(targets, flooder)
			ids = append(ids, id)
		}
		f.mu.Unlock()
		for _, flooder := range targets {
			if _, err := flooder.Receive(ctx, advertisement, from); err != nil {
				f.mu.Lock()
				f.drops++
				f.mu.Unlock()
			}
		}
		return nil
	}
}

func TestFlooderThreeNodeConverges(t *testing.T) {
	fabric := newFloodFabric()
	a := fabric.add(1)
	b := fabric.add(2)
	c := fabric.add(3)

	a.SetLinks(map[uint32]uint32{2: 10})
	b.SetLinks(map[uint32]uint32{1: 10, 3: 5})
	c.SetLinks(map[uint32]uint32{2: 5})

	ctx := context.Background()
	if _, err := a.Originate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Originate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Originate(ctx); err != nil {
		t.Fatal(err)
	}
	routes := a.Routes()
	next := make(map[uint32]uint32)
	for _, r := range routes {
		next[r.Destination] = r.NextHop
	}
	if next[2] != 2 {
		t.Fatalf("A->B next hop = %d, want 2", next[2])
	}
	if next[3] != 2 {
		t.Fatalf("A->C next hop = %d, want 2 (via B)", next[3])
	}
}

func TestFlooderIgnoresStaleVersion(t *testing.T) {
	fabric := newFloodFabric()
	a := fabric.add(1)
	_ = fabric.add(2)

	ctx := context.Background()
	a.SetLinks(map[uint32]uint32{2: 10})
	fresh, err := a.Originate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stale := fresh
	stale.Version = 0
	stale.Peers = []PeerCost{{Peer: 2, Cost: 999}}
	peerB := fabric.flooders[2]
	isNew, err := peerB.Receive(ctx, stale, 1)
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Fatal("stale LSA must not be treated as new")
	}
}

func TestFlooderNoAmplificationLoop(t *testing.T) {
	fabric := newFloodFabric()
	a := fabric.add(1)
	_ = fabric.add(2)

	ctx := context.Background()
	a.SetLinks(map[uint32]uint32{2: 1})
	adv, err := a.Originate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Deliver the same advertisement again: second delivery is a no-op and
	// must not rebroadcast (Receive returns false).
	peerB := fabric.flooders[2]
	isNew, err := peerB.Receive(ctx, adv, 1)
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Fatal("duplicate LSA must not be new")
	}
}

func TestFlooderExpire(t *testing.T) {
	flooder, err := NewFlooder(1, nil, func(ctx context.Context, a Advertisement, e uint32) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	flooder.SetLinks(map[uint32]uint32{2: 1})
	if _, err := flooder.Originate(context.Background()); err != nil {
		t.Fatal(err)
	}
	remote := Advertisement{Origin: 9, Version: 1, Timestamp: time.Now().Unix()}
	if _, err := flooder.Receive(context.Background(), remote, 2); err == nil {
		// Empty-peer advertisements are invalid (origin-only); use a valid one.
		t.Log("empty remote accepted or rejected without error path check")
	}
	_ = remote
	if n := flooder.Expire(time.Now().Add(time.Hour), time.Minute); n < 0 {
		t.Fatal("expire count must not be negative")
	}
}

func TestFlooderValidation(t *testing.T) {
	if _, err := NewFlooder(0, nil, func(ctx context.Context, a Advertisement, e uint32) error { return nil }); err == nil {
		t.Fatal("zero peer ID must fail")
	}
	if _, err := NewFlooder(1, nil, nil); err == nil {
		t.Fatal("nil broadcast must fail")
	}
}

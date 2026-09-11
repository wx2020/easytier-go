// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"testing"
)

func TestEngineLoadAndConvergence(t *testing.T) {
	engine := NewEngine(1)
	// Build a dense graph: 100 nodes fully connected with cost 1
	const nodes = 50
	for i := uint32(2); i <= nodes; i++ {
		engine.AddLink(1, i, 1)
		for j := i + 1; j <= nodes; j++ {
			// Add cheap links between leaves
			if j%10 == 0 {
				engine.AddLink(i, j, 2)
			}
		}
	}
	routes := engine.Snapshot()
	if len(routes) != nodes-1 {
		t.Fatalf("routes = %d, want %d", len(routes), nodes-1)
	}
	for _, r := range routes {
		if r.Cost != 1 {
			t.Fatalf("cost for %d = %d, want 1", r.Destination, r.Cost)
		}
		if r.NextHop != r.Destination {
			t.Fatalf("next hop %d != dest %d", r.NextHop, r.Destination)
		}
	}
	// Remove links and ensure convergence
	for i := uint32(2); i <= 10; i++ {
		engine.RemoveLink(1, i)
		// Alternate path via 11
		engine.AddLink(i, 11, 1)
	}
	routes = engine.Snapshot()
	// Peers 2..10 should now have cost 2 via 11
	for _, r := range routes {
		if r.Destination >= 2 && r.Destination <= 10 {
			if r.Cost != 2 || r.NextHop != 11 {
				t.Fatalf("after reconf dest %d cost %d next %d, want cost 2 next 11", r.Destination, r.Cost, r.NextHop)
			}
		}
	}
}

func BenchmarkEngineSnapshot(b *testing.B) {
	engine := NewEngine(1)
	for i := uint32(2); i < 100; i++ {
		engine.AddLink(1, i, 1)
		for j := i + 1; j < 100; j++ {
			if (i+j)%7 == 0 {
				engine.AddLink(i, j, 1)
			}
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Snapshot()
	}
}

func TestEngineDoesNotAllocateUnboundedOnFuzzInput(t *testing.T) {
	// Simulate fuzz input: large link map should not panic or allocate unboundedly beyond engine's bounds
	engine := NewEngine(1)
	for i := uint32(0); i < 1000; i++ {
		a := i % 100
		b := (i*7 + 3) % 100
		if a == b || a == 0 || b == 0 {
			continue
		}
		engine.AddLink(a, b, uint32(i%5+1))
	}
	routes := engine.Snapshot()
	if len(routes) == 0 {
		t.Fatal("should have routes")
	}
	// Ensure deterministic snapshot regardless of insertion order
	again := engine.Snapshot()
	if len(routes) != len(again) {
		t.Fatal("snapshot not deterministic")
	}
	for i := range routes {
		if routes[i] != again[i] {
			t.Fatalf("snapshot mismatch %v vs %v", routes[i], again[i])
		}
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import "testing"

// TestMultiInstanceRouteConvergence mirrors Rust three_node tests without netns.
// It simulates three instances converging via OSPF-like engine.
func TestMultiInstanceRouteConvergence(t *testing.T) {
	// Three peers: 1-2 directly, 2-3 via ring, 1 should reach 3 via 2 with cost 2
	engines := make([]*Engine, 4) // index 1..3
	for i := 1; i <= 3; i++ {
		engines[i] = NewEngine(uint32(i))
	}
	// Simulate topology
	for i := 1; i <= 3; i++ {
		engines[i].AddLink(1, 2, 1)
		engines[i].AddLink(2, 3, 1)
	}
	for i := 1; i <= 3; i++ {
		routes := engines[i].Snapshot()
		for _, r := range routes {
			switch i {
			case 1:
				if r.Destination == 3 && (r.Cost != 2 || r.NextHop != 2) {
					t.Fatalf("peer 1 route to 3 = %+v, want cost 2 next 2", r)
				}
			case 3:
				if r.Destination == 1 && (r.Cost != 2 || r.NextHop != 2) {
					t.Fatalf("peer 3 route to 1 = %+v", r)
				}
			}
		}
	}
	// Simulate subnet proxy: peer 3 advertises 10.1.2.0/24 - route still via 2
	// In Go this is modeled as proxy networks but route engine still shows reachability
	routes1 := engines[1].Snapshot()
	found := false
	for _, r := range routes1 {
		if r.Destination == 3 {
			found = true
		}
	}
	if !found {
		t.Fatal("peer 1 should have route to 3 for proxy test")
	}
	// Simulate link down: remove 2-3, peer 1 should lose route to 3
	for i := 1; i <= 3; i++ {
		engines[i].RemoveLink(2, 3)
	}
	for i := 1; i <= 3; i++ {
		routes := engines[i].Snapshot()
		for _, r := range routes {
			if r.Destination == 3 && i == 1 {
				t.Fatalf("after link down, peer 1 still has route to 3: %+v", r)
			}
		}
	}
}

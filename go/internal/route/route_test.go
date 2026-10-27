// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"reflect"
	"testing"
)

func TestSnapshotDirectRoute(t *testing.T) {
	engine := NewEngine(1)
	engine.AddLink(1, 2, 7)

	want := []Route{{Destination: 2, NextHop: 2, Cost: 7}}
	if got := engine.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Snapshot() = %#v, want %#v", got, want)
	}
}

func TestSnapshotMultiHopRoute(t *testing.T) {
	// The route table minimizes the summed edge cost (the committed golden
	// vectors pin this behaviour), so the cheaper two-hop path wins here.
	engine := NewEngine(1)
	engine.AddLink(1, 2, 3)
	engine.AddLink(2, 3, 4)
	engine.AddLink(1, 3, 10)

	want := []Route{
		{Destination: 2, NextHop: 2, Cost: 3},
		{Destination: 3, NextHop: 2, Cost: 7},
	}
	if got := engine.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Snapshot() = %#v, want %#v", got, want)
	}
}

// TestSnapshotDirectPeerBeatsRelayPath pins the behaviour the F50 needs: a
// peer we hold a direct session with is reached directly, because a direct
// link is advertised with a hop cost of one while the relayed path costs two
// hops. Advertising the latency instead of the hop count used to make the
// relay look cheaper and kept the traffic away from the direct session.
func TestSnapshotDirectPeerBeatsRelayPath(t *testing.T) {
	engine := NewEngine(1)
	engine.AddLink(1, 20, 1)  // direct session, hop cost
	engine.AddLink(1, 10, 1)  // relay first hop
	engine.AddLink(10, 20, 1) // relay second hop

	routes := engine.Snapshot()
	want := Route{Destination: 20, NextHop: 20, Cost: 1}
	if got := routeTo(routes, 20); got != want {
		t.Fatalf("route to 20 = %#v, want %#v", got, want)
	}
}

// TestSnapshotRelayPathUsedWhenNoDirectLink covers the complementary case:
// without a direct link the peer is reached through the relay.
func TestSnapshotRelayPathUsedWhenNoDirectLink(t *testing.T) {
	engine := NewEngine(1)
	engine.AddLink(1, 10, 1)
	engine.AddLink(10, 20, 1)

	routes := engine.Snapshot()
	want := Route{Destination: 20, NextHop: 10, Cost: 2}
	if got := routeTo(routes, 20); got != want {
		t.Fatalf("route to 20 = %#v, want %#v", got, want)
	}
}

func TestSnapshotEqualCostUsesLowestFirstHop(t *testing.T) {
	engine := NewEngine(1)
	engine.AddLink(1, 9, 1)
	engine.AddLink(9, 4, 2)
	engine.AddLink(1, 3, 1)
	engine.AddLink(3, 4, 2)

	for range 20 {
		routes := engine.Snapshot()
		if got, want := routeTo(routes, 4), (Route{Destination: 4, NextHop: 3, Cost: 3}); got != want {
			t.Fatalf("route to 4 = %#v, want %#v", got, want)
		}
	}
}

func TestSnapshotOmitsDisconnectedPeers(t *testing.T) {
	engine := NewEngine(1)
	engine.AddLink(1, 2, 1)
	engine.AddLink(3, 4, 1)

	want := []Route{{Destination: 2, NextHop: 2, Cost: 1}}
	if got := engine.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Snapshot() = %#v, want %#v", got, want)
	}
}

func TestSnapshotReflectsLinkUpdatesAndRemoval(t *testing.T) {
	engine := NewEngine(1)
	engine.AddLink(1, 2, 8)
	engine.AddLink(2, 3, 1)
	engine.AddLink(1, 3, 20)

	engine.AddLink(1, 3, 4)
	if got, want := routeTo(engine.Snapshot(), 3), (Route{Destination: 3, NextHop: 3, Cost: 4}); got != want {
		t.Fatalf("updated route = %#v, want %#v", got, want)
	}

	engine.RemoveLink(1, 3)
	if got, want := routeTo(engine.Snapshot(), 3), (Route{Destination: 3, NextHop: 2, Cost: 9}); got != want {
		t.Fatalf("route after removal = %#v, want %#v", got, want)
	}
}

func routeTo(routes []Route, destination uint32) Route {
	for _, route := range routes {
		if route.Destination == destination {
			return route
		}
	}
	return Route{}
}

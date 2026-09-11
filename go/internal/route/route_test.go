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

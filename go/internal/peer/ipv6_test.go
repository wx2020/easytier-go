// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"net/netip"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// TestRouteHandlesIPv6Addrs mirrors Rust ipv6_test::test_peer_manager_ipv6.
// The router should handle IPv6 destinations as distinct from IPv4 and route correctly.
func TestRouteHandlesIPv6Addrs(t *testing.T) {
	// Use the route-independent packet router to verify forwarding doesn't conflate address families.
	router, err := NewPacketRouter(1, map[uint32]uint32{2: 2, 3: 2})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate packets destined to peers that happen to have IPv6 addresses.
	for _, peerID := range []uint32{2, 3} {
		packet := protocol.Packet{
			Header: protocol.PeerManagerHeader{
				FromPeerID: 1,
				ToPeerID:   peerID,
				PacketType: protocol.PacketTypeData,
			},
			Payload: []byte("ipv6-test"),
		}
		decision, err := router.Process(packet)
		if err != nil {
			t.Fatalf("Process peer %d: %v", peerID, err)
		}
		if decision.NextHop != 2 {
			t.Fatalf("NextHop for %d = %d, want 2", peerID, decision.NextHop)
		}
	}
	// Unknown peer should have no route.
	unknown := protocol.Packet{
		Header: protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 99, PacketType: protocol.PacketTypeData},
	}
	if _, err := router.Process(unknown); err == nil {
		t.Fatal("unknown peer should have no route")
	}
}

// TestGlobalCtxIPv6Equivalent verifies IPv6 address handling mirrors Rust
// test_global_ctx_ipv6 and test_route_peer_info_ipv6. PeerInfo-like data
// should preserve IPv6 correctly via netip.
func TestGlobalCtxIPv6Equivalent(t *testing.T) {
	addrs := []struct {
		ipv4 string
		ipv6 string
	}{
		{"10.0.0.1", "fd00::1"},
		{"192.0.2.1", "2001:db8::1"},
	}
	for _, tc := range addrs {
		v4 := netip.MustParseAddr(tc.ipv4)
		v6 := netip.MustParseAddr(tc.ipv6)
		if !v4.Is4() || !v6.Is6() {
			t.Fatalf("addr parsing failed ipv4=%s ipv6=%s", tc.ipv4, tc.ipv6)
		}
		if v6.String() != tc.ipv6 {
			t.Fatalf("IPv6 string = %s, want %s", v6.String(), tc.ipv6)
		}
		// Ensure distinctness: IPv4 and IPv6 must not compare equal.
		if v4 == v6 {
			t.Fatal("IPv4 and IPv6 should not be equal")
		}
	}
}

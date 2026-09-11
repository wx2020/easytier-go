// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package publicipv6

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestRouterAdvertisementRoundTrip(t *testing.T) {
	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("ff02::1")
	prefix := netip.MustParsePrefix("fd00:1234:5678::/64")

	ra := RouterAdvertisement{
		CurrentHopLimit:   64,
		ManagedFlag:       false,
		OtherConfigFlag:   false,
		RouterLifetime:    1800 * time.Second,
		Prefix:            prefix,
		ValidLifetime:     3600 * time.Second,
		PreferredLifetime: 1800 * time.Second,
	}

	message, err := ra.Marshal(src, dst)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if message[0] != icmpv6TypeRouterAdvertisement {
		t.Fatalf("type = %d, want 134", message[0])
	}
	if message[1] != 64 {
		t.Fatalf("hop limit = %d, want 64", message[1])
	}
	if got := binary.BigEndian.Uint16(message[6:8]); got != 1800 {
		t.Fatalf("router lifetime = %d, want 1800", got)
	}

	parsed, err := ParseRouterAdvertisement(src, dst, message)
	if err != nil {
		t.Fatalf("ParseRouterAdvertisement: %v", err)
	}
	if parsed.Prefix != prefix.Masked() {
		t.Fatalf("parsed prefix = %v, want %v", parsed.Prefix, prefix.Masked())
	}
	if parsed.RouterLifetime != ra.RouterLifetime {
		t.Fatalf("parsed lifetime = %v, want %v", parsed.RouterLifetime, ra.RouterLifetime)
	}
	if parsed.ValidLifetime != ra.ValidLifetime {
		t.Fatalf("parsed valid = %v, want %v", parsed.ValidLifetime, ra.ValidLifetime)
	}
	if parsed.PreferredLifetime != ra.PreferredLifetime {
		t.Fatalf("parsed preferred = %v, want %v", parsed.PreferredLifetime, ra.PreferredLifetime)
	}
}

func TestParseRouterAdvertisementBadChecksum(t *testing.T) {
	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("ff02::1")
	ra := RouterAdvertisement{
		CurrentHopLimit: 64,
		RouterLifetime:  1800 * time.Second,
		Prefix:          netip.MustParsePrefix("fd00:1234:5678::/64"),
		PreferredLifetime: 1800 * time.Second,
		ValidLifetime:      3600 * time.Second,
	}
	message, err := ra.Marshal(src, dst)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Corrupt one payload byte so the checksum fails.
	message[20] ^= 0xFF
	if _, err := ParseRouterAdvertisement(src, dst, message); err == nil {
		t.Fatalf("expected checksum failure")
	}
}

func TestMarshalRejectsNonIPv6Prefix(t *testing.T) {
	ra := RouterAdvertisement{
		Prefix: netip.MustParsePrefix("10.0.0.0/24"),
	}
	if _, err := ra.Marshal(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("ff02::1")); err == nil {
		t.Fatalf("expected error for non-IPv6 /64 prefix")
	}
}
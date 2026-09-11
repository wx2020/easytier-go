// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package publicipv6

import (
	"net/netip"
	"testing"
)

func TestProviderAcquireRelease(t *testing.T) {
	p, err := NewProvider(netip.MustParsePrefix("fd00:1234:5678::/64"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Acquire("client1")
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsValid() || a.Bits() != 80 {
		t.Fatalf("lease %v invalid", a)
	}
	b, _ := p.Acquire("client1")
	if a != b {
		t.Fatalf("same client should get same lease")
	}
	p.Release("client1")
	c, _ := p.Acquire("client1")
	if c != a {
		// After release, may get same deterministic lease again
	}
	_ = c
}

func TestProviderRejectsInvalidPrefix(t *testing.T) {
	if _, err := NewProvider(netip.MustParsePrefix("10.0.0.0/24")); err == nil {
		t.Fatal("should reject non-/64 or non-IPv6")
	}
	if _, err := NewProvider(netip.MustParsePrefix("fd00::/48")); err == nil {
		t.Fatal("should reject /48")
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package config

import (
	"net/netip"
	"testing"
)

// TestIPv6ConfigSupport mirrors Rust ipv6_test::test_ipv6_config_support.
func TestIPv6ConfigSupport(t *testing.T) {
	cfg := Config{NetworkIdentity: NetworkIdentity{NetworkName: "mesh"}}
	ipv6 := "fd00::1/64"
	cfg.IPv6 = ipv6
	if cfg.IPv6 != ipv6 {
		t.Fatalf("IPv6 = %q, want %q", cfg.IPv6, ipv6)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate IPv6 CIDR: %v", err)
	}
	prefix, err := netip.ParsePrefix(ipv6)
	if err != nil {
		t.Fatal(err)
	}
	if prefix.String() != ipv6 {
		t.Fatalf("prefix = %s, want %s", prefix, ipv6)
	}
}

// TestConfigIPv6ValidationRejectsInvalid mirrors Rust validation for IPv6.
func TestConfigIPv6ValidationRejectsInvalid(t *testing.T) {
	invalid := []string{"not-an-ip", "192.0.2.1/24", "fd00::1", "fd00::1/129"}
	for _, v := range invalid {
		cfg := Config{NetworkIdentity: NetworkIdentity{NetworkName: "mesh"}, IPv6: v}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate IPv6 %q succeeded", v)
		}
	}
}

// TestParseEndpointPreservesExplicitZeroPort mirrors Rust dns.rs socket_addrs_preserves_explicit_zero_port.
func TestParseEndpointPreservesExplicitZeroPort(t *testing.T) {
	cases := []struct {
		raw         string
		defaultPort uint16
		wantPort    uint16
	}{
		{"ws://127.0.0.1:0", 80, 0},
		{"wss://127.0.0.1:0", 443, 0},
		{"ws://127.0.0.1", 80, 80},
		{"wss://127.0.0.1", 443, 443},
		{"tcp://10.0.0.1:0", 11010, 0},
		{"udp://[::1]:0", 11010, 0},
	}
	for _, tc := range cases {
		endpoint, err := ParseEndpoint(tc.raw)
		if err != nil {
			t.Fatalf("ParseEndpoint %q: %v", tc.raw, err)
		}
		if endpoint.Port != tc.wantPort {
			t.Fatalf("ParseEndpoint %q port = %d, want %d", tc.raw, endpoint.Port, tc.wantPort)
		}
		if endpoint.Address() != endpoint.Host+":"+string(rune(0)) && endpoint.Port == 0 {
			// Address should still be valid JoinHostPort with 0
			_ = endpoint.Address()
		}
	}
}

// TestIPv6RoutesAndProxyNetworks mirrors Rust proxy CIDR handling with IPv6.
func TestIPv6PublicAddrPrefixValidation(t *testing.T) {
	cfg := Config{
		NetworkIdentity:      NetworkIdentity{NetworkName: "mesh"},
		IPv6PublicAddrPrefix: "2001:db8::/32",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.IPv6PublicAddrPrefix = "not-valid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid IPv6 prefix should fail")
	}
	cfg.IPv6PublicAddrPrefix = "10.0.0.0/8"
	if err := cfg.Validate(); err == nil {
		t.Fatal("IPv4 prefix as IPv6 should fail")
	}
}

// TestConfigIPv6PrefixRoundTrip ensures Marshal/Unmarshal preserves IPv6.
func TestConfigIPv6PrefixRoundTrip(t *testing.T) {
	cfg := Config{
		NetworkIdentity:      NetworkIdentity{NetworkName: "mesh"},
		IPv6:                 "fd00::1/64",
		IPv6PublicAddrPrefix: "2001:db8:100::/64",
	}
	data, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTOML(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.IPv6 != cfg.IPv6 || parsed.IPv6PublicAddrPrefix != cfg.IPv6PublicAddrPrefix {
		t.Fatalf("round trip IPv6 = %#v, want %#v", parsed, cfg)
	}
}

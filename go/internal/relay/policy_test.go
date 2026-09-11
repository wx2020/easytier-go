// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package relay

import (
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestIsNetworkInWhitelist(t *testing.T) {
	tests := []struct {
		whitelist string
		network   string
		want      bool
	}{
		{"*", "any", true},
		{"", "any", false},
		{"net1", "net1", true},
		{"net1", "net2", false},
		{"net1 net2*", "net2foo", true},
		{"reference-*", "reference-network", true},
		{"reference-*", "other", false},
		{"net1,net2", "net2", true},
		{"  net1   net2  ", "net1", true},
	}
	for _, tt := range tests {
		got := isNetworkInWhitelist(tt.network, tt.whitelist)
		if got != tt.want {
			t.Fatalf("whitelist %q network %q = %v want %v", tt.whitelist, tt.network, got, tt.want)
		}
	}
}

func TestPolicyShouldRelayBasic(t *testing.T) {
	cfg := Config{RelayNetworkWhitelist: "net1*", ForeignRelayBPSLimit: ^uint64(0)}
	p := NewPolicy(cfg)
	pkt := protocol.Packet{Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData}, Payload: []byte("hello")}
	if !p.ShouldRelay("net1-foo", pkt.Header.PacketType, len(pkt.Payload)) {
		t.Fatal("should relay net1-foo")
	}
	if p.ShouldRelay("net2", pkt.Header.PacketType, len(pkt.Payload)) {
		t.Fatal("should not relay net2")
	}
}

func TestPolicyRelayAllPeerRPCBypass(t *testing.T) {
	cfg := Config{RelayNetworkWhitelist: "net1", RelayAllPeerRPC: true, ForeignRelayBPSLimit: ^uint64(0)}
	p := NewPolicy(cfg)
	rpcPkt := protocol.Packet{Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeRPCRequest}, Payload: []byte("rpc")}
	if !p.ShouldRelay("other-net", rpcPkt.Header.PacketType, len(rpcPkt.Payload)) {
		t.Fatal("RPC should be relayed even when whitelist fails if relay_all_peer_rpc true")
	}
	// Without flag, RPC should respect whitelist
	cfg2 := Config{RelayNetworkWhitelist: "net1", RelayAllPeerRPC: false, ForeignRelayBPSLimit: ^uint64(0)}
	p2 := NewPolicy(cfg2)
	if p2.ShouldRelay("other-net", rpcPkt.Header.PacketType, len(rpcPkt.Payload)) {
		t.Fatal("RPC should not bypass whitelist when relay_all_peer_rpc false")
	}
}

func TestPolicyBandwidthLimit(t *testing.T) {
	// Mock clock
	start := time.Now()
	now := start
	clock := func() time.Time { return now }
	bm := NewBucketManagerWithClock(100, clock)
	// also need to set now for bucket creation
	bm.now = clock
	trusted := NewTrustedStore()
	p := NewPolicyWithBuckets(Config{RelayNetworkWhitelist: "*", ForeignRelayBPSLimit: 100}, bm, trusted)
	// First 100 bytes allowed
	if !p.ShouldRelay("net1", protocol.PacketTypeData, 60) {
		t.Fatal("first consume should succeed")
	}
	if !p.ShouldRelay("net1", protocol.PacketTypeData, 40) {
		t.Fatal("second consume within limit should succeed")
	}
	// Now bucket empty, next should fail
	if p.ShouldRelay("net1", protocol.PacketTypeData, 1) {
		t.Fatal("should be rate limited")
	}
	// Advance 1 second to refill 100
	now = now.Add(time.Second)
	if !p.ShouldRelay("net1", protocol.PacketTypeData, 100) {
		t.Fatal("after refill should allow")
	}
	// Oversized packet larger than capacity should always fail
	if p.ShouldRelay("net1", protocol.PacketTypeData, 200) {
		t.Fatal("oversized should fail")
	}
	// Control packets (RPC) bypass bandwidth
	rpc := protocol.Packet{Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeRPCRequest}, Payload: []byte("x")}
	if !p.ShouldRelay("net1", rpc.Header.PacketType, 1000) {
		t.Fatal("RPC should bypass bandwidth limit")
	}
}

func TestPolicyDisableRelayData(t *testing.T) {
	cfg := Config{RelayNetworkWhitelist: "*", DisableRelayData: true, ForeignRelayBPSLimit: ^uint64(0)}
	p := NewPolicy(cfg)
	data := protocol.Packet{Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData}, Payload: []byte("data")}
	if p.ShouldRelay("net1", data.Header.PacketType, len(data.Payload)) {
		t.Fatal("disable_relay_data should block data")
	}
	rpc := protocol.Packet{Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeRPCRequest}, Payload: []byte("rpc")}
	if !p.ShouldRelay("net1", rpc.Header.PacketType, len(rpc.Payload)) {
		t.Fatal("RPC should still be allowed when disable_relay_data")
	}
}

func TestMockTrustedKeys(t *testing.T) {
	cfg := Config{RelayNetworkWhitelist: "*", ForeignRelayBPSLimit: ^uint64(0)}
	p := NewPolicy(cfg)
	// Use mock pubkey
	var pubkey [32]byte
	for i := range pubkey {
		pubkey[i] = byte(i)
	}
	// Initially not trusted
	if p.IsPubkeyTrusted(pubkey[:], "net1") {
		t.Fatal("should not be trusted initially")
	}
	// Add trusted key
	p.Trusted().Add("net1", pubkey[:], TrustedKeyMetadata{Source: TrustedSourceCredential})
	if !p.IsPubkeyTrusted(pubkey[:], "net1") {
		t.Fatal("should be trusted after add")
	}
	if p.IsPubkeyTrusted(pubkey[:], "net2") {
		t.Fatal("should not be trusted for other network")
	}
	// Check source-specific
	src := TrustedSourceCredential
	if !p.Trusted().IsTrusted(pubkey[:], "net1", &src) {
		t.Fatal("source specific should match")
	}
	other := TrustedSourceNode
	if p.Trusted().IsTrusted(pubkey[:], "net1", &other) {
		t.Fatal("wrong source should not match")
	}
	// Expiry
	expiry := time.Now().Add(-time.Hour).Unix()
	p.Trusted().Add("net2", pubkey[:], TrustedKeyMetadata{Source: TrustedSourceNode, ExpiryUnix: &expiry})
	if p.IsPubkeyTrusted(pubkey[:], "net2") {
		t.Fatal("expired key should not be trusted")
	}
	// Remove
	p.Trusted().Remove("net1")
	if p.IsPubkeyTrusted(pubkey[:], "net1") {
		t.Fatal("removed key should not be trusted")
	}
}

// Mock policy for relay-all-peer-rpc case
type mockTransport struct {
	allowed bool
}

func TestPolicyCanAddForeignPeerWithMock(t *testing.T) {
	cfg := Config{RelayNetworkWhitelist: "allowed-*", RelayAllPeerRPC: false}
	p := NewPolicy(cfg)
	if !p.CanAddForeignPeer("allowed-net", protocol.PacketTypeData) {
		t.Fatal("allowed-net should be added")
	}
	if p.CanAddForeignPeer("blocked-net", protocol.PacketTypeData) {
		t.Fatal("blocked-net should be denied")
	}
	// RPC with relay_all true should bypass
	cfg2 := Config{RelayNetworkWhitelist: "allowed-*", RelayAllPeerRPC: true}
	p2 := NewPolicy(cfg2)
	if !p2.CanAddForeignPeer("blocked-net", protocol.PacketTypeRPCRequest) {
		t.Fatal("RPC with relay_all should be allowed despite whitelist")
	}
	if p2.CanAddForeignPeer("blocked-net", protocol.PacketTypeData) {
		t.Fatal("data still blocked even with relay_all")
	}
}

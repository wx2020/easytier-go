// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package relay

import (
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestForeignManagerIsolationNoLeak(t *testing.T) {
	policy := NewPolicy(Config{RelayNetworkWhitelist: "*", ForeignRelayBPSLimit: ^uint64(0)})
	mgr := NewForeignNetworkManager(1, policy)
	// Simulate shared node bridging two networks
	if err := mgr.AddPeer("net1", 2, protocol.PacketTypeData); err != nil {
		t.Fatal(err)
	}
	if err := mgr.AddPeer("net1", 3, protocol.PacketTypeData); err != nil {
		t.Fatal(err)
	}
	if err := mgr.AddPeer("net2", 4, protocol.PacketTypeData); err != nil {
		t.Fatal(err)
	}
	if err := mgr.AddPeer("net2", 5, protocol.PacketTypeData); err != nil {
		t.Fatal(err)
	}

	// Packet from net1 destined for peer in net1 should be allowed
	env1 := protocol.ForeignNetworkPacket{
		DestinationPeerID: 3,
		NetworkName:       "net1",
		NestedPacket:      protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 3, PacketType: protocol.PacketTypeData}, Payload: []byte("hi")},
	}
	should, _ := mgr.HandleEnvelope(env1)
	if !should {
		t.Fatal("same-network packet should be relayed")
	}

	// Packet from net1 destined for peer in net2 should be denied (leak)
	envLeak := protocol.ForeignNetworkPacket{
		DestinationPeerID: 4,
		NetworkName:       "net1",
		NestedPacket:      protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 4, PacketType: protocol.PacketTypeData}, Payload: []byte("leak")},
	}
	should, reason := mgr.HandleEnvelope(envLeak)
	if should {
		t.Fatalf("cross-network leak should be denied, reason %s", reason)
	}

	// Packet for unknown network should be denied
	envUnknown := protocol.ForeignNetworkPacket{
		DestinationPeerID: 99,
		NetworkName:       "unknown",
		NestedPacket:      protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 99, PacketType: protocol.PacketTypeData}, Payload: []byte("x")},
	}
	should, _ = mgr.HandleEnvelope(envUnknown)
	if should {
		t.Fatal("unknown network should be denied")
	}

	// Test envelope marshal/unmarshal round-trip preserves isolation
	raw, err := mgr.MarshalEnvelope("net1", protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 3, PacketType: protocol.PacketTypeData}, Payload: []byte("payload")})
	if err != nil {
		t.Fatal(err)
	}
	env, ok, err := mgr.UnmarshalEnvelope(raw)
	if err != nil || !ok {
		t.Fatalf("unmarshal should succeed: %v ok=%v", err, ok)
	}
	if env.NetworkName != "net1" || env.DestinationPeerID != 3 {
		t.Fatalf("envelope mismatch %#v", env)
	}
	// Leak envelope should fail unmarshal check
	rawLeak, _ := protocol.ForeignNetworkPacket{DestinationPeerID: 4, NetworkName: "net1", NestedPacket: protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 4, PacketType: protocol.PacketTypeData}, Payload: []byte("x")}}.Marshal()
	_, ok, err = mgr.UnmarshalEnvelope(rawLeak)
	if err == nil || ok {
		t.Fatal("leak envelope should be denied on unmarshal")
	}
}

func TestForeignManagerWhitelistEnforcement(t *testing.T) {
	policy := NewPolicy(Config{RelayNetworkWhitelist: "net1*", ForeignRelayBPSLimit: ^uint64(0)})
	mgr := NewForeignNetworkManager(10, policy)
	// net1 allowed
	if err := mgr.AddPeer("net1", 2, protocol.PacketTypeData); err != nil {
		t.Fatal("net1 should be allowed")
	}
	// net2 blocked
	if err := mgr.AddPeer("net2", 3, protocol.PacketTypeData); err == nil {
		t.Fatal("net2 should be blocked by whitelist")
	}
	// RPC with relay_all should bypass (need new manager)
	policy2 := NewPolicy(Config{RelayNetworkWhitelist: "net1*", RelayAllPeerRPC: true, ForeignRelayBPSLimit: ^uint64(0)})
	mgr2 := NewForeignNetworkManager(10, policy2)
	if err := mgr2.AddPeer("net2", 3, protocol.PacketTypeRPCRequest); err != nil {
		t.Fatalf("RPC with relay_all should be allowed: %v", err)
	}
	if err := mgr2.AddPeer("net2", 4, protocol.PacketTypeData); err == nil {
		t.Fatal("data still blocked even with relay_all")
	}
}

func TestForeignManagerBandwidthEnforced(t *testing.T) {
	// Use small bucket to test limit via policy
	policy := NewPolicy(Config{RelayNetworkWhitelist: "*", ForeignRelayBPSLimit: 10})
	mgr := NewForeignNetworkManager(1, policy)
	_ = mgr.AddPeer("net1", 2, protocol.PacketTypeData)
	_ = mgr.AddPeer("net1", 3, protocol.PacketTypeData)
	env := protocol.ForeignNetworkPacket{
		DestinationPeerID: 3,
		NetworkName:       "net1",
		NestedPacket:      protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 3, PacketType: protocol.PacketTypeData}, Payload: make([]byte, 6)},
	}
	// first 6 bytes ok (capacity 10)
	if ok, _ := mgr.HandleEnvelope(env); !ok {
		t.Fatal("first packet should pass")
	}
	// second 6 bytes -> 12 total >10 should be rate limited
	if ok, _ := mgr.HandleEnvelope(env); ok {
		t.Fatal("second packet should be rate limited")
	}
	// RPC should bypass even when bucket exhausted
	envRPC := protocol.ForeignNetworkPacket{
		DestinationPeerID: 3,
		NetworkName:       "net1",
		NestedPacket:      protocol.Packet{Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeRPCRequest}, Payload: make([]byte, 100)},
	}
	if ok, _ := mgr.HandleEnvelope(envRPC); !ok {
		t.Fatal("RPC should bypass bandwidth")
	}
}

func TestForeignManagerTrustedKeys(t *testing.T) {
	policy := NewPolicy(Config{RelayNetworkWhitelist: "*", ForeignRelayBPSLimit: ^uint64(0)})
	mgr := NewForeignNetworkManager(1, policy)
	var trusted [32]byte
	for i := range trusted {
		trusted[i] = byte(i + 1)
	}
	var untrusted [32]byte
	for i := range untrusted {
		untrusted[i] = byte(255 - i)
	}
	// Add trusted key for net1
	policy.Trusted().Add("net1", trusted[:], TrustedKeyMetadata{Source: TrustedSourceCredential})
	if err := mgr.AddPeerWithKey("net1", 2, trusted[:], protocol.PacketTypeData); err != nil {
		t.Fatalf("trusted peer should be allowed: %v", err)
	}
	if err := mgr.AddPeerWithKey("net1", 3, untrusted[:], protocol.PacketTypeData); err == nil {
		t.Fatal("untrusted peer should be denied when trusted list exists")
	}
	// net2 has no trusted list, any key allowed
	if err := mgr.AddPeerWithKey("net2", 4, untrusted[:], protocol.PacketTypeData); err != nil {
		t.Fatalf("net2 without trusted list should allow any: %v", err)
	}
}

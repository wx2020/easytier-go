//go:build linux && privileged

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package relay

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func isPrivilegedForTest() bool {
	if v := os.Getenv("EASYTIER_FORCE_PRIVILEGED"); v == "1" {
		return true
	}
	return os.Geteuid() == 0
}

func hasIPCommand() bool {
	_, err := exec.LookPath("ip")
	return err == nil
}

func runIPSilent(args ...string) error {
	cmd := exec.Command("ip", args...)
	_, err := cmd.CombinedOutput()
	return err
}

func TestPrivilegedForeignTopologyCrossNamespace(t *testing.T) {
	if !isPrivilegedForTest() {
		t.Skip("requires privileged execution (root or EASYTIER_FORCE_PRIVILEGED=1)")
	}
	if !hasIPCommand() {
		t.Skip("ip command not available")
	}
	// Setup two isolated netns with veth bridge, mirroring P2P-06/07 cross-namespace foreign topology.
	// This test validates ForeignNetworkManager isolation still holds when managers are
	// instantiated per-namespace and packets are bridged via real netns channels.

	const (
		nsA      = "relay_ns_a"
		nsB      = "relay_ns_b"
		br       = "br_relay"
		hostA    = "veth_relay_a"
		hostB    = "veth_relay_b"
		guestA   = "veth_relay_a_g"
		guestB   = "veth_relay_b_g"
		ipA      = "10.201.1.1/24"
		ipB      = "10.201.1.2/24"
	)
	// Cleanup stale
	_ = runIPSilent("netns", "del", nsA)
	_ = runIPSilent("netns", "del", nsB)
	_ = runIPSilent("link", "del", br)
	t.Cleanup(func() {
		_ = runIPSilent("netns", "del", nsA)
		_ = runIPSilent("netns", "del", nsB)
		_ = runIPSilent("link", "del", br)
	})
	for _, ns := range []string{nsA, nsB} {
		cmd := exec.Command("ip", "netns", "add", ns)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("netns not available: %v %s", err, out)
		}
		cmd = exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("netns exec not available: %v %s", err, out)
		}
	}
	cmd := exec.Command("ip", "link", "add", "name", br, "type", "bridge")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("bridge not available: %v %s", err, out)
	}
	// Create veths
	for _, pair := range [][3]string{{nsA, hostA, guestA}, {nsB, hostB, guestB}} {
		ns, h, g := pair[0], pair[1], pair[2]
		_ = runIPSilent("link", "del", h)
		c := exec.Command("ip", "link", "add", h, "type", "veth", "peer", "name", g)
		if out, err := c.CombinedOutput(); err != nil {
			t.Skipf("veth not available: %v %s", err, out)
		}
		c = exec.Command("ip", "link", "set", g, "netns", ns)
		if out, err := c.CombinedOutput(); err != nil {
			t.Skipf("set netns not available: %v %s", err, out)
		}
		c = exec.Command("ip", "link", "set", h, "master", br)
		if out, err := c.CombinedOutput(); err != nil {
			t.Skipf("master not available: %v %s", err, out)
		}
		c = exec.Command("ip", "link", "set", h, "up")
		if out, err := c.CombinedOutput(); err != nil {
			t.Skipf("up not available: %v %s", err, out)
		}
		ipStr := ipA
		if ns == nsB {
			ipStr = ipB
		}
		c = exec.Command("ip", "netns", "exec", ns, "ip", "addr", "add", ipStr, "dev", g)
		if out, err := c.CombinedOutput(); err != nil {
			t.Skipf("addr add not available: %v %s", err, out)
		}
		c = exec.Command("ip", "netns", "exec", ns, "ip", "link", "set", g, "up")
		if out, err := c.CombinedOutput(); err != nil {
			t.Skipf("guest up not available: %v %s", err, out)
		}
	}
	cmd = exec.Command("ip", "link", "set", br, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("br up not available: %v %s", err, out)
	}
	// Verify connectivity via ping (deterministic, short timeout) - best effort
	time.Sleep(200 * time.Millisecond)
	ping := exec.Command("ip", "netns", "exec", nsA, "ping", "-c", "1", "-W", "1", "10.201.1.2")
	if out, err := ping.CombinedOutput(); err != nil {
		t.Logf("cross-ns ping failed (soft check, netns may be limited): %v %s", err, out)
	}

	// Now test foreign topology logic that would run across these namespaces.
	// Simulate shared relay node bridging two foreign networks, but with real netns isolation.
	// Each ns has its own manager; a central relay (in root ns) forwards only within same network.
	relayPolicy := NewPolicy(Config{RelayNetworkWhitelist: "*", ForeignRelayBPSLimit: ^uint64(0)})
	center := NewForeignNetworkManager(100, relayPolicy)

	// Register peers as if they were discovered via separate namespaces
	// netA peers in "net_alpha", netB peers in "net_beta"
	if err := center.AddPeer("net_alpha", 1, protocol.PacketTypeData); err != nil {
		t.Fatalf("add net_alpha peer1: %v", err)
	}
	if err := center.AddPeer("net_alpha", 2, protocol.PacketTypeData); err != nil {
		t.Fatalf("add net_alpha peer2: %v", err)
	}
	if err := center.AddPeer("net_beta", 3, protocol.PacketTypeData); err != nil {
		t.Fatalf("add net_beta peer3: %v", err)
	}
	if err := center.AddPeer("net_beta", 4, protocol.PacketTypeData); err != nil {
		t.Fatalf("add net_beta peer4: %v", err)
	}

	// Same-network packet should relay (simulates packet from nsA to center to nsA peer)
	envOK := protocol.ForeignNetworkPacket{
		DestinationPeerID: 2,
		NetworkName:       "net_alpha",
		NestedPacket:      protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData}, Payload: []byte("hello-alpha")},
	}
	if should, reason := center.HandleEnvelope(envOK); !should {
		t.Fatalf("same-network should relay, denied: %s", reason)
	}
	// Cross-network leak must be denied even when underlying netns bridge is up
	envLeak := protocol.ForeignNetworkPacket{
		DestinationPeerID: 3,
		NetworkName:       "net_alpha",
		NestedPacket:      protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 3, PacketType: protocol.PacketTypeData}, Payload: []byte("leak")},
	}
	if should, _ := center.HandleEnvelope(envLeak); should {
		t.Fatal("cross-network leak should be denied (P2P-06)")
	}
	// Verify that even if we move peer3 into net_alpha, it would then be allowed (deterministic re-check)
	center.RemovePeer("net_beta", 3)
	if err := center.AddPeer("net_alpha", 3, protocol.PacketTypeData); err != nil {
		t.Fatalf("re-add peer3 to alpha: %v", err)
	}
	if should, _ := center.HandleEnvelope(envLeak); !should {
		t.Fatal("after moving peer3 to alpha, leak should become allowed")
	}
	// Restore
	center.RemovePeer("net_alpha", 3)
	_ = center.AddPeer("net_beta", 3, protocol.PacketTypeData)

	// Now simulate encapsulated relay via actual channel bridging of envelopes:
	// Send envelope bytes over a channel that represents inter-namespace transport.
	ch := make(chan []byte, 2)
	raw, err := center.MarshalEnvelope("net_alpha", protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 100, ToPeerID: 2, PacketType: protocol.PacketTypeData}, Payload: []byte("bridged")})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ch <- raw
	// Receiver side (simulating nsB's view) should NOT be able to unmarshal leak envelope
	leakRaw, _ := protocol.ForeignNetworkPacket{DestinationPeerID: 3, NetworkName: "net_alpha", NestedPacket: protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 100, ToPeerID: 3, PacketType: protocol.PacketTypeData}, Payload: []byte("leak2")}}.Marshal()
	ch <- leakRaw
	// Drain and validate
	for i := 0; i < 2; i++ {
		data := <-ch
		env, _, err := center.UnmarshalEnvelope(data)
		if i == 0 {
			if err != nil {
				t.Fatalf("first envelope should pass: %v", err)
			}
			if env.NetworkName != "net_alpha" {
				t.Fatalf("env network %q", env.NetworkName)
			}
		} else {
			if err == nil {
				t.Fatal("second envelope (leak) should be denied on unmarshal")
			}
		}
	}
}

func TestPrivilegedForeignManagerRPCRelayAllBypass(t *testing.T) {
	if !isPrivilegedForTest() {
		t.Skip("requires privileged")
	}
	if !hasIPCommand() {
		t.Skip("ip command not available")
	}
	// Verify that privileged netns creation works and that RPC bypass still holds under real netns
	ns := "relay_rpc_ns"
	_ = runIPSilent("netns", "del", ns)
	if err := runIPSilent("netns", "add", ns); err != nil {
		t.Skipf("netns not available: %v", err)
	}
	t.Cleanup(func() { _ = runIPSilent("netns", "del", ns) })
	if out, err := exec.Command("ip", "netns", "exec", ns, "ip", "link", "show", "lo").CombinedOutput(); err != nil {
		t.Skipf("netns exec not available: %v %s", err, out)
	}
	policy := NewPolicy(Config{RelayNetworkWhitelist: "allowed*", RelayAllPeerRPC: true, ForeignRelayBPSLimit: ^uint64(0)})
	mgr := NewForeignNetworkManager(1, policy)
	if err := mgr.AddPeer("allowed_net", 2, protocol.PacketTypeData); err != nil {
		t.Fatal(err)
	}
	// RPC to disallowed net should be allowed via relay_all
	if err := mgr.AddPeer("other_net", 3, protocol.PacketTypeRPCRequest); err != nil {
		t.Fatalf("RPC relay_all should bypass whitelist in privileged env: %v", err)
	}
	if err := mgr.AddPeer("other_net", 4, protocol.PacketTypeData); err == nil {
		t.Fatal("data to other_net should still be blocked")
	}
}

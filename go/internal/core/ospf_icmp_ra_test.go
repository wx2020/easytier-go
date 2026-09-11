// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package core

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/route"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"github.com/EasyTier/EasyTier/go/internal/tun"
)

func TestNodeOSPFInitWiresFlooderAndService(t *testing.T) {
	identity := testIdentity(22, "ospf-wiring", 0x77)
	node, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identity.PeerID, LegacyIdentity: identity},
		PacketHandler: func(_ context.Context, _ protocol.Packet) error {
			return nil
		},
		EnableOSPF: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for node.runtime.OSPF() == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if node.runtime.OSPF() == nil {
		t.Fatal("OSPF flooder was not initialized")
	}
	if node.runtime.PeerRPC() == nil {
		t.Fatal("peer RPC manager was not initialized for OSPF")
	}
	_ = node.Close()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

func TestTwoNodeOSPFConvergesOverMesh(t *testing.T) {
	identityA := testIdentity(22, "ospf-mesh", 0x88)
	identityB := testIdentity(11, "ospf-mesh", 0x88)
	nodeA, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identityA.PeerID, LegacyIdentity: identityA},
		PacketHandler: func(_ context.Context, _ protocol.Packet) error {
			return nil
		},
		EnableOSPF:   true,
		RouteRefresh: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identityB.PeerID, LegacyIdentity: identityB},
		PacketHandler: func(_ context.Context, _ protocol.Packet) error {
			return nil
		},
		EnableOSPF:   true,
		RouteRefresh: 200 * time.Millisecond,
		Peers:        []string{"tcp://" + nodeA.Address().String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveA := make(chan error, 1)
	go func() { serveA <- nodeA.Serve(ctx) }()
	serveB := make(chan error, 1)
	go func() { serveB <- nodeB.Serve(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		routes := nodeA.runtime.manager.Router.Routes()
		if routes[11] == 11 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("OSPF did not converge, routes = %v", routes)
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = nodeA.Close()
	_ = nodeB.Close()
	if err := <-serveA; err != nil {
		t.Fatal(err)
	}
	if err := <-serveB; err != nil {
		t.Fatal(err)
	}
}

func TestNodeICMPProxyConsumesEchoInPipeline(t *testing.T) {
	identity := testIdentity(22, "icmp-wiring", 0x99)
	delivered := make(chan protocol.Packet, 4)
	node, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identity.PeerID, LegacyIdentity: identity},
		PacketHandler: func(_ context.Context, packet protocol.Packet) error {
			delivered <- packet
			return nil
		},
		NoTUN:           true,
		EnableICMPProxy: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()

	client, err := peer.NewPeerConnectionManager(peer.PeerConnectionManagerConfig{
		LocalPeerID: 11, LegacyIdentity: testIdentity(11, "icmp-wiring", 0x99),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	channel, err := transport.DialTCP(context.Background(), node.Address().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	connected := make(chan error, 1)
	go func() { connected <- client.Connect(context.Background(), channel) }()
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	// ICMP echo request to a foreign address: the proxy NATs it (raw send
	// fails silently without privileges but the packet is still consumed).
	echo := buildIPv4Packet(t, "10.144.144.1", "10.144.144.2", 1, []byte{8, 0, 0, 0, 0, 1, 0, 1})
	if err := client.Send(context.Background(), identity.PeerID, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: echo,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-delivered:
		t.Fatalf("ICMP echo must be consumed by the proxy, got %v bytes", len(packet.Payload))
	case <-time.After(500 * time.Millisecond):
	}
	_ = node.Close()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

func TestNodeRAAnnouncerCachesAdvertisement(t *testing.T) {
	identity := testIdentity(22, "ra-wiring", 0xaa)
	tunDevice, _, err := tun.NewMemoryDevicePair(4)
	if err != nil {
		t.Fatal(err)
	}
	node, err := ListenWithOptions(NodeOptions{
		Address:            "127.0.0.1:0",
		PeerManager:        peer.PeerConnectionManagerConfig{LocalPeerID: identity.PeerID, LegacyIdentity: identity},
		TUN:                tunDevice,
		TUNMTU:             1500,
		IPv6:               "fd00:1234::1/64",
		RAAnnounceInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for len(node.runtime.LastRA()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	frame := node.runtime.LastRA()
	if len(frame) < 40+16 {
		t.Fatalf("RA frame too short: %d", len(frame))
	}
	if frame[0]>>4 != 6 || frame[6] != 58 || frame[7] != 255 {
		t.Fatalf("RA frame header invalid: %x", frame[:8])
	}
	if frame[40] != 134 {
		t.Fatalf("RA ICMPv6 type = %d, want 134", frame[40])
	}
	_ = node.Close()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

func TestNodeOSPFDisabledByDefault(t *testing.T) {
	identity := testIdentity(22, "ospf-off", 0xbb)
	node, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identity.PeerID, LegacyIdentity: identity},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()
	time.Sleep(200 * time.Millisecond)
	if node.runtime.OSPF() != nil {
		t.Fatal("OSPF flooder must not start unless enabled")
	}
	_ = node.Close()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

var _ = route.MethodOSPFAnnounce

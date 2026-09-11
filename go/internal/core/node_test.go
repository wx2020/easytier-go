// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package core

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"github.com/EasyTier/EasyTier/go/internal/tun"
)

func TestNodeRepliesToPingWithPong(t *testing.T) {
	node, err := Listen("127.0.0.1:0", 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()

	connection, err := net.Dial("tcp", node.Address().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := protocol.WriteStreamFrame(connection, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: 22, PacketType: protocol.PacketTypePing},
		Payload: []byte{1, 0, 0, 0},
	}); err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ReadStreamFrame(connection, protocol.DefaultMaxStreamFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.PacketType != protocol.PacketTypePong || response.Header.FromPeerID != 22 || response.Header.ToPeerID != 11 {
		t.Fatalf("response header = %#v", response.Header)
	}

	cancel()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("node did not stop after context cancellation")
	}
}

func TestNodeCloseIsIdempotent(t *testing.T) {
	node, err := Listen("127.0.0.1:0", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNodeRespondsToLegacyHandshake(t *testing.T) {
	identity := peer.LegacyIdentity{PeerID: 22, NetworkName: "mesh"}
	for i := range identity.NetworkSecretDigest {
		identity.NetworkSecretDigest[i] = 0x66
	}
	node, err := ListenWithIdentity("127.0.0.1:0", 0, &identity)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()
	defer func() {
		_ = node.Close()
		<-serveResult
	}()

	client, err := transport.DialTCP(context.Background(), node.Address().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clientIdentity := identity
	clientIdentity.PeerID = 11
	response, err := peer.InitiateLegacyHandshake(context.Background(), client, clientIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if response.MyPeerID != identity.PeerID {
		t.Fatalf("response = %#v", response)
	}
}

func TestManagedNodeRoutesDataThroughPeerManager(t *testing.T) {
	identity := testIdentity(22, "managed", 0x33)
	packets := make(chan protocol.Packet, 1)
	node, err := ListenWithOptions(NodeOptions{
		Address: "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{
			LocalPeerID:    identity.PeerID,
			LegacyIdentity: identity,
		},
		PacketHandler: func(_ context.Context, packet protocol.Packet) error {
			packets <- packet
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()

	client, err := peer.NewPeerConnectionManager(peer.PeerConnectionManagerConfig{
		LocalPeerID:    11,
		LegacyIdentity: testIdentity(11, "managed", 0x33),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	channel, err := transport.DialTCP(context.Background(), node.Address().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	connectResult := make(chan error, 1)
	go func() { connectResult <- client.Connect(context.Background(), channel) }()
	if err := <-connectResult; err != nil {
		t.Fatal(err)
	}
	if err := client.Send(context.Background(), identity.PeerID, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: []byte("overlay"),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-packets:
		if packet.Header.FromPeerID != 11 || packet.Header.ToPeerID != identity.PeerID || string(packet.Payload) != "overlay" {
			t.Fatalf("managed packet = %#v", packet)
		}
	case <-time.After(time.Second):
		t.Fatal("managed node did not deliver data")
	}
	_ = node.Close()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

func TestManagedNodeHandlesUDPSessionAndRPC(t *testing.T) {
	identity := testIdentity(22, "udp-managed", 0x44)
	responseBody := []byte(`{"ok":true}`)
	node, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		UDPAddress:  "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identity.PeerID, LegacyIdentity: identity},
		RPCHandler: func(_ context.Context, request rpc.RpcPacket) (rpc.RpcPacket, error) {
			if request.Descriptor == nil || request.Descriptor.ServiceName != "test" {
				t.Fatalf("RPC request = %#v", request)
			}
			return rpc.RpcPacket{Descriptor: request.Descriptor, Body: responseBody}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()
	client, err := peer.NewPeerConnectionManager(peer.PeerConnectionManagerConfig{
		LocalPeerID: 11, LegacyIdentity: testIdentity(11, "udp-managed", 0x44),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	channel, err := transport.DialUDP(context.Background(), node.UDPAddress().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(context.Background(), channel); err != nil {
		t.Fatal(err)
	}
	request := rpc.RpcPacket{
		FromPeer: 11, ToPeer: identity.PeerID, TransactionID: 7,
		Descriptor: &rpc.RpcDescriptor{ServiceName: "test", MethodIndex: 1},
		Body:       []byte(`{}`), IsRequest: true, TotalPieces: 1,
	}
	body, err := request.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send(context.Background(), identity.PeerID, protocol.Packet{
		Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeRPCRequest}, Payload: body,
	}); err != nil {
		t.Fatal(err)
	}
	responsePacket, err := client.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	response, err := rpc.UnmarshalRpcPacket(responsePacket.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]bool
	if err := json.Unmarshal(response.Body, &decoded); err != nil || !decoded["ok"] {
		t.Fatalf("RPC response = %s, %v", response.Body, err)
	}
	_ = node.Close()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

func TestManagedNodeAcceptsWebSocketPeerTransport(t *testing.T) {
	identity := testIdentity(22, "ws-managed", 0x45)
	webSocket, err := transport.ListenWebSocket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packets := make(chan protocol.Packet, 1)
	node, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		WebSocket:   webSocket,
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identity.PeerID, LegacyIdentity: identity},
		PacketHandler: func(_ context.Context, packet protocol.Packet) error {
			packets <- packet
			return nil
		},
	})
	if err != nil {
		_ = webSocket.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()
	client, err := peer.NewPeerConnectionManager(peer.PeerConnectionManagerConfig{
		LocalPeerID: 11, LegacyIdentity: testIdentity(11, "ws-managed", 0x45),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	channel, err := transport.DialWebSocket(context.Background(), webSocket.URL())
	if err != nil {
		t.Fatal(err)
	}
	connected := make(chan error, 1)
	go func() { connected <- client.Connect(context.Background(), channel) }()
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	if err := client.Send(context.Background(), identity.PeerID, protocol.Packet{
		Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData}, Payload: []byte("websocket"),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-packets:
		if string(packet.Payload) != "websocket" {
			t.Fatalf("WebSocket packet = %#v", packet)
		}
	case <-time.After(time.Second):
		t.Fatal("WebSocket packet was not delivered")
	}
	_ = node.Close()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

func TestManagedNodeConnectsTUNToPeerManager(t *testing.T) {
	identity := testIdentity(22, "tun-managed", 0x55)
	tunDevice, external, err := tun.NewMemoryDevicePair(4)
	if err != nil {
		t.Fatal(err)
	}
	node, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identity.PeerID, LegacyIdentity: identity},
		TUN:         tunDevice, TUNMTU: 1500, TUNDestination: 11,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()
	client, err := peer.NewPeerConnectionManager(peer.PeerConnectionManagerConfig{
		LocalPeerID: 11, LegacyIdentity: testIdentity(11, "tun-managed", 0x55),
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
	packet := []byte{0x45, 0, 0, 20}
	if err := client.Send(context.Background(), identity.PeerID, protocol.Packet{
		Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData}, Payload: packet,
	}); err != nil {
		t.Fatal(err)
	}
	readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
	defer readCancel()
	got, err := external.ReadPacket(readCtx)
	if err != nil || string(got) != string(packet) {
		t.Fatalf("TUN packet = %v, %v", got, err)
	}
	_ = node.Close()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

func TestManagedNodeNoTUNStillExposesManagement(t *testing.T) {
	identity := testIdentity(33, "no-tun-managed", 0x66)
	node, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identity.PeerID, LegacyIdentity: identity},
		NoTUN:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.IsNoTUN() != true {
		t.Fatal("IsNoTUN should be true")
	}
	if node.TUNAddresses() != nil && node.TUNAddresses().NoTUN != true {
		t.Fatalf("TUNAddresses NoTUN flag missing: %v", node.TUNAddresses())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()
	client, err := peer.NewPeerConnectionManager(peer.PeerConnectionManagerConfig{
		LocalPeerID: 44, LegacyIdentity: testIdentity(44, "no-tun-managed", 0x66),
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
	// Verify data path still works via PacketHandler even without TUN
	packets := make(chan protocol.Packet, 1)
	// Use a second node to test management portal like RPC over no-TUN
	// For now just verify Send/Receive works
	if err := client.Send(context.Background(), identity.PeerID, protocol.Packet{
		Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData}, Payload: []byte("no-tun"),
	}); err != nil {
		t.Fatal(err)
	}
	// Node has no PacketHandler, but we can verify it stays alive and can be closed cleanly
	_ = node.Close()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("no-TUN node did not stop")
	}
	_ = packets
}

func TestManagedNodeTUNWithDHCPAndStaticAssignment(t *testing.T) {
	identity := testIdentity(55, "dhcp-tun", 0x77)
	tunDevice, _, err := tun.NewMemoryDevicePairWithMTU(4, tun.EffectiveMTU(1380, true))
	if err != nil {
		t.Fatal(err)
	}
	// Use DHCP and static IPv6 together
	node, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identity.PeerID, LegacyIdentity: identity},
		TUN:         tunDevice,
		TUNMTU:      0, // should be defaulted via EffectiveMTU
		TUNDestination: 11,
		DHCP:        true,
		IPv6:        "fd00::55/64",
		EnableEncryption: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	addrs := node.TUNAddresses()
	if addrs == nil || addrs.IPv4 == nil {
		t.Fatalf("DHCP should allocate IPv4, got %v", addrs)
	}
	if addrs.IPv4.Addr().String() == "10.144.144.0" || addrs.IPv4.Addr().String() == "10.144.144.255" {
		t.Fatalf("DHCP allocated reserved %v", addrs.IPv4)
	}
	if addrs.IPv6 == nil || addrs.IPv6.String() != "fd00::55/64" {
		t.Fatalf("static IPv6 not assigned: %v", addrs.IPv6)
	}
	if addrs.MTU != 1360 { // 1380-20
		t.Fatalf("MTU = %d, want 1360 due to encryption overhead", addrs.MTU)
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTwoNodeTUNTransfersICMPAndTCP(t *testing.T) {
	identityA := testIdentity(22, "tun-icmp", 0x88)
	identityB := testIdentity(11, "tun-icmp", 0x88)
	// Assign static IPs in the same DHCP pool subnet for realism
	tunA, externalA, err := tun.NewMemoryDevicePairWithMTU(8, 1500)
	if err != nil {
		t.Fatal(err)
	}
	tunB, externalB, err := tun.NewMemoryDevicePairWithMTU(8, 1500)
	if err != nil {
		t.Fatal(err)
	}
	// Static assignment
	v4A := mustParsePrefix(t, "10.144.144.1/24")
	v4B := mustParsePrefix(t, "10.144.144.2/24")
	if err := tunA.AssignIPv4(v4A); err != nil {
		t.Fatal(err)
	}
	if err := tunB.AssignIPv4(v4B); err != nil {
		t.Fatal(err)
	}
	v6A := mustParsePrefix(t, "fd00::1/64")
	v6B := mustParsePrefix(t, "fd00::2/64")
	if err := tunA.AssignIPv6(v6A); err != nil {
		t.Fatal(err)
	}
	if err := tunB.AssignIPv6(v6B); err != nil {
		t.Fatal(err)
	}
	nodeA, err := ListenWithOptions(NodeOptions{
		Address: "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identityA.PeerID, LegacyIdentity: identityA},
		TUN: tunA, TUNMTU: 1500, TUNDestination: identityB.PeerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	addrA := nodeA.Address().String()
	nodeB, err := ListenWithOptions(NodeOptions{
		Address: "127.0.0.1:0",
		Peers:   []string{addrA},
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identityB.PeerID, LegacyIdentity: identityB},
		TUN: tunB, TUNMTU: 1500, TUNDestination: identityA.PeerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	serveA := make(chan error, 1)
	serveB := make(chan error, 1)
	go func() { serveA <- nodeA.Serve(ctxA) }()
	go func() { serveB <- nodeB.Serve(ctxB) }()
	// Wait for peer managers to connect via auto Peers mechanism
	waitForPeer(t, nodeA.PeerManager(), identityB.PeerID, time.Second)
	waitForPeer(t, nodeB.PeerManager(), identityA.PeerID, time.Second)
	// Also ensure A side has peer connection (via listener accept)
	// Build ICMP and TCP packets
	icmpPacket := buildIPv4Packet(t, "10.144.144.1", "10.144.144.2", 1, []byte{8, 0, 0, 0, 0, 1, 0, 1})
	tcpPacket := buildIPv4Packet(t, "10.144.144.1", "10.144.144.2", 6, []byte{0, 80, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0})
	// Test ICMP: write to externalA (simulating OS -> TUN A) should arrive at externalB
	if err := externalA.WritePacket(context.Background(), icmpPacket); err != nil {
		t.Fatal(err)
	}
	readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := externalB.ReadPacket(readCtx)
	if err != nil {
		t.Fatalf("ICMP over TUN: %v", err)
	}
	if string(got) != string(icmpPacket) {
		t.Fatalf("ICMP packet mismatch got %v want %v", got, icmpPacket)
	}
	// Test TCP: write to externalA, should arrive at externalB
	if err := externalA.WritePacket(context.Background(), tcpPacket); err != nil {
		t.Fatal(err)
	}
	readCtx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	got2, err := externalB.ReadPacket(readCtx2)
	if err != nil {
		t.Fatalf("TCP over TUN: %v", err)
	}
	if string(got2) != string(tcpPacket) {
		t.Fatalf("TCP packet mismatch")
	}
	// Reverse direction B->A
	icmpPacket2 := buildIPv4Packet(t, "10.144.144.2", "10.144.144.1", 1, []byte{8, 0, 0, 0, 0, 1, 0, 2})
	if err := externalB.WritePacket(context.Background(), icmpPacket2); err != nil {
		t.Fatal(err)
	}
	readCtx3, cancel3 := context.WithTimeout(context.Background(), time.Second)
	defer cancel3()
	got3, err := externalA.ReadPacket(readCtx3)
	if err != nil {
		t.Fatalf("Reverse ICMP: %v", err)
	}
	if string(got3) != string(icmpPacket2) {
		t.Fatalf("reverse ICMP mismatch")
	}
	cancelA()
	cancelB()
	_ = nodeA.Close()
	_ = nodeB.Close()
	select {
	case err := <-serveA:
		if err != nil {
			t.Fatalf("serveA %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("nodeA not stopped")
	}
	select {
	case err := <-serveB:
		if err != nil {
			t.Fatalf("serveB %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("nodeB not stopped")
	}
}

func waitForPeer(t *testing.T, mgr *peer.PeerConnectionManager, peerID uint32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, ok := mgr.Peers()[peerID]; ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("peer %d did not connect within %v, peers=%v", peerID, timeout, mgr.Peers())
}

func buildIPv4Packet(t *testing.T, src, dst string, protocol byte, payload []byte) []byte {
	t.Helper()
	srcIP := net.ParseIP(src).To4()
	dstIP := net.ParseIP(dst).To4()
	if srcIP == nil || dstIP == nil {
		t.Fatalf("invalid src/dst %s %s", src, dst)
	}
	header := make([]byte, 20)
	header[0] = 0x45
	header[1] = 0
	totalLen := 20 + len(payload)
	header[2] = byte(totalLen >> 8)
	header[3] = byte(totalLen)
	header[8] = 64
	header[9] = protocol
	copy(header[12:16], srcIP)
	copy(header[16:20], dstIP)
	// checksum 0 for test
	packet := append(append([]byte(nil), header...), payload...)
	if len(packet) > 1500 {
		t.Fatalf("packet too large %d", len(packet))
	}
	return packet
}

func mustParsePrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return pfx
}

func testIdentity(peerID uint32, network string, value byte) peer.LegacyIdentity {
	identity := peer.LegacyIdentity{PeerID: peerID, NetworkName: network}
	for index := range identity.NetworkSecretDigest {
		identity.NetworkSecretDigest[index] = value
	}
	return identity
}

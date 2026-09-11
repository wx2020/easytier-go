// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package vpnportal

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/transport/wgtest"
)

func testStockPortal(t *testing.T) *Portal {
	t.Helper()
	portal, err := NewPortal(config.VPNPortalConfig{
		ClientCIDR:      "10.144.144.0/24",
		WireGuardListen: "127.0.0.1:0",
	}, config.NetworkIdentity{NetworkName: "stock-net", NetworkSecret: "stock-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return portal
}

func buildIPv4Packet(src, dst [4]byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	copy(packet[20:], payload)
	return packet
}

func TestPortalStockHandshakeAndForward(t *testing.T) {
	portal := testStockPortal(t)
	var forwarded [][]byte
	var mu sync.Mutex
	portal.SetMeshForwarder(func(_ context.Context, ipPacket []byte) error {
		mu.Lock()
		forwarded = append(forwarded, append([]byte(nil), ipPacket...))
		mu.Unlock()
		return nil
	})
	if !portal.StockEnabled() {
		t.Fatal("stock handling must arm with a forwarder")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := portal.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer portal.Close()

	initiator, err := wgtest.New(portal.wgConfig.ClientPrivate, portal.wgConfig.ServerPublic)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", portal.ListenAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	init, err := initiator.BuildInit()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(init); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2048)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("handshake response: %v", err)
	}
	if n != 92 {
		t.Fatalf("response size = %d, want 92", n)
	}
	if err := initiator.OpenResponse(resp[:n]); err != nil {
		t.Fatalf("open response: %v", err)
	}

	// Client -> mesh: inner IP packet is decapsulated and forwarded.
	inner := buildIPv4Packet([4]byte{10, 144, 144, 5}, [4]byte{10, 144, 144, 1}, []byte("client-data"))
	if _, err := conn.Write(initiator.Seal(inner)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		got := len(forwarded) > 0
		mu.Unlock()
		if got || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(forwarded) == 0 {
		t.Fatal("decapsulated packet was not forwarded to the mesh")
	}
	if string(forwarded[0][20:]) != "client-data" {
		t.Fatalf("forwarded payload = %q", forwarded[0][20:])
	}

	// Mesh -> client: return path via learned client IP.
	back := buildIPv4Packet([4]byte{10, 144, 144, 1}, [4]byte{10, 144, 144, 5}, []byte("mesh-reply"))
	handled, err := portal.DeliverToClient(ctx, back)
	if err != nil || !handled {
		t.Fatalf("deliver = %v, %v; want true, nil", handled, err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	n, err = conn.Read(resp)
	if err != nil {
		t.Fatalf("client data: %v", err)
	}
	opened, err := initiator.Open(resp[:n])
	if err != nil {
		t.Fatalf("client open: %v", err)
	}
	if string(opened[20:]) != "mesh-reply" {
		t.Fatalf("reply payload = %q", opened[20:])
	}
}

func TestPortalStockRejectsWrongKey(t *testing.T) {
	portal := testStockPortal(t)
	portal.SetMeshForwarder(func(_ context.Context, _ []byte) error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := portal.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer portal.Close()

	var wrongPriv [32]byte
	for i := range wrongPriv {
		wrongPriv[i] = byte(i + 1)
	}
	stranger, err := wgtest.New(wrongPriv, portal.wgConfig.ServerPublic)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", portal.ListenAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	init, err := stranger.BuildInit()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(init); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 2048)); err == nil {
		t.Fatal("wrong-key initiation must get no response")
	}
	time.Sleep(300 * time.Millisecond)
	if portal.ClientCount() != 0 {
		t.Fatalf("stranger tracked: %d", portal.ClientCount())
	}
}

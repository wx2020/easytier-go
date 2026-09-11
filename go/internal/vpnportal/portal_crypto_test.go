// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package vpnportal

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

func testPortalWithNativeCrypto(t *testing.T) *Portal {
	t.Helper()
	portal, err := NewPortal(config.VPNPortalConfig{
		ClientCIDR:      "10.144.144.0/24",
		WireGuardListen: "127.0.0.1:0",
	}, config.NetworkIdentity{NetworkName: "portal-net", NetworkSecret: "portal-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := portal.EnableNativeCrypto(); err != nil {
		t.Fatal(err)
	}
	if !portal.NativeCryptoEnabled() {
		t.Fatal("native crypto must be armed")
	}
	return portal
}

func TestPortalNativeClientRegisters(t *testing.T) {
	portal := testPortalWithNativeCrypto(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := portal.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer portal.Close()

	clientCfg, err := transport.NewWgCryptoConfigForPortal("portal-net", "portal-secret", false)
	if err != nil {
		t.Fatal(err)
	}
	client, err := transport.NewWgCryptoState(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", portal.ListenAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sealed, err := client.SealSequenced(1, []byte("register"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(sealed); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for portal.ClientCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if portal.ClientCount() != 1 {
		t.Fatalf("native client was not tracked, count = %d", portal.ClientCount())
	}
	// The sealed ack must be readable by the client key.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	ack := make([]byte, 2048)
	n, err := conn.Read(ack)
	if err != nil {
		t.Fatalf("portal ack: %v", err)
	}
	opened, err := client.Open(ack[:n])
	if err != nil {
		t.Fatalf("portal ack does not authenticate: %v", err)
	}
	if string(opened) != "portal-ack" {
		t.Fatalf("ack body = %q", opened)
	}
}

func TestPortalNativeIgnoresStrangers(t *testing.T) {
	portal := testPortalWithNativeCrypto(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := portal.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer portal.Close()

	conn, err := net.Dial("udp", portal.ListenAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Wrong secret: authentication fails, no state retained.
	wrongCfg, err := transport.NewWgCryptoConfigForPortal("portal-net", "wrong", false)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := transport.NewWgCryptoState(wrongCfg)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := stranger.SealSequenced(1, []byte("intrude"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(sealed); err != nil {
		t.Fatal(err)
	}
	// Plain garbage is ignored as well.
	if _, err := conn.Write([]byte("not-a-wg-datagram")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if portal.ClientCount() != 0 {
		t.Fatalf("strangers must leave no state, count = %d", portal.ClientCount())
	}
}

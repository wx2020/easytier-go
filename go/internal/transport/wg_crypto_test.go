// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"bytes"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func testWGCryptoPair(t *testing.T) (*WgCryptoState, *WgCryptoState) {
	t.Helper()
	cfgA, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	cfgB, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewWgCryptoState(cfgA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewWgCryptoState(cfgB)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestWGCryptoRoundTrip(t *testing.T) {
	a, b := testWGCryptoPair(t)
	sealed, err := a.SealSequenced(1, []byte("hello-wg"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := b.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, []byte("hello-wg")) {
		t.Fatalf("round trip = %q", opened)
	}
}

func TestWGCryptoWrongNetworkSecretFails(t *testing.T) {
	a, _ := testWGCryptoPair(t)
	cfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "wrong")
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := NewWgCryptoState(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.SealSequenced(7, []byte("secret-data"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.Open(sealed); err == nil {
		t.Fatal("open with wrong network secret must fail")
	}
}

func TestWGCryptoReplayRejected(t *testing.T) {
	a, b := testWGCryptoPair(t)
	sealed, err := a.SealSequenced(42, []byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("replayed datagram must be rejected")
	}
}

func TestWGCryptoTamperRejected(t *testing.T) {
	a, b := testWGCryptoPair(t)
	sealed, err := a.SealSequenced(9, []byte("integrity"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("tampered datagram must fail authentication")
	}
}

func TestWGCryptoPortalModesInterop(t *testing.T) {
	serverCfg, err := NewWgCryptoConfigForPortal("mesh", "secret", true)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := NewWgCryptoConfigForPortal("mesh", "secret", false)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewWgCryptoState(serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewWgCryptoState(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := client.SealSequenced(3, []byte("portal-hello"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := server.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != "portal-hello" {
		t.Fatalf("portal round trip = %q", opened)
	}
}

func TestWGCryptoSealPeerPacket(t *testing.T) {
	a, b := testWGCryptoPair(t)
	packet := protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData},
		Payload: []byte("peer-payload"),
	}
	sealed, err := a.SealPeerPacket(11, packet)
	if err != nil {
		t.Fatal(err)
	}
	body, err := b.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := protocol.ParseBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered.Payload) != "peer-payload" {
		t.Fatalf("peer payload = %q", recovered.Payload)
	}
}

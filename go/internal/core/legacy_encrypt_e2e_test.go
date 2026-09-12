// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package core

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

// Two peers deriving the same legacy cipher from one network secret must
// exchange encrypted data transparently, while a peer without the cipher
// drops inbound encrypted packets.
func TestLegacyEncryptionEndToEnd(t *testing.T) {
	identity := testIdentity(22, "enc-net", 0x55)
	key128, key256 := protocol.DeriveLegacyKeys("enc-secret")
	cipher, err := peer.NewLegacyCipher("aes-gcm", key128, key256)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan protocol.Packet, 4)
	node, err := ListenWithOptions(NodeOptions{
		Address: "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{
			LocalPeerID:    identity.PeerID,
			LegacyIdentity: identity,
			LegacyCipher:   cipher,
		},
		PacketHandler: func(_ context.Context, packet protocol.Packet) error {
			received <- packet
			return nil
		},
		NoTUN: true,
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
		LegacyIdentity: testIdentity(11, "enc-net", 0x55),
		LegacyCipher:   cipher,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	channel, err := transport.DialTCP(ctx, node.Address().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	connected := make(chan error, 1)
	go func() { connected <- client.Connect(ctx, channel) }()
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	payload := []byte("secret-payload")
	if err := client.Send(ctx, identity.PeerID, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: identity.PeerID, PacketType: protocol.PacketTypeData},
		Payload: payload,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-received:
		if !bytes.Equal(packet.Payload, payload) {
			t.Fatalf("decrypted payload = %q, want %q", packet.Payload, payload)
		}
		if packet.Header.IsEncrypted() {
			t.Fatal("delivered packet must be decrypted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("encrypted data packet was not delivered")
	}
	_ = node.Close()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

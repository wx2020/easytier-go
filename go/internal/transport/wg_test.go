// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/peer"
)

func TestWGSyntheticHeaderInterop(t *testing.T) {
	// Verify Rust-compatible header bytes for various payload lengths.
	for _, n := range []int{0, 5, 100, 1380} {
		h := protocol.MarshalWGTunnelHeader(n)
		if h[0] != 0x45 || h[8] != 64 {
			t.Fatalf("WG header invalid for %d: %x", n, h)
		}
		if got, err := protocol.ParseWGTunnelHeader(h); err != nil || got != n {
			t.Fatalf("WG header round-trip %d => %d err %v", n, got, err)
		}
	}
}

func TestWGPingPongWithDigestDerivedKeys(t *testing.T) {
	// Derive WG private keys via Rust-compatible digest and verify that
	// two peers with same network identity can exchange data, while
	// mismatched digest would cause handshake failure (simulated via legacy handshake).
	privA := protocol.DeriveWGPrivateKey("mesh", "secret")
	privB := protocol.DeriveWGPrivateKey("mesh", "secret")
	if privA != privB {
		t.Fatal("same identity must derive same WG private")
	}
	privC := protocol.DeriveWGPrivateKey("mesh", "wrong")
	if privA == privC {
		t.Fatal("mismatched secret must derive different WG private")
	}

	svc, err := ListenWG("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go svc.Serve(ctx)

	serverDone := make(chan error, 1)
	go func() {
		sess, err := svc.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer sess.Close()
		serverID := peer.LegacyIdentity{PeerID: 22, NetworkName: "mesh"}
		serverID.NetworkSecretDigest = protocol.GenerateDigestFromStrings("mesh", "secret")
		pkt, err := sess.Receive(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		if _, err := peer.RespondLegacyHandshake(ctx, sess, serverID, pkt); err != nil {
			serverDone <- err
			return
		}
		pkt, err = sess.Receive(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		if string(pkt.Payload) != "ping" {
			serverDone <- err
			return
		}
		serverDone <- sess.Send(ctx, protocol.Packet{
			Header:  protocol.PeerManagerHeader{FromPeerID: 22, ToPeerID: 11, PacketType: protocol.PacketTypeData},
			Payload: []byte("pong"),
		})
	}()

	client, err := DialWG(ctx, svc.Address().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clientID := peer.LegacyIdentity{PeerID: 11, NetworkName: "mesh"}
	clientID.NetworkSecretDigest = protocol.GenerateDigestFromStrings("mesh", "secret")
	resp, err := peer.InitiateLegacyHandshake(ctx, client, clientID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.MyPeerID != 22 {
		t.Fatalf("peer id mismatch %d", resp.MyPeerID)
	}
	if err := client.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: 22, PacketType: protocol.PacketTypeData},
		Payload: []byte("ping"),
	}); err != nil {
		t.Fatal(err)
	}
	pkt, err := client.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt.Payload) != "pong" {
		t.Fatalf("pong mismatch %q", string(pkt.Payload))
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestWGRejectsWrongNetworkSecret(t *testing.T) {
	svc, err := ListenWG("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go svc.Serve(ctx)

	serverDone := make(chan error, 1)
	go func() {
		sess, err := svc.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer sess.Close()
		serverID := peer.LegacyIdentity{PeerID: 22, NetworkName: "mesh"}
		serverID.NetworkSecretDigest = protocol.GenerateDigestFromStrings("mesh", "secret")
		pkt, err := sess.Receive(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		_, err = peer.RespondLegacyHandshake(ctx, sess, serverID, pkt)
		// Should fail because digests differ
		if err == nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	client, err := DialWG(ctx, svc.Address().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clientID := peer.LegacyIdentity{PeerID: 11, NetworkName: "mesh"}
	clientID.NetworkSecretDigest = protocol.GenerateDigestFromStrings("mesh", "wrong")
	_, err = peer.InitiateLegacyHandshake(ctx, client, clientID)
	if err == nil {
		t.Fatal("handshake with wrong secret should fail")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server side unexpected success: %v", err)
	}
}

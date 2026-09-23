// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestWGStandardGoToGo(t *testing.T) {
	cfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ListenWGWithCrypto("127.0.0.1:0", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = svc.Serve(ctx) }()

	serverDone := make(chan error, 1)
	go func() {
		sess, err := svc.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer sess.Close()
		pkt, err := sess.Receive(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		if string(pkt.Payload) != "ping" {
			t.Errorf("server expected ping, got %q", string(pkt.Payload))
		}
		serverDone <- sess.Send(ctx, protocol.Packet{
			Header:  protocol.PeerManagerHeader{FromPeerID: 22, ToPeerID: 11, PacketType: protocol.PacketTypeData},
			Payload: []byte("pong"),
		})
	}()

	clientCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	client, err := DialWGStandard(ctx, svc.Address().String(), &clientCfg)
	if err != nil {
		t.Fatalf("DialWGStandard failed: %v", err)
	}
	defer client.Close()

	if err := client.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: 22, PacketType: protocol.PacketTypeData},
		Payload: []byte("ping"),
	}); err != nil {
		t.Fatalf("client send failed: %v", err)
	}

	pkt, err := client.Receive(ctx)
	if err != nil {
		t.Fatalf("client receive failed: %v", err)
	}
	if string(pkt.Payload) != "pong" {
		t.Fatalf("client expected pong, got %q", string(pkt.Payload))
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

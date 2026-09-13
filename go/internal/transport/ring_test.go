// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestCreateRingTunnelPairPingPong(t *testing.T) {
	server, client := CreateRingTunnelPair()
	defer server.Close()
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		pkt, err := server.Receive(ctx)
		if err != nil {
			return
		}
		_ = server.Send(ctx, protocol.Packet{
			Header:  protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 1, PacketType: protocol.PacketTypeData},
			Payload: pkt.Payload,
		})
	}()

	if err := client.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData},
		Payload: []byte("ring-ping"),
	}); err != nil {
		t.Fatal(err)
	}
	pkt, err := client.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt.Payload) != "ring-ping" {
		t.Fatalf("payload = %q, want ring-ping", pkt.Payload)
	}
}

func TestRingClosePropagatesToPeer(t *testing.T) {
	server, client := CreateRingTunnelPair()
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Receive(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("receive on ring with closed peer: got %v, want net.ErrClosed", err)
	}
	if err := client.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData},
		Payload: []byte("x"),
	}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send on ring with closed peer: got %v, want net.ErrClosed", err)
	}
}

func TestRingListenDialRoundTrip(t *testing.T) {
	address := "ring://" + newRingID()
	ln, err := ListenRing(address)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	accepted := make(chan PacketChannel, 1)
	go func() {
		channel, err := ln.Accept(ctx)
		if err == nil {
			accepted <- channel
		}
	}()

	client, err := DialPacketChannel(ctx, "ring", address, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIfCloser(client)
	select {
	case server := <-accepted:
		defer closeIfCloser(server)
		packet := protocol.Packet{Payload: []byte("via-registry")}
		if err := client.Send(ctx, packet); err != nil {
			t.Fatal(err)
		}
		got, err := server.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if string(got.Payload) != "via-registry" {
			t.Fatalf("payload = %q", got.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener never accepted")
	}
}

func TestRingDuplicateListenFails(t *testing.T) {
	id := newRingID()
	first, err := ListenRing("ring://" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := ListenRing("ring://" + id); err == nil {
		t.Fatal("duplicate ring listener must fail")
	}
}

func TestRingDialUnregisteredFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := DialRing(ctx, "ring://nobody-registered-this"); err == nil {
		t.Fatal("dialing an unregistered ring id must fail")
	}
}

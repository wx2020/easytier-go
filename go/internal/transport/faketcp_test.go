// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestFakeTCPPingPong(t *testing.T) {
	svc, err := ListenFakeTCP("127.0.0.1:0", 0)
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
		pkt, err := sess.Receive(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		if string(pkt.Payload) != "ping" {
			serverDone <- err
			return
		}
		err = sess.Send(ctx, protocol.Packet{
			Header:  protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 1, PacketType: protocol.PacketTypeData},
			Payload: []byte("pong"),
		})
		serverDone <- err
	}()

	client, err := DialFakeTCP(ctx, svc.Address().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := client.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData},
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

func TestFakeTCPGenericPacketChannel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ln, err := ListenPacketChannelWithContext(ctx, "faketcp", "127.0.0.1:0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		sess, err := ln.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		defer sess.(interface{ Close() error }).Close()
		pkt, err := sess.Receive(ctx)
		if err != nil {
			done <- err
			return
		}
		done <- sess.Send(ctx, pkt)
	}()
	ch, err := DialPacketChannel(ctx, "faketcp", ln.Address().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.(interface{ Close() error }).Close()
	payload := []byte("generic-faketcp")
	if err := ch.Send(ctx, protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData}, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	pkt, err := ch.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt.Payload) != string(payload) {
		t.Fatalf("payload mismatch %q", string(pkt.Payload))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFakeTCPPrivilegedDetection(t *testing.T) {
	// This test just ensures the function runs and matches OS expectation.
	priv := IsFakeTCPPrivileged()
	t.Logf("fakeTCP privileged = %v", priv)
	// On Linux CI, may be root or not; both are acceptable.
}

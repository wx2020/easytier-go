// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestWGEncryptedPingPong(t *testing.T) {
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
	go svc.Serve(ctx)

	serverDone := make(chan error, 1)
	go func() {
		sess, err := svc.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer sess.Close()
		if sess.crypto == nil {
			serverDone <- errors.New("server session has no crypto state")
			return
		}
		pkt, err := sess.Receive(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		if string(pkt.Payload) != "ping" {
			serverDone <- errors.New("payload mismatch")
			return
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
	client, err := DialWGWithCrypto(ctx, svc.Address().String(), &clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
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

func TestWGEncryptedDropsWrongSecret(t *testing.T) {
	cfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ListenWGWithCrypto("127.0.0.1:0", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go svc.Serve(ctx)

	wrongCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "wrong")
	if err != nil {
		t.Fatal(err)
	}
	intruder, err := DialWGWithCrypto(ctx, svc.Address().String(), &wrongCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer intruder.Close()
	// The intruder's datagrams must fail authentication server-side: no
	// session surfaces on Accept and none is retained.
	_ = intruder.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 99, ToPeerID: 22, PacketType: protocol.PacketTypeData},
		Payload: []byte("intrude"),
	})
	short, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer stop()
	if _, err := svc.Accept(short); err == nil {
		t.Fatal("wrong-secret datagram must not establish a session")
	}
	svc.mu.Lock()
	leftover := len(svc.sessions)
	svc.mu.Unlock()
	if leftover != 0 {
		t.Fatalf("server retained %d sessions from bad datagrams", leftover)
	}
}

func TestWGHandshakeEndToEndUpgradesKeys(t *testing.T) {
	cfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ListenWGWithCrypto("127.0.0.1:0", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
		if string(pkt.Payload) != "post-hs" {
			serverDone <- errors.New("payload mismatch")
			return
		}
		serverDone <- sess.Send(ctx, protocol.Packet{
			Header:  protocol.PeerManagerHeader{FromPeerID: 22, ToPeerID: 11, PacketType: protocol.PacketTypeData},
			Payload: []byte("hs-pong"),
		})
	}()

	clientCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	client, err := DialWGWithCrypto(ctx, svc.Address().String(), &clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	before := client.crypto.SendEpoch()
	if err := client.Handshake(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if client.crypto.SendEpoch() == before {
		t.Fatal("handshake must rotate to a new epoch")
	}
	if err := client.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: 22, PacketType: protocol.PacketTypeData},
		Payload: []byte("post-hs"),
	}); err != nil {
		t.Fatal(err)
	}
	pkt, err := client.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt.Payload) != "hs-pong" {
		t.Fatalf("pong mismatch %q", string(pkt.Payload))
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestWGHandshakeWithoutCryptoFails(t *testing.T) {
	svc, err := ListenWG("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go svc.Serve(ctx)
	client, err := DialWG(ctx, svc.Address().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Handshake(ctx); err == nil {
		t.Fatal("handshake without crypto must fail")
	}
}

func TestWGStandardShapedPacketsNotNative(t *testing.T) {
	cfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ListenWGWithCrypto("127.0.0.1:0", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go svc.Serve(ctx)

	// A standard-shaped initiation (148 bytes, type 1, no native magic)
	// must not be mistaken for a native handshake: no session surfaces.
	conn, err := net.Dial("udp", svc.Address().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	forged := make([]byte, 148)
	forged[0] = 0x01
	copy(forged[20:], bytes.Repeat([]byte{0xab}, 128))
	header := protocol.MarshalWGTunnelHeader(len(forged))
	if _, err := conn.Write(append(header, forged...)); err != nil {
		t.Fatal(err)
	}
	short, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer stop()
	if _, err := svc.Accept(short); err == nil {
		t.Fatal("standard-shaped datagram must not establish a native session")
	}
}

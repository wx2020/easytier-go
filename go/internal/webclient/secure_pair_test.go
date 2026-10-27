// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webclient

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

// TestSecureChannelRoundTrip pins the Noise upgrade wrappers: one packet each
// way must survive after the handshake.
func TestSecureChannelRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() { _ = listener.Serve(ctx) }()

	clientCh, err := transport.DialUDP(ctx, listener.Address().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	serverCh, err := listener.Accept(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	type result struct {
		ch      transport.PacketChannel
		upgrade bool
		err     error
	}
	serverResult := make(chan result, 1)
	go func() {
		ch, up, err := AcceptOrUpgradeServerChannel(ctx, serverCh, true)
		serverResult <- result{ch: ch, upgrade: up, err: err}
	}()

	secureClient, err := UpgradeClientChannel(ctx, clientCh)
	if err != nil {
		t.Fatalf("client upgrade: %v", err)
	}
	got := <-serverResult
	if got.err != nil {
		t.Fatalf("server upgrade: %v", got.err)
	}
	if !got.upgrade {
		t.Fatal("server did not upgrade")
	}

	recvCtx, cancelRecv := context.WithTimeout(ctx, 5*time.Second)
	defer cancelRecv()
	serverGot := make(chan error, 1)
	go func() {
		packet, err := got.ch.Receive(recvCtx)
		if err != nil {
			serverGot <- err
			return
		}
		if string(packet.Payload) != "client-to-server" {
			serverGot <- errPayload(packet.Payload)
			return
		}
		serverGot <- got.ch.Send(recvCtx, protocol.Packet{
			Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
			Payload: []byte("server-to-client"),
		})
	}()

	if err := secureClient.Send(recvCtx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: []byte("client-to-server"),
	}); err != nil {
		t.Fatalf("client send: %v", err)
	}
	if err := <-serverGot; err != nil {
		t.Fatalf("server side: %v", err)
	}
	reply, err := secureClient.Receive(recvCtx)
	if err != nil {
		t.Fatalf("client receive: %v", err)
	}
	if string(reply.Payload) != "server-to-client" {
		t.Fatalf("reply payload = %q", reply.Payload)
	}
}

func errPayload(payload []byte) error {
	return &payloadError{payload: payload}
}

type payloadError struct{ payload []byte }

func (e *payloadError) Error() string { return "unexpected payload: " + string(e.payload) }

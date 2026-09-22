// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestQUICTunnelPingPong(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svc, err := ListenQUIC("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenQUIC: %v", err)
	}
	defer svc.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		serverSession, err := svc.Accept(ctx)
		if err != nil {
			t.Errorf("svc.Accept: %v", err)
			return
		}
		defer serverSession.Close()

		pkt, err := serverSession.Receive(ctx)
		if err != nil {
			t.Errorf("server Receive: %v", err)
			return
		}
		if string(pkt.Payload) != "ping-from-client" {
			t.Errorf("unexpected payload: %s", string(pkt.Payload))
			return
		}

		reply := protocol.Packet{
			Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
			Payload: []byte("pong-from-server"),
		}
		if err := serverSession.Send(ctx, reply); err != nil {
			t.Errorf("server Send: %v", err)
			return
		}
	}()

	clientSession, err := DialQUIC(ctx, svc.Address().String())
	if err != nil {
		t.Fatalf("DialQUIC: %v", err)
	}
	defer clientSession.Close()

	ping := protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: []byte("ping-from-client"),
	}
	if err := clientSession.Send(ctx, ping); err != nil {
		t.Fatalf("client Send: %v", err)
	}

	reply, err := clientSession.Receive(ctx)
	if err != nil {
		t.Fatalf("client Receive: %v", err)
	}
	if string(reply.Payload) != "pong-from-server" {
		t.Fatalf("client received unexpected reply: %s", string(reply.Payload))
	}

	wg.Wait()
}

func TestQUICPacketChannelIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ln, err := ListenPacketChannel("quic", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacketChannel quic: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		serverCh, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("ln.Accept: %v", err)
			return
		}
		if closer, ok := serverCh.(interface{ Close() error }); ok {
			defer closer.Close()
		}

		pkt, err := serverCh.Receive(ctx)
		if err != nil {
			t.Errorf("server Receive: %v", err)
			return
		}

		resp := protocol.Packet{
			Header:  pkt.Header,
			Payload: append([]byte("echo:"), pkt.Payload...),
		}
		_ = serverCh.Send(ctx, resp)
	}()

	clientCh, err := DialPacketChannel(ctx, "quic", ln.Address().String(), 0)
	if err != nil {
		t.Fatalf("DialPacketChannel: %v", err)
	}
	if closer, ok := clientCh.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	req := protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: []byte("integration-test-data"),
	}
	if err := clientCh.Send(ctx, req); err != nil {
		t.Fatalf("clientCh.Send: %v", err)
	}

	resp, err := clientCh.Receive(ctx)
	if err != nil {
		t.Fatalf("clientCh.Receive: %v", err)
	}
	if string(resp.Payload) != "echo:integration-test-data" {
		t.Fatalf("unexpected resp payload: %s", string(resp.Payload))
	}

	wg.Wait()
}

func TestQUICMultiPacketSequence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	svc, err := ListenQUIC("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenQUIC: %v", err)
	}
	defer svc.Close()

	count := 50
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		serverSession, err := svc.Accept(ctx)
		if err != nil {
			t.Errorf("svc.Accept: %v", err)
			return
		}
		defer serverSession.Close()

		for i := 0; i < count; i++ {
			pkt, err := serverSession.Receive(ctx)
			if err != nil {
				t.Errorf("server Receive packet %d: %v", i, err)
				return
			}
			expectedPayload := bytes.Repeat([]byte{byte(i)}, 128)
			if !bytes.Equal(pkt.Payload, expectedPayload) {
				t.Errorf("packet %d payload mismatch", i)
				return
			}
		}
	}()

	clientSession, err := DialQUIC(ctx, svc.Address().String())
	if err != nil {
		t.Fatalf("DialQUIC: %v", err)
	}
	defer clientSession.Close()

	for i := 0; i < count; i++ {
		pkt := protocol.Packet{
			Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
			Payload: bytes.Repeat([]byte{byte(i)}, 128),
		}
		if err := clientSession.Send(ctx, pkt); err != nil {
			t.Fatalf("client Send %d: %v", i, err)
		}
	}

	wg.Wait()
}

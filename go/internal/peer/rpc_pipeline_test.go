// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func connectPipePair(t *testing.T, client, server *PeerConnectionManager) {
	t.Helper()
	clientChannel, serverChannel := managerPipe(t)
	connectResult := make(chan error, 1)
	go func() { connectResult <- client.Connect(context.Background(), clientChannel) }()
	if err := server.Accept(context.Background(), serverChannel); err != nil {
		t.Fatal(err)
	}
	if err := <-connectResult; err != nil {
		t.Fatal(err)
	}
}

func TestManagerRPCHandlerConsumesInPipeline(t *testing.T) {
	client, server := newDirectManagers(t)
	defer client.Close()
	defer server.Close()
	connectPipePair(t, client, server)

	var consumed atomic.Int32
	server.SetRPCHandler(func(_ context.Context, packet protocol.Packet) bool {
		if packet.Header.PacketType == protocol.PacketTypeRPCRequest {
			consumed.Add(1)
			return true
		}
		return false
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Send(ctx, 22, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeRPCRequest},
		Payload: []byte("rpc"),
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for consumed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if consumed.Load() != 1 {
		t.Fatalf("pipeline handler consumed %d rpc packets, want 1", consumed.Load())
	}
	// Consumed packets must not surface on Receive.
	short, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer stop()
	if _, err := server.Receive(short); err == nil {
		t.Fatal("consumed RPC packet must not be delivered to Receive")
	}

	// With no handler installed, RPC packets fall through to Receive.
	server.SetRPCHandler(nil)
	if err := client.Send(ctx, 22, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeRPCRequest},
		Payload: []byte("rpc2"),
	}); err != nil {
		t.Fatal(err)
	}
	packet, err := server.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(packet.Payload) != "rpc2" {
		t.Fatalf("payload = %q", packet.Payload)
	}
}

func TestManagerThroughputHooksFeedPinger(t *testing.T) {
	client, server := newDirectManagersWithPinger(t)
	defer client.Close()
	defer server.Close()
	connectPipePair(t, client, server)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Send(ctx, 22, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: []byte("hello"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Receive(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		tx := client.pingerFor(22).Throughput().TXPackets()
		rx := server.pingerFor(11).Throughput().RXPackets()
		if tx > 0 && rx > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("throughput hooks did not fire: tx=%d rx=%d", tx, rx)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newDirectManagersWithPinger(t *testing.T) (*PeerConnectionManager, *PeerConnectionManager) {
	t.Helper()
	clientStatic, err := GenerateDirectPeerStaticKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverStatic, err := GenerateDirectPeerStaticKeypair()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewPeerConnectionManager(PeerConnectionManagerConfig{
		LocalPeerID:   11,
		HandshakeMode: HandshakeModeDirectNoise,
		DirectHandshake: DirectPeerHandshakeConfig{
			LocalPeerID:        11,
			NetworkName:        "mesh",
			NetworkSecret:      "secret",
			StaticKeypair:      clientStatic,
			PinnedRemoteStatic: serverStatic.Public,
			CipherSuite:        CipherSuiteChaCha20Poly1305,
		},
		PingerEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPeerConnectionManager(PeerConnectionManagerConfig{
		LocalPeerID:   22,
		HandshakeMode: HandshakeModeDirectNoise,
		DirectHandshake: DirectPeerHandshakeConfig{
			LocalPeerID:        22,
			NetworkName:        "mesh",
			NetworkSecret:      "secret",
			StaticKeypair:      serverStatic,
			PinnedRemoteStatic: clientStatic.Public,
			CipherSuite:        CipherSuiteChaCha20Poly1305,
		},
		PingerEnabled: true,
	})
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	return client, server
}

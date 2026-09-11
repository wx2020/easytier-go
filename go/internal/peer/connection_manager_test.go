// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

func TestPeerConnectionManagerDirectPingOverPipe(t *testing.T) {
	clientManager, serverManager := newDirectManagers(t)
	defer clientManager.Close()
	defer serverManager.Close()

	clientConnection, serverConnection := net.Pipe()
	clientChannel, err := transport.NewTCPPacketChannel(clientConnection, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverChannel, err := transport.NewTCPPacketChannel(serverConnection, 0)
	if err != nil {
		t.Fatal(err)
	}
	connectResult := make(chan error, 1)
	go func() { connectResult <- clientManager.Connect(context.Background(), clientChannel) }()
	if err := serverManager.Accept(context.Background(), serverChannel); err != nil {
		t.Fatal(err)
	}
	if err := <-connectResult; err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := clientManager.Send(ctx, 22, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypePing},
		Payload: []byte("ping"),
	}); err != nil {
		t.Fatal(err)
	}
	packet, err := serverManager.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Header.PacketType != protocol.PacketTypePing || string(packet.Payload) != "ping" {
		t.Fatalf("server packet = %#v", packet)
	}
	pong, err := clientManager.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pong.Header.PacketType != protocol.PacketTypePong || pong.Header.FromPeerID != 22 || string(pong.Payload) != "ping" {
		t.Fatalf("client pong = %#v", pong)
	}
}

func TestPeerSessionCompressionBeforeEncryption(t *testing.T) {
	client, server := newDirectManagersWithCompression(t)
	defer client.Close()
	defer server.Close()

	clientChannel, serverChannel := managerPipe(t)
	connectResult := make(chan error, 1)
	go func() { connectResult <- client.Connect(context.Background(), clientChannel) }()
	if err := server.Accept(context.Background(), serverChannel); err != nil {
		t.Fatal(err)
	}
	if err := <-connectResult; err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, 512)
	for index := range payload {
		payload[index] = "abc"[index%3]
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Send(ctx, 22, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: payload,
	}); err != nil {
		t.Fatal(err)
	}
	packet, err := server.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(packet.Payload) != string(payload) || packet.Header.IsCompressed() || packet.Header.Flags&protocol.FlagEncrypted != 0 {
		t.Fatalf("received packet = %#v", packet)
	}
}

func TestPeerConnectionManagerLegacyPingOverPipe(t *testing.T) {
	clientManager, err := NewPeerConnectionManager(PeerConnectionManagerConfig{
		LocalPeerID:    11,
		LegacyIdentity: testIdentity(11, "mesh", 0x44),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientManager.Close()
	serverManager, err := NewPeerConnectionManager(PeerConnectionManagerConfig{
		LocalPeerID:    22,
		LegacyIdentity: testIdentity(22, "mesh", 0x44),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverManager.Close()

	clientChannel, serverChannel := managerPipe(t)
	connectResult := make(chan error, 1)
	go func() { connectResult <- clientManager.Connect(context.Background(), clientChannel) }()
	if err := serverManager.Accept(context.Background(), serverChannel); err != nil {
		t.Fatal(err)
	}
	if err := <-connectResult; err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := clientManager.Send(ctx, 22, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypePing},
		Payload: []byte("legacy"),
	}); err != nil {
		t.Fatal(err)
	}
	packet, err := serverManager.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Header.PacketType != protocol.PacketTypePing || string(packet.Payload) != "legacy" {
		t.Fatalf("server packet = %#v", packet)
	}
}

func TestPeerConnectionManagerReplacesDuplicate(t *testing.T) {
	clientManager, serverManager := newDirectManagers(t)
	defer clientManager.Close()
	defer serverManager.Close()

	firstClient, firstServer := managerPipe(t)
	connectResult := make(chan error, 1)
	go func() { connectResult <- clientManager.Connect(context.Background(), firstClient) }()
	if err := serverManager.Accept(context.Background(), firstServer); err != nil {
		t.Fatal(err)
	}
	if err := <-connectResult; err != nil {
		t.Fatal(err)
	}
	firstSession, ok := serverManager.Peer(11)
	if !ok {
		t.Fatal("first session was not registered")
	}

	secondClient, secondServer := managerPipe(t)
	connectResult = make(chan error, 1)
	go func() { connectResult <- clientManager.Connect(context.Background(), secondClient) }()
	if err := serverManager.Accept(context.Background(), secondServer); err != nil {
		t.Fatal(err)
	}
	if err := <-connectResult; err != nil {
		t.Fatal(err)
	}
	secondSession, ok := serverManager.Peer(11)
	if !ok || secondSession == firstSession {
		t.Fatal("duplicate did not replace the first session")
	}
	if serverManager.PeerCount() != 1 {
		t.Fatalf("peer count = %d, want 1", serverManager.PeerCount())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := clientManager.Send(ctx, 22, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypePing},
		Payload: []byte("replacement"),
	}); err != nil {
		t.Fatal(err)
	}
	packet, err := serverManager.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(packet.Payload) != "replacement" {
		t.Fatalf("replacement packet = %#v", packet)
	}
}

func newDirectManagers(t *testing.T) (*PeerConnectionManager, *PeerConnectionManager) {
	return newDirectManagersWithAlgorithm(t, protocol.CompressionNone)
}

func newDirectManagersWithCompression(t *testing.T) (*PeerConnectionManager, *PeerConnectionManager) {
	return newDirectManagersWithAlgorithm(t, protocol.CompressionZstd)
}

func newDirectManagersWithAlgorithm(t *testing.T, algorithm protocol.CompressionAlgorithm) (*PeerConnectionManager, *PeerConnectionManager) {
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
		LocalPeerID:      11,
		DataCompressAlgo: algorithm,
		HandshakeMode:    HandshakeModeDirectNoise,
		DirectHandshake: DirectPeerHandshakeConfig{
			LocalPeerID:        11,
			NetworkName:        "mesh",
			NetworkSecret:      "secret",
			StaticKeypair:      clientStatic,
			PinnedRemoteStatic: serverStatic.Public,
			CipherSuite:        CipherSuiteChaCha20Poly1305,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPeerConnectionManager(PeerConnectionManagerConfig{
		LocalPeerID:      22,
		DataCompressAlgo: algorithm,
		HandshakeMode:    HandshakeModeDirectNoise,
		DirectHandshake: DirectPeerHandshakeConfig{
			LocalPeerID:        22,
			NetworkName:        "mesh",
			NetworkSecret:      "secret",
			StaticKeypair:      serverStatic,
			PinnedRemoteStatic: clientStatic.Public,
			CipherSuite:        CipherSuiteChaCha20Poly1305,
		},
	})
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	return client, server
}

func managerPipe(t *testing.T) (*transport.TCPPacketChannel, *transport.TCPPacketChannel) {
	t.Helper()
	client, server := net.Pipe()
	clientChannel, err := transport.NewTCPPacketChannel(client, 0)
	if err != nil {
		_ = client.Close()
		_ = server.Close()
		t.Fatal(err)
	}
	serverChannel, err := transport.NewTCPPacketChannel(server, 0)
	if err != nil {
		_ = clientChannel.Close()
		t.Fatal(err)
	}
	return clientChannel, serverChannel
}

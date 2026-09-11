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

func TestTCPPacketChannelRoundTrip(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	client, err := NewTCPPacketChannel(clientConnection, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTCPPacketChannel(serverConnection, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	packet := protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData},
		Payload: []byte("packet"),
	}
	writeResult := make(chan error, 1)
	go func() { writeResult <- client.Send(context.Background(), packet) }()
	got, err := server.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	if got.Header != (protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData, Length: 6}) || string(got.Payload) != "packet" {
		t.Fatalf("packet = %#v", got)
	}

	reply := protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 1, PacketType: protocol.PacketTypePong},
		Payload: []byte("reply"),
	}
	replyResult := make(chan error, 1)
	go func() { replyResult <- server.Send(context.Background(), reply) }()
	got, err = client.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := <-replyResult; err != nil {
		t.Fatal(err)
	}
	if got.Header != (protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 1, PacketType: protocol.PacketTypePong, Length: 5}) || string(got.Payload) != "reply" {
		t.Fatalf("reverse packet = %#v", got)
	}
}

func TestTCPPacketChannelReceiveHonorsContextDeadline(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	client, err := NewTCPPacketChannel(clientConnection, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer serverConnection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = client.Receive(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive error = %v, want deadline exceeded", err)
	}
}

func TestTCPPacketChannelReceiveHonorsCancellationWithoutDeadline(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	client, err := NewTCPPacketChannel(clientConnection, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer serverConnection.Close()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.Receive(ctx)
		result <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive error = %v, want context canceled", err)
	}
}

func TestTCPPacketChannelSendRejectsOversizedFrame(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	client, err := NewTCPPacketChannel(clientConnection, protocol.PeerManagerHeaderSize)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer serverConnection.Close()

	if err := client.Send(context.Background(), protocol.Packet{Payload: []byte("x")}); err == nil {
		t.Fatal("Send accepted a frame larger than the configured maximum")
	}
}

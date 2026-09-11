// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/transport"
)

func TestLegacyHandshakeOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	serverIdentity := testIdentity(22, "mesh", 0x33)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		channel, err := transport.NewTCPPacketChannel(connection, 0)
		if err != nil {
			serverResult <- err
			return
		}
		defer channel.Close()
		packet, err := channel.Receive(context.Background())
		if err == nil {
			_, err = RespondLegacyHandshake(context.Background(), channel, serverIdentity, packet)
		}
		serverResult <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := transport.DialTCP(ctx, listener.Addr().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := InitiateLegacyHandshake(ctx, client, testIdentity(11, "mesh", 0x33))
	if err != nil {
		t.Fatal(err)
	}
	if response.MyPeerID != serverIdentity.PeerID {
		t.Fatalf("server peer ID = %d", response.MyPeerID)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

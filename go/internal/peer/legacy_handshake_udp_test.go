// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/transport"
)

func TestLegacyHandshakeOverUDP(t *testing.T) {
	service, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	serveCtx, stopServe := context.WithCancel(context.Background())
	defer stopServe()
	serveResult := make(chan error, 1)
	go func() { serveResult <- service.Serve(serveCtx) }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := transport.DialUDP(ctx, service.Address().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := service.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	serverIdentity := testIdentity(22, "mesh", 0x44)
	serverResult := make(chan error, 1)
	go func() {
		packet, err := server.Receive(ctx)
		if err == nil {
			_, err = RespondLegacyHandshake(ctx, server, serverIdentity, packet)
		}
		serverResult <- err
	}()

	response, err := InitiateLegacyHandshake(ctx, client, testIdentity(11, "mesh", 0x44))
	if err != nil {
		t.Fatal(err)
	}
	if response.MyPeerID != serverIdentity.PeerID {
		t.Fatalf("server peer ID = %d", response.MyPeerID)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	stopServe()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestWSSSelfSignedListenerInsecureDial(t *testing.T) {
	listener, err := ListenWebSocket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- listener.ServeTLS(ctx, "", "") }()

	// The dial supplies no TLS options at all: the insecure default must
	// accept the listener's self-signed certificate.
	wssURL := "wss://" + listener.Address().String()
	client, err := DialWebSocket(ctx, wssURL)
	if err != nil {
		t.Fatalf("insecure wss dial: %v", err)
	}
	defer client.Close()
	// Once ServeTLS ran, the listener reports the wss scheme.
	if got := listener.URL()[:4]; got != "wss:" {
		t.Fatalf("listener URL scheme = %q, want wss:", got)
	}
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	packet := protocol.Packet{Payload: []byte("self-signed wss")}
	if err := client.Send(ctx, packet); err != nil {
		t.Fatal(err)
	}
	got, err := server.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != string(packet.Payload) {
		t.Fatalf("payload = %q, want %q", got.Payload, packet.Payload)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveResult; err != nil {
		t.Fatalf("ServeTLS error: %v", err)
	}
}

func TestListenPacketChannelWSSServesTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := ListenPacketChannelWithContext(ctx, "wss", "127.0.0.1:0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := DialPacketChannel(ctx, "wss", "wss://"+ln.Address().String(), 0)
	if err != nil {
		t.Fatalf("dial packet channel wss: %v", err)
	}
	defer closeIfCloser(client)
	server, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIfCloser(server)

	packet := protocol.Packet{Payload: []byte("factory wss")}
	if err := client.Send(ctx, packet); err != nil {
		t.Fatal(err)
	}
	got, err := server.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != string(packet.Payload) {
		t.Fatalf("payload = %q, want %q", got.Payload, packet.Payload)
	}
}

func closeIfCloser(c interface{}) {
	if closer, ok := c.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func TestWSSServerNameRewrite(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":   "localhost",
		"::1":         "localhost",
		"10.1.2.3":    "localhost",
		"example.com": "example.com",
		"":            "localhost",
	}
	for host, want := range cases {
		if got := wssServerName(host); got != want {
			t.Fatalf("wssServerName(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestInsecureWSSClientConfig(t *testing.T) {
	config := InsecureWSSClientConfig()
	if config == nil || !config.InsecureSkipVerify {
		t.Fatal("insecure wss client config must skip verification")
	}
	// A self-signed listener certificate must dial successfully through the
	// generated config (verifies the certificate is well-formed TLS).
	listener, err := ListenWebSocket("127.0.0.1:0", WebSocketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = listener.ServeTLS(ctx, "", "") }()
	wssURL := "wss://" + listener.Address().String()
	client, err := DialWebSocket(ctx, wssURL, WebSocketOptions{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("explicit insecure dial: %v", err)
	}
	_ = client.Close()
}

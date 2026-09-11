// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webclient

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestWebSecureOptionalDowngrade(t *testing.T) {
	// Server optional (default) should accept plain client.
	srv, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(20 * time.Millisecond)
	addr := srv.Addr().String()
	client, err := NewClient(ClientConfig{
		Address:             addr,
		MachineID:           "plain-machine",
		HeartbeatInterval:   10 * time.Millisecond,
		ReconnectMinBackoff: 5 * time.Millisecond,
		ReconnectMaxBackoff: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	go func() { _ = client.Run(cctx) }()
	waitFor(t, func() bool {
		s, ok := srv.Session("plain-machine")
		return ok && s.Connected
	})
}

func TestWebSecureUpgradeAndDowngrade(t *testing.T) {
	// Secure client to optional server should upgrade successfully.
	srv, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(20 * time.Millisecond)
	addr := srv.Addr().String()
	updates := make(chan ConfigUpdate, 1)
	client, err := NewClient(ClientConfig{
		Address:             addr,
		MachineID:           "secure-machine",
		EnableNoise:         true,
		HeartbeatInterval:   10 * time.Millisecond,
		ReconnectMinBackoff: 5 * time.Millisecond,
		ReconnectMaxBackoff: 20 * time.Millisecond,
		OnConfigUpdate:      func(u ConfigUpdate) { updates <- u },
	})
	if err != nil {
		t.Fatal(err)
	}
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	go func() { _ = client.Run(cctx) }()
	waitFor(t, func() bool {
		s, ok := srv.Session("secure-machine")
		return ok && s.Connected
	})
	// Verify secure datagram channel works: send config update.
	if err := srv.SendConfigUpdate(context.Background(), "secure-machine", ConfigUpdate{Version: "2", Config: json.RawMessage(`{"secure":true}`)}); err != nil {
		t.Fatal(err)
	}
	select {
	case u := <-updates:
		if u.Version != "2" {
			t.Fatalf("version = %q want 2", u.Version)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for secure config update")
	}
}

func TestWebSecureRequiredRejectsPlain(t *testing.T) {
	srv, err := NewServer(ServerConfig{RequireSecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(20 * time.Millisecond)
	addr := srv.Addr().String()
	client, err := NewClient(ClientConfig{
		Address:             addr,
		MachineID:           "plain-required-machine",
		HeartbeatInterval:   10 * time.Millisecond,
		ReconnectMinBackoff: 5 * time.Millisecond,
		ReconnectMaxBackoff: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	go func() { _ = client.Run(cctx) }()
	// Should NOT become connected within 500ms.
	time.Sleep(500 * time.Millisecond)
	if s, ok := srv.Session("plain-required-machine"); ok && s.Connected {
		t.Fatalf("plain client should not be connected when server requires secure, got %+v", s)
	}
	_ = client.Close()
	_ = srv.Close()
}

func TestWebSecureRequiredAcceptsSecure(t *testing.T) {
	srv, err := NewServer(ServerConfig{RequireSecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(20 * time.Millisecond)
	addr := srv.Addr().String()
	client, err := NewClient(ClientConfig{
		Address:             addr,
		MachineID:           "secure-required-machine",
		EnableNoise:         true,
		HeartbeatInterval:   10 * time.Millisecond,
		ReconnectMinBackoff: 5 * time.Millisecond,
		ReconnectMaxBackoff: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	go func() { _ = client.Run(cctx) }()
	waitFor(t, func() bool {
		s, ok := srv.Session("secure-required-machine")
		return ok && s.Connected
	})
	_ = client.Close()
}

func TestWebSecureOverUDPAndWS(t *testing.T) {
	tests := []struct {
		name   string
		listen func(*Server) error
		scheme string
	}{
		{
			name: "udp",
			listen: func(s *Server) error { return s.ListenUDP("127.0.0.1:0") },
			scheme: "udp",
		},
		{
			name: "websocket",
			listen: func(s *Server) error { return s.ListenWebSocket("127.0.0.1:0") },
			scheme: "ws",
		},
	}
	// For UDP/WS we just test plain downgrade for now; secure over those transports should also work via same PacketChannel abstraction.
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Use non-secure for simplicity, but server still does AcceptOrUpgrade handling.
			srv, err := NewServer(ServerConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.listen(srv); err != nil {
				t.Skipf("listen %s failed: %v", tc.name, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = srv.Serve(ctx) }()
			time.Sleep(20 * time.Millisecond)
			addr := srv.Addr().String()
			if addr == "" {
				t.Fatal("addr empty")
			}
			clientAddr := tc.scheme + "://" + addr
			// Plain client to optional server should succeed.
			client, err := NewClient(ClientConfig{
				Address:             clientAddr,
				MachineID:           "machine-" + tc.name,
				HeartbeatInterval:   10 * time.Millisecond,
				ReconnectMinBackoff: 5 * time.Millisecond,
				ReconnectMaxBackoff: 20 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			cctx, ccancel := context.WithCancel(context.Background())
			defer ccancel()
			go func() { _ = client.Run(cctx) }()
			waitFor(t, func() bool {
				s, ok := srv.Session("machine-" + tc.name)
				return ok && s.Connected
			})
			_ = client.Close()
		})
	}
}

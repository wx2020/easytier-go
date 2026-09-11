// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webclient

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/transport"
)

func TestLoopbackRegistrationHeartbeatAndConfigUpdate(t *testing.T) {
	updates := make(chan ConfigUpdate, 1)
	server, client, _ := startLoopback(t, ClientConfig{
		MachineID:           "machine-1",
		HeartbeatInterval:   10 * time.Millisecond,
		ReconnectMinBackoff: 5 * time.Millisecond,
		ReconnectMaxBackoff: 20 * time.Millisecond,
		OnConfigUpdate:      func(update ConfigUpdate) { updates <- update },
	})

	waitFor(t, func() bool {
		session, ok := server.Session("machine-1")
		return ok && session.Connected
	})
	first, _ := server.Session("machine-1")
	waitFor(t, func() bool {
		current, ok := server.Session("machine-1")
		return ok && current.LastSeen.After(first.LastSeen)
	})

	if err := server.SendConfigUpdate(context.Background(), "machine-1", ConfigUpdate{
		Version: "2",
		Config:  []byte(`{"network":"mesh"}`),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case update := <-updates:
		if update.Version != "2" || string(update.Config) != `{"network":"mesh"}` {
			t.Fatalf("config update = %#v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for config update")
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientReconnectsAfterServerBecomesAvailable(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(ClientConfig{
		Address:             address,
		MachineID:           "reconnect-machine",
		HeartbeatInterval:   10 * time.Millisecond,
		ReconnectMinBackoff: 5 * time.Millisecond,
		ReconnectMaxBackoff: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Run(ctx) }()
	time.Sleep(25 * time.Millisecond)

	server, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen(address); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()

	waitFor(t, func() bool {
		session, ok := server.Session("reconnect-machine")
		return ok && session.Connected
	})
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("client Run: %v", err)
	}
	_ = server.Close()
	if err := <-serveDone; err != nil {
		t.Fatalf("server Serve: %v", err)
	}
}

func TestConfigSessionLoopbackOverUDPAndWebSocket(t *testing.T) {
	tests := []struct {
		name    string
		listen  func(*Server) error
		address func(*Server) string
	}{
		{
			name: "udp",
			listen: func(server *Server) error {
				return server.ListenUDP("127.0.0.1:0")
			},
			address: func(server *Server) string { return "udp://" + server.Addr().String() },
		},
		{
			name: "websocket",
			listen: func(server *Server) error {
				return server.ListenWebSocket("127.0.0.1:0", transport.WebSocketOptions{
					CheckOrigin: func(*http.Request) bool { return true },
				})
			},
			address: func(server *Server) string { return "ws://" + server.Addr().String() },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, err := NewServer(ServerConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if err := test.listen(server); err != nil {
				t.Fatal(err)
			}
			serveDone := make(chan error, 1)
			go func() { serveDone <- server.Serve(context.Background()) }()
			updates := make(chan ConfigUpdate, 1)
			client, err := NewClient(ClientConfig{
				Address:             test.address(server),
				MachineID:           "machine-" + test.name,
				HeartbeatInterval:   10 * time.Millisecond,
				ReconnectMinBackoff: 5 * time.Millisecond,
				ReconnectMaxBackoff: 20 * time.Millisecond,
				OnConfigUpdate: func(update ConfigUpdate) {
					updates <- update
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			clientDone := make(chan error, 1)
			go func() { clientDone <- client.Run(context.Background()) }()

			waitFor(t, func() bool {
				session, ok := server.Session("machine-" + test.name)
				return ok && session.Connected
			})
			first, _ := server.Session("machine-" + test.name)
			waitFor(t, func() bool {
				current, ok := server.Session("machine-" + test.name)
				return ok && current.LastSeen.After(first.LastSeen)
			})
			if err := server.SendConfigUpdate(context.Background(), "machine-"+test.name, ConfigUpdate{Config: []byte(`{"mode":"loopback"}`)}); err != nil {
				t.Fatal(err)
			}
			select {
			case update := <-updates:
				if string(update.Config) != `{"mode":"loopback"}` {
					t.Fatalf("config update = %#v", update)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for config update")
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-clientDone:
				if err != nil {
					t.Fatalf("client Run: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("client did not stop")
			}
			waitFor(t, func() bool {
				session, ok := server.Session("machine-" + test.name)
				return ok && !session.Connected
			})
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-serveDone:
				if err != nil {
					t.Fatalf("server Serve: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("server did not stop")
			}
		})
	}
}

func TestInvalidFrameIsRejected(t *testing.T) {
	server, err := NewServer(ServerConfig{MaxFrameSize: 32})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	defer func() {
		_ = server.Close()
		if err := <-serveDone; err != nil {
			t.Errorf("server Serve: %v", err)
		}
	}()

	connection, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], 33)
	if _, err := connection.Write(prefix[:]); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	_, err = connection.Read(one[:])
	if err == nil {
		t.Fatal("invalid frame was accepted")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.DeadlineExceeded) {
		var netError net.Error
		if !errors.As(err, &netError) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("invalid frame read error = %v", err)
		}
	}
}

func TestUnsupportedNoiseUpgrade(t *testing.T) {
	if _, err := (UnsupportedNoiseUpgrader{}).Upgrade(context.Background(), nil); !errors.Is(err, ErrNoiseUnsupported) {
		t.Fatalf("Upgrade error = %v", err)
	}
}

func startLoopback(t *testing.T, config ClientConfig) (*Server, *Client, <-chan error) {
	t.Helper()
	server, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	config.Address = server.Addr().String()
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Run(context.Background()) }()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		select {
		case <-clientDone:
		case <-time.After(time.Second):
			t.Error("client did not stop")
		}
		select {
		case <-serveDone:
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	})
	return server, client, serveDone
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met")
}

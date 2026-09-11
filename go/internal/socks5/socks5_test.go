// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestConnectEcho(t *testing.T) {
	echo := startEcho(t)
	manager := startManager(t, nil)
	connection := dialManager(t, manager)
	defer connection.Close()

	negotiateClient(t, connection, []byte{methodNoAuth})
	writeRequest(t, connection, commandConnect, addressIPv4, net.ParseIP("127.0.0.1").To4(), echo.Addr().(*net.TCPAddr).Port)
	if reply := readReply(t, connection); reply != replySucceeded {
		t.Fatalf("CONNECT reply = %d, want success", reply)
	}
	message := []byte("loopback echo")
	if _, err := connection.Write(message); err != nil {
		t.Fatalf("write through proxy: %v", err)
	}
	received := make([]byte, len(message))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatalf("read through proxy: %v", err)
	}
	if string(received) != string(message) {
		t.Fatalf("echo = %q, want %q", received, message)
	}
}

func TestRejectsUnsupportedAuthentication(t *testing.T) {
	manager := startManager(t, nil)
	connection := dialManager(t, manager)
	defer connection.Close()

	negotiateClient(t, connection, []byte{2})
}

func TestRejectsUnsupportedCommand(t *testing.T) {
	manager := startManager(t, nil)
	connection := dialManager(t, manager)
	defer connection.Close()

	negotiateClient(t, connection, []byte{methodNoAuth})
	writeRequest(t, connection, 3, addressIPv4, net.IPv4zero.To4(), 0)
	if reply := readReply(t, connection); reply != replyCommandNotSupported {
		t.Fatalf("reply = %d, want %d", reply, replyCommandNotSupported)
	}
}

func TestParsesIPv6AndDomain(t *testing.T) {
	tests := []struct {
		name    string
		address byte
		host    []byte
		want    string
	}{
		{name: "IPv6", address: addressIPv6, host: net.ParseIP("2001:db8::1").To16(), want: "[2001:db8::1]:443"},
		{name: "domain", address: addressDomain, host: []byte("example.test"), want: "example.test:443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialed := make(chan string, 1)
			manager := startManager(t, func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" {
					t.Errorf("network = %q, want tcp", network)
				}
				dialed <- address
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					_, _ = io.Copy(io.Discard, server)
				}()
				return client, nil
			})
			connection := dialManager(t, manager)
			defer connection.Close()

			negotiateClient(t, connection, []byte{methodNoAuth})
			writeRequest(t, connection, commandConnect, test.address, test.host, 443)
			if reply := readReply(t, connection); reply != replySucceeded {
				t.Fatalf("reply = %d, want success", reply)
			}
			select {
			case address := <-dialed:
				if address != test.want {
					t.Fatalf("dial address = %q, want %q", address, test.want)
				}
			case <-time.After(time.Second):
				t.Fatal("dial was not called")
			}
		})
	}
}

func TestContextCancellationClosesListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	manager := NewManager(Config{})
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("start manager: %v", err)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", manager.Addr().String(), 10*time.Millisecond)
		if err != nil {
			break
		}
		_ = connection.Close()
		time.Sleep(time.Millisecond)
	}
	if connection, err := net.DialTimeout("tcp", manager.Addr().String(), 10*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Fatal("listener remained reachable after context cancellation")
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("close manager: %v", err)
	}
	if err := manager.Start(context.Background()); err != ErrClosed {
		t.Fatalf("start after close = %v, want %v", err, ErrClosed)
	}
}

func startManager(t *testing.T, dial DialContextFunc) *Manager {
	t.Helper()
	manager := NewManager(Config{ListenAddr: "127.0.0.1:0", DialContext: dial})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("start manager: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func dialManager(t *testing.T, manager *Manager) net.Conn {
	t.Helper()
	connection, err := net.Dial("tcp", manager.Addr().String())
	if err != nil {
		t.Fatalf("dial manager: %v", err)
	}
	return connection
}

func startEcho(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener
}

func negotiateClient(t *testing.T, connection net.Conn, methods []byte) {
	t.Helper()
	request := append([]byte{version, byte(len(methods))}, methods...)
	if _, err := connection.Write(request); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	var response [2]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	want := byte(methodNoAuth)
	if len(methods) == 1 && methods[0] != methodNoAuth {
		want = methodNoAcceptable
	}
	if response != [2]byte{version, want} {
		t.Fatalf("greeting response = %v, want [%d %d]", response, version, want)
	}
}

func writeRequest(t *testing.T, connection net.Conn, command, addressType byte, host []byte, port int) {
	t.Helper()
	request := []byte{version, command, 0, addressType}
	if addressType == addressDomain {
		request = append(request, byte(len(host)))
	}
	request = append(request, host...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := connection.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
}

func readReply(t *testing.T, connection net.Conn) byte {
	t.Helper()
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		t.Fatalf("read reply header: %v", err)
	}
	if header[0] != version || header[2] != 0 {
		t.Fatalf("invalid reply header %v", header)
	}
	length := 0
	switch header[3] {
	case addressIPv4:
		length = 4
	case addressIPv6:
		length = 16
	case addressDomain:
		var domainLength [1]byte
		if _, err := io.ReadFull(connection, domainLength[:]); err != nil {
			t.Fatalf("read reply domain length: %v", err)
		}
		length = int(domainLength[0])
	default:
		t.Fatalf("invalid reply address type %d", header[3])
	}
	if _, err := io.CopyN(io.Discard, connection, int64(length+2)); err != nil {
		t.Fatalf("read reply address: %v", err)
	}
	return header[1]
}

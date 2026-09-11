// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/gorilla/websocket"
)

func TestWebSocketPacketChannelHTTPTestServerRoundTrip(t *testing.T) {
	packet := protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: 22, PacketType: protocol.PacketTypeData},
		Payload: []byte("websocket packet"),
	}
	wireBody := make(chan []byte, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		messageType, body, err := connection.ReadMessage()
		if err == nil && messageType != websocket.BinaryMessage {
			err = errors.New("websocket message was not binary")
		}
		if err != nil {
			t.Errorf("server websocket channel: %v", err)
			return
		}
		wireBody <- body
		if err := connection.WriteMessage(websocket.BinaryMessage, body); err != nil {
			t.Errorf("server websocket channel: %v", err)
		}
	}))
	defer server.Close()

	client, err := DialWebSocket(context.Background(), "ws"+server.URL[len("http"):])
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Send(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	body := <-wireBody
	if len(body) != protocol.PeerManagerHeaderSize+len(packet.Payload) || binary.LittleEndian.Uint32(body[:4]) != packet.Header.FromPeerID {
		t.Fatalf("wire body = %d bytes with prefix %d, want peer body with first field %d", len(body), binary.LittleEndian.Uint32(body[:4]), packet.Header.FromPeerID)
	}
	got, err := client.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Header != (protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: 22, PacketType: protocol.PacketTypeData, Length: 16}) || string(got.Payload) != string(packet.Payload) {
		t.Fatalf("packet = %#v, want %#v", got, packet)
	}
}

func TestWebSocketPacketChannelRejectsMalformedAndOversizeMessages(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
		limit   int
	}{
		{name: "malformed", message: make([]byte, protocol.PeerManagerHeaderSize+1), limit: 128},
		{name: "oversize", message: make([]byte, 33), limit: 32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				connection, err := upgrader.Upgrade(writer, request, nil)
				if err != nil {
					return
				}
				channel, err := NewWebSocketPacketChannel(connection, test.limit)
				if err != nil {
					return
				}
				defer channel.Close()
				if _, err := channel.Receive(context.Background()); err == nil {
					t.Errorf("Receive accepted %s message", test.name)
				}
			}))
			defer server.Close()

			connection, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := connection.WriteMessage(websocket.BinaryMessage, test.message); err != nil {
				t.Fatal(err)
			}
			_ = connection.Close()
		})
	}
}

func TestWebSocketListenerLoopbackAndControls(t *testing.T) {
	listener, err := ListenWebSocket("127.0.0.1:0", WebSocketOptions{
		CheckOrigin: func(request *http.Request) bool {
			return request.Header.Get("Origin") == "https://allowed.example" && request.Header.Get("X-EasyTier-Test") == "present"
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- listener.Serve(context.Background()) }()
	defer func() {
		_ = listener.Close()
		if err := <-serveResult; err != nil {
			t.Errorf("Serve error: %v", err)
		}
	}()

	client, err := DialWebSocket(context.Background(), listener.URL(), WebSocketOptions{
		Origin: "https://allowed.example",
		Header: http.Header{"X-EasyTier-Test": []string{"present"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	packet := protocol.Packet{Payload: []byte("loopback")}
	if err := client.Send(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	got, err := server.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != "loopback" {
		t.Fatalf("payload = %q", got.Payload)
	}
}

func TestWebSocketListenerTLSPacketRoundTrip(t *testing.T) {
	certificateServer := httptest.NewTLSServer(nil)
	serverTLSConfig := certificateServer.TLS.Clone()
	certificateServer.Close()

	listener, err := ListenWebSocket("127.0.0.1:0", WebSocketOptions{
		TLSServerConfig: serverTLSConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- listener.Serve(context.Background()) }()
	defer func() {
		_ = listener.Close()
		if err := <-serveResult; err != nil {
			t.Errorf("Serve error: %v", err)
		}
	}()

	if got := listener.URL()[:4]; got != "wss:" {
		t.Fatalf("listener URL scheme = %q, want wss:", got)
	}
	client, err := DialWebSocket(context.Background(), listener.URL(), WebSocketOptions{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test certificate is self-signed
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	packet := protocol.Packet{Payload: []byte("secure loopback")}
	if err := client.Send(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	got, err := server.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != string(packet.Payload) {
		t.Fatalf("payload = %q, want %q", got.Payload, packet.Payload)
	}
}

func TestWebSocketPacketChannelReceiveHonorsCancellation(t *testing.T) {
	clientConnection, serverConnection := websocketPipe(t)
	client, err := NewWebSocketPacketChannel(clientConnection, 0)
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

func websocketPipe(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	connections := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upgrader := websocket.Upgrader{}
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		connections <- connection
	}))
	t.Cleanup(server.Close)
	client, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case serverConnection := <-connections:
		return client, serverConnection
	case <-time.After(time.Second):
		_ = client.Close()
		t.Fatal("websocket server did not accept connection")
		return nil, nil
	}
}

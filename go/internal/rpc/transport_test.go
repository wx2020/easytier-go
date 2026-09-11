// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestManagementRPCServerLoopbackResponse(t *testing.T) {
	server := newTestServer(t, "127.0.0.0/8", func(_ context.Context, request RpcPacket) (RpcPacket, error) {
		if request.Body == nil {
			t.Fatal("handler received no request body")
		}
		return RpcPacket{
			Descriptor:  request.Descriptor,
			Body:        append([]byte("response:"), request.Body...),
			TotalPieces: request.TotalPieces,
			PieceIdx:    request.PieceIdx,
			TraceID:     request.TraceID,
		}, nil
	})
	serveServer(t, server)

	request := RpcPacket{
		FromPeer:      10,
		ToPeer:        20,
		TransactionID: 30,
		Descriptor:    &RpcDescriptor{ServiceName: "management", MethodIndex: 1},
		Body:          []byte("request"),
		IsRequest:     true,
		TotalPieces:   1,
		TraceID:       40,
	}
	response, err := Call(context.Background(), server.Addr().String(), request)
	if err != nil {
		t.Fatal(err)
	}
	want := RpcPacket{
		FromPeer:      request.ToPeer,
		ToPeer:        request.FromPeer,
		TransactionID: request.TransactionID,
		Descriptor:    request.Descriptor,
		Body:          []byte("response:request"),
		TotalPieces:   request.TotalPieces,
		TraceID:       request.TraceID,
	}
	if !reflect.DeepEqual(response, want) {
		t.Fatalf("response = %#v, want %#v", response, want)
	}
}

func TestManagementRPCServerRejectsDeniedSource(t *testing.T) {
	called := make(chan struct{}, 1)
	server := newTestServer(t, "192.0.2.0/24", func(context.Context, RpcPacket) (RpcPacket, error) {
		called <- struct{}{}
		return RpcPacket{}, nil
	})
	serveServer(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Call(ctx, server.Addr().String(), RpcPacket{IsRequest: true})
	if err == nil {
		t.Fatal("Call from denied loopback source succeeded")
	}
	select {
	case <-called:
		t.Fatal("handler was called for denied source")
	default:
	}
}

func TestManagementRPCCallCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = Call(ctx, listener.Addr().String(), RpcPacket{
		IsRequest:  true,
		Descriptor: &RpcDescriptor{ServiceName: "management"},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call error = %v, want %v", err, context.DeadlineExceeded)
	}
	select {
	case connection := <-accepted:
		_ = connection.Close()
	case <-time.After(time.Second):
		t.Fatal("server did not accept client connection")
	}
}

func TestManagementRPCFragmentsRequestAndResponse(t *testing.T) {
	const bodySize = 8 * 1024
	server := newTestServer(t, "127.0.0.0/8", func(_ context.Context, request RpcPacket) (RpcPacket, error) {
		if len(request.Body) != bodySize {
			return RpcPacket{}, errors.New("request was not reassembled")
		}
		return RpcPacket{
			Descriptor: request.Descriptor,
			Body:       append([]byte("reply:"), request.Body...),
		}, nil
	})
	serveServer(t, server)

	request := RpcPacket{
		FromPeer:      1,
		ToPeer:        2,
		TransactionID: 9,
		Descriptor:    &RpcDescriptor{ServiceName: "management", MethodIndex: 4},
		Body:          bytes.Repeat([]byte("x"), bodySize),
		IsRequest:     true,
	}
	response, err := Call(context.Background(), server.Addr().String(), request)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Body) != "reply:"+string(request.Body) || response.TotalPieces != 1 || response.PieceIdx != 0 {
		t.Fatalf("response body/pieces = %d/%d/%d", len(response.Body), response.TotalPieces, response.PieceIdx)
	}
}

func TestManagementRPCHandlerErrorIsReturnedAsResponse(t *testing.T) {
	server := newTestServer(t, "127.0.0.0/8", func(context.Context, RpcPacket) (RpcPacket, error) {
		return RpcPacket{}, errors.New("service rejected request")
	})
	serveServer(t, server)

	response, err := Call(context.Background(), server.Addr().String(), RpcPacket{
		FromPeer:   1,
		ToPeer:     2,
		Descriptor: &RpcDescriptor{ServiceName: "management", MethodIndex: 1},
		IsRequest:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Body) != `{"error":"service rejected request"}` {
		t.Fatalf("error response = %s", response.Body)
	}
}

func newTestServer(t *testing.T, cidr string, handler Handler) *Server {
	t.Helper()
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer([]netip.Prefix{prefix}, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func serveServer(t *testing.T, server *Server) {
	t.Helper()
	go func() {
		if err := server.Serve(context.Background()); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
}

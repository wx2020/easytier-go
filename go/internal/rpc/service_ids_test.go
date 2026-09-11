// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestServiceIDsMirrorRust(t *testing.T) {
	cases := map[uint32]string{
		ServiceIDPeerCenter:         "peer_center",
		ServiceIDOSPFRoute:          ServiceNameOSPFRoute,
		ServiceIDHolePunchConnector: ServiceNameHolePunch,
	}
	for id, want := range cases {
		got, ok := ServiceNameForID(id)
		if !ok || got != want {
			t.Fatalf("ServiceNameForID(%d) = %q, %v; want %q", id, got, ok, want)
		}
	}
	if _, ok := ServiceNameForID(999); ok {
		t.Fatal("unknown service ID must not resolve")
	}
}

func TestFuncServiceDispatch(t *testing.T) {
	service := NewFuncService("test")
	if service.ServiceName() != "test" {
		t.Fatalf("service name = %q", service.ServiceName())
	}
	service.OnMethod(3, func(_ context.Context, from uint32, body []byte) ([]byte, error) {
		return append([]byte("ack:"), body...), nil
	})
	resp, err := service.HandleMethod(3, context.Background(), 7, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != "ack:hi" {
		t.Fatalf("response = %q", resp)
	}
	if _, err := service.HandleMethod(4, context.Background(), 7, nil); err == nil {
		t.Fatal("unregistered method must fail")
	}
}

func TestCallJSONRoundTrip(t *testing.T) {
	linkA := &memLink{myPeerID: 1, peerID: 2, outbound: make(chan protocol.Packet, 16)}
	linkB := &memLink{myPeerID: 2, peerID: 1, outbound: make(chan protocol.Packet, 16)}
	linkA.sendTo = linkB
	linkB.sendTo = linkA

	mgrA, err := NewPeerRpcManager(linkA)
	if err != nil {
		t.Fatal(err)
	}
	defer mgrA.Close()
	mgrB, err := NewPeerRpcManager(linkB)
	if err != nil {
		t.Fatal(err)
	}
	defer mgrB.Close()

	type request struct {
		Name string `json:"name"`
	}
	type response struct {
		Greeting string `json:"greeting"`
	}
	service := NewFuncService("greet")
	service.OnMethod(0, JSONMethod(func(_ context.Context, _ uint32, req request) (response, error) {
		return response{Greeting: "hello " + req.Name}, nil
	}))
	if err := mgrB.Register("mesh", service); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		for packet := range linkA.outbound {
			_ = mgrB.HandlePacket(context.Background(), packet)
		}
	}()
	go func() {
		for packet := range linkB.outbound {
			_ = mgrA.HandlePacket(context.Background(), packet)
		}
	}()

	resp, err := CallJSON[response](ctx, mgrA, 2, "mesh", "greet", 0, request{Name: "world"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Greeting != "hello world" {
		t.Fatalf("greeting = %q", resp.Greeting)
	}
}

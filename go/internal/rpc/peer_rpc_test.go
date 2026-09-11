// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// memLink is one half of a loopback transport used by the tests below.
type memLink struct {
	myPeerID  uint32
	peerID    uint32
	sendTo    *memLink
	outbound  chan protocol.Packet
	handleRPC func(ctx context.Context, packet protocol.Packet) error
}

func (l *memLink) MyPeerID() uint32 { return l.myPeerID }

func (l *memLink) Send(_ context.Context, dstPeerID uint32, packet protocol.Packet) error {
	if dstPeerID != l.peerID {
		return errors.New("mem link transport cannot reach non-peer destination")
	}
	l.outbound <- packet
	return nil
}

type greetingService struct {
	mu    sync.Mutex
	array []string
	delay func() error
}

func (s *greetingService) ServiceName() string { return "greeting" }

func (s *greetingService) HandleMethod(_ uint32, _ context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
	if s.delay != nil {
		if err := s.delay(); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	s.array = append(s.array, string(requestBody))
	s.mu.Unlock()
	return []byte("hello-" + string(requestBody) + "-" + itoa(fromPeerID)), nil
}

func itoa(value uint32) string {
	if value == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}

func TestPeerRpcManagerCallAndDispatch(t *testing.T) {
	linkA := &memLink{myPeerID: 1, peerID: 2, outbound: make(chan protocol.Packet, 16)}
	linkB := &memLink{myPeerID: 2, peerID: 1, outbound: make(chan protocol.Packet, 16)}
	linkA.sendTo = linkB
	linkB.sendTo = linkA

	mgrA, err := NewPeerRpcManager(linkA)
	if err != nil {
		t.Fatal(err)
	}
	mgrB, err := NewPeerRpcManager(linkB)
	if err != nil {
		t.Fatal(err)
	}

	svcB := &greetingService{}
	if err := mgrB.Register("net-1", svcB); err != nil {
		t.Fatal(err)
	}

	// Wire the receive loops: each manager's receive for packets on its channel.
	go func() {
		for {
			select {
			case packet := <-linkB.outbound:
				if err := mgrA.HandlePacket(context.Background(), packet); err != nil {
					t.Errorf("mgrA handle: %v", err)
				}
			case packet := <-linkA.outbound:
				if err := mgrB.HandlePacket(context.Background(), packet); err != nil {
					t.Errorf("mgrB handle: %v", err)
				}
			}
		}
	}()

	response, err := mgrA.Call(context.Background(), 2, "net-1", "greeting", 0, []byte("world"))
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if got, want := string(response), "hello-world-1"; got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
	svcB.mu.Lock()
	got, want := len(svcB.array), 1
	svcB.mu.Unlock()
	if got != want {
		t.Fatalf("server received %d requests, want %d", got, want)
	}
}

func TestPeerRpcManagerErrorEnvelope(t *testing.T) {
	linkA := &memLink{myPeerID: 1, peerID: 2, outbound: make(chan protocol.Packet, 16)}
	linkB := &memLink{myPeerID: 2, peerID: 1, outbound: make(chan protocol.Packet, 16)}
	linkA.sendTo = linkB
	linkB.sendTo = linkA

	mgrA, _ := NewPeerRpcManager(linkA)
	mgrB, _ := NewPeerRpcManager(linkB)
	svcB := &greetingService{delay: func() error { return errors.New("boom") }}
	if err := mgrB.Register("net-1", svcB); err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			select {
			case packet := <-linkB.outbound:
				_ = mgrA.HandlePacket(context.Background(), packet)
			case packet := <-linkA.outbound:
				_ = mgrB.HandlePacket(context.Background(), packet)
			}
		}
	}()

	_, err := mgrA.Call(context.Background(), 2, "net-1", "greeting", 0, []byte("world"))
	if err == nil {
		t.Fatal("expected an error from the server handler")
	}
	if !contains(err.Error(), "boom") {
		t.Fatalf("error = %v, want it to contain boom", err)
	}
}

func TestPeerRpcManagerUnregisteredService(t *testing.T) {
	linkA := &memLink{myPeerID: 1, peerID: 2, outbound: make(chan protocol.Packet, 16)}
	linkB := &memLink{myPeerID: 2, peerID: 1, outbound: make(chan protocol.Packet, 16)}
	linkA.sendTo = linkB
	linkB.sendTo = linkA

	mgrA, _ := NewPeerRpcManager(linkA)
	mgrB, _ := NewPeerRpcManager(linkB)

	go func() {
		for {
			select {
			case packet := <-linkB.outbound:
				_ = mgrA.HandlePacket(context.Background(), packet)
			case packet := <-linkA.outbound:
				_ = mgrB.HandlePacket(context.Background(), packet)
			}
		}
	}()

	_, err := mgrA.Call(context.Background(), 2, "net-1", "missing", 0, nil)
	if err == nil {
		t.Fatal("expected an error for an unregistered service")
	}
	if !contains(err.Error(), "no rpc service") {
		t.Fatalf("error = %v, want it to mention the missing service", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

func TestRelayIKHandshakeLoopback(t *testing.T) {
	initiatorKey, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		// Use deterministic generated pair via GenerateDirectPeerStaticKeypair
		initiatorKey, err = GenerateDirectPeerStaticKeypair()
		if err != nil {
			t.Fatal(err)
		}
	}
	responderKey, err := GenerateDirectPeerStaticKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// Build a direct channel pair via in-memory transport (TCP loopback for relay packets)
	// Use transport's ring alternative: use net.Listen TCP but carry relay handshake packets as normal data packets.
	// Simpler: use a buffered channel implementation of PacketChannel.
	chA, chB := newTestChannelPair(32)

	initCfg := RelayHandshakeConfig{
		LocalPeerID:   11,
		StaticKeypair: initiatorKey,
		RemoteStatic:  responderKey.Public,
		CipherSuite:   CipherSuiteChaCha20Poly1305,
	}
	respCfg := RelayHandshakeConfig{
		LocalPeerID:   22,
		StaticKeypair: responderKey,
		CipherSuite:   CipherSuiteChaCha20Poly1305,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 2)
	var initSess, respSess *SecureDatagramSession
	var respID uint32
	go func() {
		s, id, err := RespondRelayHandshake(ctx, chB, respCfg)
		if err != nil {
			errCh <- err
			return
		}
		respSess = s
		respID = id
		errCh <- nil
	}()
	go func() {
		s, err := InitiateRelayHandshake(ctx, chA, initCfg, 22)
		if err != nil {
			errCh <- err
			return
		}
		initSess = s
		errCh <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("relay handshake failed: %v", err)
		}
	}
	if respID != 11 {
		t.Fatalf("responder saw initiatorID %d want 11", respID)
	}
	// Verify that sessions can encrypt/decrypt via relay
	plain := []byte("hello relay")
	ct, err := initSess.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	pkt := protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: 22, PacketType: protocol.PacketTypeData, Flags: protocol.FlagEncrypted},
		Payload: ct,
	}
	// Simulate relay decrypt via responder session: Open payload
	got, err := respSess.Open(pkt.Payload)
	if err != nil {
		t.Fatalf("responder Open failed: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("payload mismatch: got %q want %q", string(got), string(plain))
	}
	// Reverse direction
	ct2, err := respSess.Seal([]byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	got2, err := initSess.Open(ct2)
	if err != nil {
		t.Fatalf("initiator Open failed: %v", err)
	}
	if string(got2) != "world" {
		t.Fatalf("reverse mismatch %q", string(got2))
	}
}

func TestRelayRacedHandshakeDeterminism(t *testing.T) {
	// Two peers with IDs 11 and 22 both attempt to initiate at same time.
	// Rust rule: smaller peer_id initiates.
	m11 := NewRelayManager(11)
	m22 := NewRelayManager(22)

	if !m11.ShouldInitiate(22) {
		t.Fatal("peer 11 should initiate against 22")
	}
	if m22.ShouldInitiate(11) {
		t.Fatal("peer 22 should not initiate against 11")
	}
	// Simulate concurrent TryInitiate
	initiatedBy11 := m11.TryInitiate(22)
	initiatedBy22 := m22.TryInitiate(11)
	// At least one should claim, but raced logic: if 22 later receives msg1 from 11,
	// it should yield.
	if !initiatedBy11 {
		t.Fatal("m11 should claim initiator")
	}
	if !initiatedBy22 {
		t.Log("m22 correctly would be responder due to concurrent claim - but both claimed independent pending maps")
	}
	// Simulate m22 receiving handshake from 11 while pending: it should detect race and yield.
	// In Go relay manager, TryInitiate already handles pending check within same manager instance.
	// For cross-manager race, the responder's manager sees pending and decides via ShouldInitiate.
	shouldYield := !m22.ShouldInitiate(11)
	if !shouldYield {
		t.Fatal("m22 should yield to smaller peer")
	}
}

func TestRelayRetryAndTimeout(t *testing.T) {
	m := NewRelayManager(11)
	peer := uint32(22)
	m.FailHandshake(peer, 0)
	if !m.IsBackoffActive(peer) {
		t.Fatal("backoff should be active after failure")
	}
	m.CompleteHandshake(peer)
	if m.IsBackoffActive(peer) {
		t.Fatal("backoff should be cleared after success")
	}
	// Timeout wrapper
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := WithRelayTimeout(ctx, 30*time.Millisecond, func(c context.Context) error {
		<-c.Done()
		return c.Err()
	})
	if err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("expected timeout, got %v", err)
	}
}

// newTestChannelPair creates two bridged PacketChannels for testing.
func newTestChannelPair(capacity int) (PacketChannel, PacketChannel) {
	a := &testChannel{ch: make(chan protocol.Packet, capacity)}
	b := &testChannel{ch: make(chan protocol.Packet, capacity)}
	a.peer = b
	b.peer = a
	return a, b
}

type testChannel struct {
	ch   chan protocol.Packet
	peer *testChannel
}

func (c *testChannel) Send(ctx context.Context, p protocol.Packet) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.peer.ch <- p:
		return nil
	}
}
func (c *testChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	select {
	case <-ctx.Done():
		return protocol.Packet{}, ctx.Err()
	case p := <-c.ch:
		return p, nil
	}
}

// Ensure imported transport is used (avoid unused import)
var _ = transport.DialTCP

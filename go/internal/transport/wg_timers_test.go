// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// withWGTimers shrinks the routine timers for the test duration.
func withWGTimers(t *testing.T, timers wgSessionTimers, fn func()) {
	t.Helper()
	original := wgTimers
	wgTimers = timers.clamped()
	defer func() { wgTimers = original }()
	fn()
}

// withWGIdleTTL shrinks the listener idle-peer recycle window.
func withWGIdleTTL(t *testing.T, ttl time.Duration, fn func()) {
	t.Helper()
	original := wgPeerIdleTTL
	wgPeerIdleTTL = ttl
	defer func() { wgPeerIdleTTL = original }()
	fn()
}

func TestWGRoutineHandshakeAndKeepalive(t *testing.T) {
	withWGTimers(t, wgSessionTimers{
		keepalive:    120 * time.Millisecond,
		rekeyAfter:   200 * time.Millisecond,
		rekeyTimeout: 100 * time.Millisecond,
		rekeyAttempt: 2 * time.Second,
	}, func() {
		cfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
		if err != nil {
			t.Fatal(err)
		}
		svc, err := ListenWGWithCrypto("127.0.0.1:0", &cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer svc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go svc.Serve(ctx)

		accepted := make(chan *WGSession, 1)
		go func() {
			sess, err := svc.Accept(ctx)
			if err == nil {
				accepted <- sess
			}
		}()

		clientCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
		if err != nil {
			t.Fatal(err)
		}
		client, err := DialWGWithCrypto(ctx, svc.Address().String(), &clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()

		// The routine task must complete the initial handshake without any
		// explicit Handshake call (the oracle handshakes during connect).
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if client.handshaked.Load() {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !client.handshaked.Load() {
			t.Fatal("routine task did not complete the initial handshake")
		}
		if client.crypto.SendEpoch() == 0 {
			t.Fatal("handshake must rotate the epoch away from the static keys")
		}
		var server *WGSession
		select {
		case server = <-accepted:
		case <-time.After(2 * time.Second):
			t.Fatal("server never accepted the session")
		}
		defer server.Close()

		// With both peers silent, keepalives must flow in both directions
		// (each side's keepalive keeps the peer's lastRecv fresh).
		deadline = time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if client.keepalivesSent.Load() > 0 && server.keepalivesRecv.Load() > 0 &&
				server.keepalivesSent.Load() > 0 && client.keepalivesRecv.Load() > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if client.keepalivesSent.Load() == 0 || server.keepalivesRecv.Load() == 0 {
			t.Fatalf("client keepalives not exchanged: sent=%d serverRecv=%d",
				client.keepalivesSent.Load(), server.keepalivesRecv.Load())
		}
		if server.keepalivesSent.Load() == 0 || client.keepalivesRecv.Load() == 0 {
			t.Fatalf("server keepalives not exchanged: sent=%d clientRecv=%d",
				server.keepalivesSent.Load(), client.keepalivesRecv.Load())
		}

		// The initiator must rekey once REKEY_AFTER_TIME elapses: the epoch
		// moves again while traffic keeps flowing.
		before := client.crypto.SendEpoch()
		deadline = time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if client.crypto.SendEpoch() != before {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if client.crypto.SendEpoch() == before {
			t.Fatal("initiator did not rekey after REKEY_AFTER_TIME")
		}
		// The responder must have adopted the rekeyed key: a round trip
		// still decrypts on both sides.
		if err := client.Send(ctx, protocol.Packet{
			Header:  protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: 22, PacketType: protocol.PacketTypeData},
			Payload: []byte("after-rekey"),
		}); err != nil {
			t.Fatal(err)
		}
		pkt, err := server.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if string(pkt.Payload) != "after-rekey" {
			t.Fatalf("payload mismatch %q", string(pkt.Payload))
		}
	})
}

func TestWGRoutineAbandonsUnresponsivePeer(t *testing.T) {
	withWGTimers(t, wgSessionTimers{
		keepalive:    5 * time.Second,
		rekeyAfter:   5 * time.Second,
		rekeyTimeout: 50 * time.Millisecond,
		rekeyAttempt: 250 * time.Millisecond,
	}, func() {
		// A bound but silent socket: handshakes never receive a response.
		blackhole, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer blackhole.Close()

		cfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client, err := DialWGWithCrypto(ctx, blackhole.LocalAddr().String(), &cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if client.isClosedSession() {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !client.isClosedSession() {
			t.Fatal("session must be abandoned after REKEY_ATTEMPT_TIME without a response")
		}
		err = client.Send(ctx, protocol.Packet{
			Header:  protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: 22, PacketType: protocol.PacketTypeData},
			Payload: []byte("x"),
		})
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("send on abandoned session: got %v, want net.ErrClosed", err)
		}
	})
}

func TestWGIdleServerSessionRecycled(t *testing.T) {
	withWGIdleTTL(t, 300*time.Millisecond, func() {
		cfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
		if err != nil {
			t.Fatal(err)
		}
		svc, err := ListenWGWithCrypto("127.0.0.1:0", &cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer svc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go svc.Serve(ctx)

		clientCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
		if err != nil {
			t.Fatal(err)
		}
		client, err := DialWGWithCrypto(ctx, svc.Address().String(), &clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			svc.mu.Lock()
			count := len(svc.sessions)
			svc.mu.Unlock()
			if count > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		svc.mu.Lock()
		count := len(svc.sessions)
		svc.mu.Unlock()
		if count == 0 {
			t.Fatal("server session was never created")
		}

		// After the idle TTL with no traffic the janitor must recycle it.
		deadline = time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			svc.mu.Lock()
			count = len(svc.sessions)
			svc.mu.Unlock()
			if count == 0 {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		svc.mu.Lock()
		defer svc.mu.Unlock()
		if len(svc.sessions) != 0 {
			t.Fatalf("idle server session not recycled: %d remain", len(svc.sessions))
		}
	})
}

func TestWGCryptoRejectsExpiredKeys(t *testing.T) {
	cfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewWgCryptoState(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if state.isExpired(time.Now()) {
		t.Fatal("fresh state must not be expired")
	}
	// Force REJECT_AFTER_TIME to elapse since establishment.
	state.mu.Lock()
	state.established = time.Now().Add(-wgRejectAfterTime - time.Second)
	state.mu.Unlock()

	if _, err := state.Seal([]byte("payload")); !errors.Is(err, ErrWGSessionExpired) {
		t.Fatalf("seal with expired keys: got %v", err)
	}
	state.AdoptSessionKey([32]byte{1})
	// AdoptSessionKey restarts the window, so sealing works again.
	if _, err := state.Seal([]byte("payload")); err != nil {
		t.Fatalf("seal after adopt: %v", err)
	}
	if state.isExpired(time.Now()) {
		t.Fatal("adopted key must restart the expiry window")
	}
}

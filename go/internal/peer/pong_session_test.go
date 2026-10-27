// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// TestDeliverPongSameSessionCounts pins the session-scoped pong rule: a pong
// that arrives on the pinged peer's own session is a valid round trip and
// completes the pending ping.
func TestDeliverPongSameSessionCounts(t *testing.T) {
	manager := newPingerTestManager(t, 1)
	pinger := manager.pingerFor(2)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := pinger.doPingPongOnce(pinger.ctx, 5); err != nil {
			t.Errorf("same-session pong rejected: %v", err)
		}
	}()
	time.Sleep(30 * time.Millisecond)
	manager.deliverPong(newPongPacket(2, 1, 5), 2)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("same-session pong did not complete the ping")
	}
}

// TestDeliverPongRelayedSessionIgnored pins the 2026-10-27 half-open-session
// fix: a pong that arrives on any other session (a relay answered the ping)
// must not complete the round trip. Otherwise a dead hole-punch session never
// reaches the five-consecutive-loss disconnect because every ping "succeeds"
// through the relay, and routed traffic keeps entering the dead link.
func TestDeliverPongRelayedSessionIgnored(t *testing.T) {
	manager := newPingerTestManager(t, 1)
	pinger := manager.pingerFor(2)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(pinger.ctx, 300*time.Millisecond)
		defer cancel()
		if _, err := pinger.doPingPongOnce(ctx, 6); err == nil {
			t.Errorf("relayed pong accepted as a round trip")
		}
	}()
	time.Sleep(30 * time.Millisecond)
	// The same sequence answered through session 9 (a relay): must be
	// ignored even though a pinger is waiting for that sequence.
	manager.deliverPong(newPongPacket(2, 1, 6), 9)
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatalf("ping did not time out after a relayed-only answer")
	}
}

func newPingerTestManager(t *testing.T, localPeerID uint32) *PeerConnectionManager {
	t.Helper()
	manager, err := NewPeerConnectionManager(PeerConnectionManagerConfig{
		LocalPeerID:    localPeerID,
		HandshakeMode:  HandshakeModeLegacy,
		LegacyIdentity: LegacyIdentity{PeerID: localPeerID, NetworkName: "pong-session-test"},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	// A mock session for peer 2 so the ping send path succeeds, plus the
	// pinger under test. deliverPong routes by the pinger table; a real
	// channel is not needed to verify pong session scoping.
	manager.mu.Lock()
	manager.peers[2] = &PeerSession{PeerID: 2, Channel: &mockChannel{}}
	manager.mu.Unlock()
	pinger, err := NewPeerConnPinger(PeerConnPingerConfig{
		MyPeerID: localPeerID,
		PeerID:   2,
		Manager:  manager,
	})
	if err != nil {
		t.Fatalf("pinger: %v", err)
	}
	manager.mu.Lock()
	manager.pingers[2] = pinger
	manager.mu.Unlock()
	return manager
}

var _ = protocol.PacketTypePong

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestWindowLatencyRecordAndAverage(t *testing.T) {
	window := NewWindowLatency(3)
	if got := window.Average(); got != 0 {
		t.Fatalf("empty window average = %v, want 0", got)
	}

	window.Record(1)
	window.Record(2)
	window.Record(3)
	if got := window.Average(); got != 2 {
		t.Fatalf("average = %v, want 2", got)
	}

	// window is full; new sample overwrites the oldest.
	window.Record(10)
	if got := window.Average(); got != 5 {
		t.Fatalf("average after overflow = %v, want 5", got)
	}
}

func TestPingIntervalControllerResetsOnLoss(t *testing.T) {
	throughput := &ThroughputSnapshot{}
	lossCount := &atomic.Uint32{}
	controller := &pingIntervalController{
		throughput:      throughput,
		lossCount:       lossCount,
		maxBackoffIdx:   maxBackoffIdx,
		logicTime:       10,
		lastSendLogicTime: 0,
	}

	// loss causes the backoff to reset to zero, producing an immediate ping.
	lossCount.Add(1)
	if !controller.shouldSendPing() {
		t.Fatalf("expected ping when loss count is non-zero")
	}
	if controller.backoffIdx != 1 {
		t.Fatalf("backoffIdx = %d, want 1 after a send", controller.backoffIdx)
	}

	// Immediately after sending, backoff has grown so no ping is sent.
	lossCount.Store(0)
	controller.logicTime = 11
	if controller.shouldSendPing() {
		t.Fatalf("expected no ping when within backoff window")
	}
}

func TestPingIntervalControllerSendsWhenTXWithoutRX(t *testing.T) {
	throughput := &ThroughputSnapshot{}
	controller := &pingIntervalController{
		throughput:      throughput,
		lossCount:       &atomic.Uint32{},
		maxBackoffIdx:   maxBackoffIdx,
		logicTime:       10,
		lastSendLogicTime: 0,
		lastTXPackets:   100,
		lastRXPackets:   100,
	}

	// TX grew but RX did not: ping more frequently.
	throughput.txPackets.Store(120)
	if !controller.shouldSendPing() {
		t.Fatalf("expected ping when TX increases without RX increase")
	}
}

// mockChannel records sent packets. Receive blocks until ctx completes.
type mockChannel struct {
	sent []protocol.Packet
}

func (m *mockChannel) Send(ctx context.Context, packet protocol.Packet) error {
	m.sent = append(m.sent, packet)
	return nil
}

func (m *mockChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	<-ctx.Done()
	return protocol.Packet{}, ctx.Err()
}

func newPingerWithMockPeer(t *testing.T, myPeerID, peerID uint32) (*PeerConnPinger, *mockChannel) {
	t.Helper()
	manager, err := NewPeerConnectionManager(PeerConnectionManagerConfig{
		LocalPeerID: myPeerID,
		HandshakeMode: HandshakeModeLegacy,
		LegacyIdentity: LegacyIdentity{PeerID: myPeerID, NetworkName: "test-net"},
	})
	if err != nil {
		t.Fatalf("NewPeerConnectionManager: %v", err)
	}
	channel := &mockChannel{}
	manager.mu.Lock()
	manager.peers[peerID] = &PeerSession{PeerID: peerID, Channel: channel}
	manager.mu.Unlock()

	pinger, err := NewPeerConnPinger(PeerConnPingerConfig{
		MyPeerID: myPeerID,
		PeerID:   peerID,
		Manager:  manager,
	})
	if err != nil {
		t.Fatalf("NewPeerConnPinger: %v", err)
	}
	return pinger, channel
}

func TestPeerConnPingerMatchesSequence(t *testing.T) {
	pinger, _ := newPingerWithMockPeer(t, 1, 2)

	done := make(chan struct{})
	go func() {
		defer close(done)
		duration, err := pinger.doPingPongOnce(pinger.ctx, 99)
		if err != nil {
			t.Errorf("doPingPongOnce: %v", err)
			return
		}
		if duration <= 0 {
			t.Errorf("latency = %v, want > 0", duration)
		}
	}()

	time.Sleep(50 * time.Millisecond)
	pinger.HandlePong(newPongPacket(2, 1, 99))
	<-done
}

func TestPeerConnPingerIgnoresWrongSequence(t *testing.T) {
	pinger, _ := newPingerWithMockPeer(t, 1, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	go func() {
		time.Sleep(20 * time.Millisecond)
		pinger.HandlePong(newPongPacket(2, 1, 7))
		time.Sleep(20 * time.Millisecond)
		pinger.HandlePong(newPongPacket(2, 1, 42))
	}()

	if _, err := pinger.doPingPongOnce(ctx, 42); err != nil {
		t.Fatalf("doPingPongOnce with correct seq: %v", err)
	}
}

func TestPeerConnPingerTimeout(t *testing.T) {
	pinger, _ := newPingerWithMockPeer(t, 1, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	if _, err := pinger.doPingPongOnce(ctx, 1); err == nil {
		t.Fatalf("expected timeout error")
	}
}

func newPongPacket(fromPeerID, toPeerID, seq uint32) protocol.Packet {
	payload := make([]byte, 4)
	payload[0] = byte(seq)
	payload[1] = byte(seq >> 8)
	payload[2] = byte(seq >> 16)
	payload[3] = byte(seq >> 24)
	return protocol.Packet{
		Header: protocol.PeerManagerHeader{
			FromPeerID: fromPeerID,
			ToPeerID:   toPeerID,
			PacketType: protocol.PacketTypePong,
		},
		Payload: payload,
	}
}
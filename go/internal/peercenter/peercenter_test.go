// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peercenter

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestSelectCenterPeerPicksSmallest(t *testing.T) {
	routes := []PeerRoute{
		{PeerID: 5},
		{PeerID: 2},
		{PeerID: 9},
		{PeerID: 1, IsPublicServer: true},
	}
	if got := SelectCenterPeer(7, routes); got != 2 {
		t.Fatalf("center = %d, want 2 (public servers and self excluded)", got)
	}
}

func TestSelectCenterPeerFallsBackToSelf(t *testing.T) {
	routes := []PeerRoute{{PeerID: 1, IsPublicServer: true}}
	if got := SelectCenterPeer(7, routes); got != 7 {
		t.Fatalf("center = %d, want own id 7", got)
	}
}

func TestCalcDigestDeterministicAcrossOrder(t *testing.T) {
	pairsA := []SrcDstPeerPair{{Source: 3, Dest: 8}, {Source: 1, Dest: 2}, {Source: 3, Dest: 2}}
	pairsB := []SrcDstPeerPair{{Source: 1, Dest: 2}, {Source: 3, Dest: 2}, {Source: 3, Dest: 8}}

	if got := CalcDigest(pairsA); got != CalcDigest(pairsB) {
		t.Fatalf("digest should be order-independent: %d != %d", got, CalcDigest(pairsB))
	}
	if CalcDigest(pairsA) == CalcDigest(pairsA[:2]) {
		t.Fatalf("digest of different contents collided")
	}
}

func TestServerReportAndDigestMatch(t *testing.T) {
	server := NewServer()
	server.ReportPeers(1, map[uint32]DirectPeerInfo{2: {LatencyMS: 5}})
	server.ReportPeers(3, map[uint32]DirectPeerInfo{2: {LatencyMS: 3}})

	digest := server.CurrentDigest()

	// Requesting with the matching digest returns no-update.
	_, gotDigest, noUpdate := server.GetGlobalPeerMap(digest)
	if !noUpdate {
		t.Fatalf("expected no-update response when digest matches")
	}
	if gotDigest != digest {
		t.Fatalf("returned digest %d != stored %d", gotDigest, digest)
	}

	// Requesting with a stale digest returns the full map.
	got, gotDigest, noUpdate := server.GetGlobalPeerMap(0)
	if noUpdate {
		t.Fatalf("expected full map when digest is stale")
	}
	if len(got) != 2 {
		t.Fatalf("global map size = %d, want 2", len(got))
	}
	if gotDigest != digest {
		t.Fatalf("returned digest %d != stored %d", gotDigest, digest)
	}
}

func TestServerCleanOutdated(t *testing.T) {
	server := NewServer()
	now := time.Now()
	server.ReportPeers(1, map[uint32]DirectPeerInfo{2: {LatencyMS: 5}})

	// No cleanup before the TTL elapses.
	server.CleanOutdated(20*time.Second, now.Add(10*time.Second))
	if got := len(server.GlobalMap()); got != 1 {
		t.Fatalf("map size %d, want 1 before expiry", got)
	}

	// Cleanup after the report is older than the TTL.
	server.CleanOutdated(20*time.Second, now.Add(30*time.Second))
	if got := len(server.GlobalMap()); got != 0 {
		t.Fatalf("map size %d, want 0 after expiry", got)
	}
	if server.CurrentDigest() != 0 {
		t.Fatalf("digest should be zero after clearing")
	}
}

func TestRunnerExecutesPeriodicJob(t *testing.T) {
	var calls atomic.Int32
	runner := NewRunner(1, func() []PeerRoute {
		return []PeerRoute{{PeerID: 2}}
	}, func(ctx context.Context, center uint32) JobResult {
		calls.Add(1)
		return JobResult{SleepTime: 10 * time.Millisecond}
	})

	runner.Start()
	time.Sleep(45 * time.Millisecond)
	runner.Stop()

	if got := calls.Load(); got < 2 {
		t.Fatalf("job calls = %d, want at least 2", got)
	}
}

func TestRunnerStopsOnContext(t *testing.T) {
	var calls atomic.Int32
	runner := NewRunner(1, nil, func(ctx context.Context, center uint32) JobResult {
		calls.Add(1)
		return JobResult{SleepTime: time.Second}
	})

	runner.Start()
	time.Sleep(20 * time.Millisecond)
	runner.Stop()

	// Stop cancelled the context; no further runs should exceed the first.
	if got := calls.Load(); got > 2 {
		t.Fatalf("job calls after stop = %d, want <= 2", got)
	}
}
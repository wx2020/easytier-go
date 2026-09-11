// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peercenter

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
)

// memLinkTransport is a single-peer loopback RPC transport used by instance
// tests. It forwards packets into the peer RPC manager via HandlePacket.
type memLinkTransport struct {
	myPeerID  uint32
	peerID    uint32
	outbound  chan protocol.Packet
	onReceive func(ctx context.Context, packet protocol.Packet) error
}

func (l *memLinkTransport) MyPeerID() uint32 { return l.myPeerID }

func (l *memLinkTransport) Send(_ context.Context, dstPeerID uint32, packet protocol.Packet) error {
	if dstPeerID != l.peerID {
		return errUnreachable
	}
	l.outbound <- packet
	return nil
}

var errUnreachable = &rpcError{"destination peer is not directly reachable"}

type rpcError struct{ message string }

func (e *rpcError) Error() string { return e.message }

// relayTransport passes every packet to the remote manager's handler.
func relayTransport(ctx context.Context, remote *rpc.PeerRpcManager, link *memLinkTransport) {
	go func() {
		for {
			select {
			case packet := <-link.outbound:
				if err := remote.HandlePacket(ctx, packet); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

type staticProvider struct {
	myPeerID uint32
	direct   map[uint32]DirectPeerInfo
	routes   []PeerRoute
}

func (p *staticProvider) MyPeerID() uint32                           { return p.myPeerID }
func (p *staticProvider) ListDirectPeers() map[uint32]DirectPeerInfo { return p.direct }
func (p *staticProvider) ListRoutes() []PeerRoute                    { return p.routes }

func TestInstanceReportsAndGetsGlobalPeerMap(t *testing.T) {
	linkA := &memLinkTransport{myPeerID: 1, peerID: 2, outbound: make(chan protocol.Packet, 64)}
	linkB := &memLinkTransport{myPeerID: 2, peerID: 1, outbound: make(chan protocol.Packet, 64)}
	linkA.onReceive = linkB.onReceive

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgrA, err := rpc.NewPeerRpcManager(linkA)
	if err != nil {
		t.Fatal(err)
	}
	mgrB, err := rpc.NewPeerRpcManager(linkB)
	if err != nil {
		t.Fatal(err)
	}
	relayTransport(ctx, mgrB, linkA)
	relayTransport(ctx, mgrA, linkB)

	providerA := &staticProvider{
		myPeerID: 1,
		direct:   map[uint32]DirectPeerInfo{2: {LatencyMS: 3}},
		routes:   []PeerRoute{{PeerID: 2}, {PeerID: 1}},
	}
	providerB := &staticProvider{
		myPeerID: 2,
		direct:   map[uint32]DirectPeerInfo{1: {LatencyMS: 3}},
		routes:   []PeerRoute{{PeerID: 1}},
	}

	instanceA, err := NewInstance(providerA, mgrA)
	if err != nil {
		t.Fatal(err)
	}
	instanceB, err := NewInstance(providerB, mgrB)
	if err != nil {
		t.Fatal(err)
	}

	if err := instanceB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := instanceA.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// The smallest non-public peer is the center; here A is the center.
	if got := SelectCenterPeer(providerA.MyPeerID(), providerA.ListRoutes()); got != 1 {
		t.Fatalf("center = %d, want 1", got)
	}

	// B reports to A and A becomes the center with B in its map.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		server := instanceA.Server()
		if server.CurrentDigest() != 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := instanceA.Server().CurrentDigest(); got == 0 {
		t.Fatal("center server did not receive a peer report within the deadline")
	}

	// B eventually fetches the global map from A.
	for time.Now().Before(deadline) {
		if len(instanceB.GlobalPeerMap()) > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	got := instanceB.GlobalPeerMap()
	if _, ok := got[1]; !ok {
		t.Fatalf("global map missing center peer 1: %v", got)
	}
	entry := got[1]
	if info, ok := entry.DirectPeers[2]; !ok || info.LatencyMS != 3 {
		t.Fatalf("center peer 1 direct peer map = %v, want peer 2 with latency 3", entry.DirectPeers)
	}

	instanceA.Stop()
	instanceB.Stop()
}

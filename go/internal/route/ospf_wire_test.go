// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"google.golang.org/protobuf/proto"

	peerrpc "github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
)

// The protobuf envelope must round-trip a Go LSA losslessly: origin, version,
// timestamp, proxy CIDRs and every link cost survive the reference schema.
func TestSyncRequestRoundTrip(t *testing.T) {
	advertisement := Advertisement{
		Origin:     7,
		Version:    9,
		Timestamp:  1700000000,
		Peers:      []PeerCost{{Peer: 3, Cost: 4}, {Peer: 11, Cost: 1}},
		ProxyCIDRs: []string{"10.0.0.0/24", "192.168.1.0/24"},
		UDPNatType: common.NatType_FullCone,
	}
	request, err := syncRequestFromAdvertisement(advertisement, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > MaxSyncRouteInfoRequestSize {
		t.Fatalf("encoded request size %d", len(wire))
	}
	decoded := &peerrpc.SyncRouteInfoRequest{}
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	got, err := advertisementFromSyncRequest(decoded, 99)
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != advertisement.Origin || got.Version != advertisement.Version {
		t.Fatalf("origin/version = %d/%d, want %d/%d", got.Origin, got.Version, advertisement.Origin, advertisement.Version)
	}
	if got.Timestamp != advertisement.Timestamp {
		t.Fatalf("timestamp = %d, want %d", got.Timestamp, advertisement.Timestamp)
	}
	if got.UDPNatType != advertisement.UDPNatType {
		t.Fatalf("udp nat type = %v, want %v", got.UDPNatType, advertisement.UDPNatType)
	}
	if len(got.Peers) != len(advertisement.Peers) {
		t.Fatalf("edges = %d, want %d", len(got.Peers), len(advertisement.Peers))
	}
	for i, peer := range advertisement.Peers {
		if got.Peers[i].Peer != peer.Peer || got.Peers[i].Cost != peer.Cost {
			t.Fatalf("edge %d = %+v, want %+v", i, got.Peers[i], peer)
		}
	}
	if len(got.ProxyCIDRs) != len(advertisement.ProxyCIDRs) {
		t.Fatalf("proxy CIDRs = %v", got.ProxyCIDRs)
	}
}

// The request must decode as the reference message shape: my_peer_id,
// my_session_id, is_initiator, the origin self-description entry (cost 0) and
// one conn-peer-list row for the origin's links.
func TestSyncRequestReferenceShape(t *testing.T) {
	advertisement := Advertisement{
		Origin:  5,
		Version: 2,
		Peers:   []PeerCost{{Peer: 6, Cost: 3}},
	}
	request, err := syncRequestFromAdvertisement(advertisement, 77)
	if err != nil {
		t.Fatal(err)
	}
	if request.GetMyPeerId() != 5 || request.GetMySessionId() != 77 || !request.GetIsInitiator() {
		t.Fatalf("envelope = %+v", request)
	}
	items := request.GetPeerInfos().GetItems()
	if len(items) != 2 {
		t.Fatalf("peer info entries = %d, want origin + 1 link", len(items))
	}
	self := items[0]
	if self.GetPeerId() != 5 || self.GetCost() != 0 || self.GetVersion() != 2 {
		t.Fatalf("origin entry = %+v", self)
	}
	if self.GetLastUpdate() == nil || self.GetLastUpdate().GetSeconds() != advertisement.Timestamp {
		t.Fatalf("origin last_update = %+v", self.GetLastUpdate())
	}
	link := items[1]
	if link.GetPeerId() != 6 || link.GetCost() != 3 {
		t.Fatalf("link entry = %+v", link)
	}
	rows := request.GetConnInfo().(*peerrpc.SyncRouteInfoRequest_ConnPeerList).ConnPeerList.GetPeerConnInfos()
	if len(rows) != 1 || rows[0].GetPeerId().GetPeerId() != 5 {
		t.Fatalf("conn rows = %+v", rows)
	}
	if len(rows[0].GetConnectedPeerIds()) != 1 || rows[0].GetConnectedPeerIds()[0] != 6 {
		t.Fatalf("connected peers = %+v", rows[0].GetConnectedPeerIds())
	}
}

// A reference-style connection bitmap decodes by row: bit (i*len+j) set means
// peer_ids[i] is connected to peer_ids[j].
func TestAdvertisementFromConnBitmap(t *testing.T) {
	peerIDs := []*peerrpc.PeerIdVersion{
		{PeerId: 5}, {PeerId: 6}, {PeerId: 7},
	}
	// Row 0 (origin 5): connected to 6 and 7 → bits 0*3+1 and 0*3+2.
	bitmap := make([]byte, 2)
	bitmap[0] |= 1 << 1
	bitmap[0] |= 1 << 2
	request := &peerrpc.SyncRouteInfoRequest{
		MyPeerId: 5,
		PeerInfos: &peerrpc.RoutePeerInfos{Items: []*peerrpc.RoutePeerInfo{
			{PeerId: 5, Version: 4},
			{PeerId: 6, Cost: 8},
			{PeerId: 7},
		}},
		ConnInfo: &peerrpc.SyncRouteInfoRequest_ConnBitmap{
			ConnBitmap: &peerrpc.RouteConnBitmap{PeerIds: peerIDs, Bitmap: bitmap},
		},
	}
	got, err := advertisementFromSyncRequest(request, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 2 {
		t.Fatalf("edges = %+v", got.Peers)
	}
	if got.Peers[0].Peer != 6 || got.Peers[0].Cost != 8 {
		t.Fatalf("edge 0 = %+v", got.Peers[0])
	}
	if got.Peers[1].Peer != 7 || got.Peers[1].Cost != 1 {
		t.Fatalf("edge 1 = %+v (unknown cost must fall back to 1)", got.Peers[1])
	}
}

// Missing conn info degrades to a node-info-only LSA.
func TestAdvertisementFromNodeInfoOnly(t *testing.T) {
	request := &peerrpc.SyncRouteInfoRequest{
		MyPeerId:  3,
		PeerInfos: &peerrpc.RoutePeerInfos{Items: []*peerrpc.RoutePeerInfo{{PeerId: 3, Version: 1}}},
	}
	got, err := advertisementFromSyncRequest(request, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != 3 || got.Version != 1 || len(got.Peers) != 0 {
		t.Fatalf("LSA = %+v", got)
	}
}

// Zero origins and oversized payloads must be rejected.
func TestSyncRequestValidation(t *testing.T) {
	if _, err := advertisementFromSyncRequest(&peerrpc.SyncRouteInfoRequest{}, 0); err == nil {
		t.Fatal("zero origin must fail")
	}
	oversized := &peerrpc.SyncRouteInfoRequest{MyPeerId: 1}
	items := make([]*peerrpc.RoutePeerInfo, MaxAdvertisementPeers+2)
	for i := range items {
		items[i] = &peerrpc.RoutePeerInfo{PeerId: uint32(i + 1)}
	}
	oversized.PeerInfos = &peerrpc.RoutePeerInfos{Items: items}
	if _, err := advertisementFromSyncRequest(oversized, 1); err == nil {
		t.Fatal("oversized peer list must fail")
	}
}

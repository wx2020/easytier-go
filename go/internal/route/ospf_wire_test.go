// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"google.golang.org/protobuf/proto"

	peerrpc "github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
)

// schema: origin, version, timestamp, proxy CIDRs and NAT type survive;
// link costs do not travel (the reference conn graph is unweighted).
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
	lsas, err := advertisementsFromSyncRequest(decoded, 99)
	if err != nil {
		t.Fatal(err)
	}
	if len(lsas) != 1 {
		t.Fatalf("decoding must yield exactly the origin LSA, got %d", len(lsas))
	}
	got := lsas[0]
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
		if got.Peers[i].Peer != peer.Peer {
			t.Fatalf("edge %d = %+v, want peer %d", i, got.Peers[i], peer.Peer)
		}
		if got.Peers[i].Cost != 1 {
			t.Fatalf("edge %d cost = %d, want the unweighted fallback 1", i, got.Peers[i].Cost)
		}
	}
	if len(got.ProxyCIDRs) != len(advertisement.ProxyCIDRs) {
		t.Fatalf("proxy CIDRs = %v", got.ProxyCIDRs)
	}
}

// The request must decode as the reference message shape: my_peer_id,
// my_session_id, is_initiator, exactly ONE peer-info item (the origin
// self-description; fabricated entries for neighbors would trip the
// reference duplicate detection) and one conn-peer-list row with the
// origin's links.
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
	if len(items) != 1 {
		t.Fatalf("peer info entries = %d, want only the origin self-description", len(items))
	}
	self := items[0]
	if self.GetPeerId() != 5 || self.GetCost() != 0 || self.GetVersion() != 2 {
		t.Fatalf("origin entry = %+v", self)
	}
	if self.GetLastUpdate() == nil || self.GetLastUpdate().GetSeconds() != advertisement.Timestamp {
		t.Fatalf("origin last_update = %+v", self.GetLastUpdate())
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
// peer_ids[i] is connected to peer_ids[j]. Every item is a self-description,
// so the decoder yields one LSA per item; only the reporting peer's own row
// contributes edges to its LSA, and edges toward the local peer are dropped.
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
			{PeerId: 6},
			{PeerId: 7},
		}},
		ConnInfo: &peerrpc.SyncRouteInfoRequest_ConnBitmap{
			ConnBitmap: &peerrpc.RouteConnBitmap{PeerIds: peerIDs, Bitmap: bitmap},
		},
	}
	lsas, err := advertisementsFromSyncRequest(request, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(lsas) != 3 {
		t.Fatalf("LSAs = %d, want one per self-description", len(lsas))
	}
	if len(lsas[0].Peers) != 2 || lsas[0].Peers[0].Peer != 6 || lsas[0].Peers[1].Peer != 7 {
		t.Fatalf("origin edges = %+v", lsas[0].Peers)
	}
	for _, edge := range lsas[0].Peers {
		if edge.Cost != 1 {
			t.Fatalf("edge = %+v, want the unweighted fallback 1", edge)
		}
	}
	if len(lsas[1].Peers) != 0 || len(lsas[2].Peers) != 0 {
		t.Fatalf("relayed self-descriptions must be node-info-only: %+v %+v", lsas[1], lsas[2])
	}
}

// Missing conn info degrades to node-info-only LSAs.
func TestAdvertisementFromNodeInfoOnly(t *testing.T) {
	request := &peerrpc.SyncRouteInfoRequest{
		MyPeerId:  3,
		PeerInfos: &peerrpc.RoutePeerInfos{Items: []*peerrpc.RoutePeerInfo{{PeerId: 3, Version: 1}}},
	}
	lsas, err := advertisementsFromSyncRequest(request, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(lsas) != 1 || lsas[0].Origin != 3 || lsas[0].Version != 1 || len(lsas[0].Peers) != 0 {
		t.Fatalf("LSAs = %+v", lsas)
	}
}

// Zero origins and oversized payloads must be rejected.
func TestSyncRequestValidation(t *testing.T) {
	if _, err := advertisementsFromSyncRequest(&peerrpc.SyncRouteInfoRequest{}, 0); err == nil {
		t.Fatal("zero origin must fail")
	}
	oversized := &peerrpc.SyncRouteInfoRequest{MyPeerId: 1}
	items := make([]*peerrpc.RoutePeerInfo, MaxAdvertisementPeers+2)
	for i := range items {
		items[i] = &peerrpc.RoutePeerInfo{PeerId: uint32(i + 1)}
	}
	oversized.PeerInfos = &peerrpc.RoutePeerInfos{Items: items}
	if _, err := advertisementsFromSyncRequest(oversized, 1); err == nil {
		t.Fatal("oversized peer list must fail")
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	peerrpc "github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
)

func TestOSPFServiceInstallsSyncedLSA(t *testing.T) {
	flooder, err := NewFlooder(2, nil, func(ctx context.Context, a Advertisement, e uint32) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	service := NewOSPFService(flooder, nil)
	// The wire identity must match the reference registry exactly.
	if service.ServiceName() != "OspfRouteRpc" || rpc.ServiceNameOSPFRoute != "OspfRouteRpc" {
		t.Fatalf("service name = %q", service.ServiceName())
	}
	if MethodOSPFRouteSync != 1 {
		t.Fatalf("SyncRouteInfo method index = %d, want 1 (one-based reference)", MethodOSPFRouteSync)
	}
	advertisement := Advertisement{
		Origin:  1,
		Version: 1,
		Peers:   []PeerCost{{Peer: 2, Cost: 10}},
	}
	request, err := syncRequestFromAdvertisement(advertisement, 42)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := service.HandleMethod(MethodOSPFRouteSync, context.Background(), 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	response := &peerrpc.SyncRouteInfoResponse{}
	if err := proto.Unmarshal(responseBody, response); err != nil {
		t.Fatal(err)
	}
	if response.GetSessionId() != flooder.SessionID() {
		t.Fatalf("response session id = %d, want %d", response.GetSessionId(), flooder.SessionID())
	}
	if response.GetError() != 0 {
		t.Fatalf("response error = %d", response.GetError())
	}
	routes := flooder.Routes()
	found := false
	for _, item := range routes {
		if item.Destination == 1 && item.NextHop == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("synced LSA did not converge, routes = %v", routes)
	}
	if _, err := service.HandleMethod(MethodOSPFRouteSync, context.Background(), 1, []byte("junk")); err == nil {
		t.Fatal("malformed sync request must fail")
	}
	if _, err := service.HandleMethod(999, context.Background(), 1, wire); err == nil {
		t.Fatal("unknown method must fail")
	}
}

// Reference check_duplicate_peer_id: a sender whose own entry regressed
// under a different route id exposes a duplicated peer id, and the handler
// rejects it with SyncRouteInfoError_DuplicatePeerId instead of applying the
// LSA.
func TestOSPFServiceDetectsDuplicatePeerID(t *testing.T) {
	flooder, err := NewFlooder(2, nil, func(ctx context.Context, a Advertisement, e uint32) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	flooder.SetSessionID(42)
	service := NewOSPFService(flooder, nil)

	first := &peerrpc.SyncRouteInfoRequest{
		MyPeerId:    1,
		MySessionId: 100,
		PeerInfos: &peerrpc.RoutePeerInfos{Items: []*peerrpc.RoutePeerInfo{{
			PeerId:      1,
			PeerRouteId: 777,
			Version:     3,
		}}},
	}
	wire, err := proto.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.HandleMethod(MethodOSPFRouteSync, context.Background(), 1, wire); err != nil {
		t.Fatal(err)
	}
	if flooder.PeerRouteID(1) != 777 || flooder.SeenVersion(1) != 3 {
		t.Fatalf("route id/version not recorded: %d/%d", flooder.PeerRouteID(1), flooder.SeenVersion(1))
	}

	// The same peer id now reports a different route id with a lower
	// version: duplicated between two live nodes.
	duplicate := &peerrpc.SyncRouteInfoRequest{
		MyPeerId:    1,
		MySessionId: 200,
		PeerInfos: &peerrpc.RoutePeerInfos{Items: []*peerrpc.RoutePeerInfo{{
			PeerId:      1,
			PeerRouteId: 999,
			Version:     1,
		}}},
	}
	duplicateWire, err := proto.Marshal(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := service.HandleMethod(MethodOSPFRouteSync, context.Background(), 1, duplicateWire)
	if err != nil {
		t.Fatal(err)
	}
	response := &peerrpc.SyncRouteInfoResponse{}
	if err := proto.Unmarshal(responseBody, response); err != nil {
		t.Fatal(err)
	}
	if response.GetError() != peerrpc.SyncRouteInfoError_DuplicatePeerId {
		t.Fatalf("error = %v, want DuplicatePeerId", response.GetError())
	}
	if flooder.SeenVersion(1) != 3 {
		t.Fatalf("rejected LSA version must not be applied, seen = %d", flooder.SeenVersion(1))
	}

	// The receiver's own identity regressed under a different route id with
	// a higher version: our own peer id is duplicated.
	conflicting := &peerrpc.SyncRouteInfoRequest{
		MyPeerId:    1,
		MySessionId: 300,
		PeerInfos: &peerrpc.RoutePeerInfos{Items: []*peerrpc.RoutePeerInfo{{
			PeerId:      2,
			PeerRouteId: flooder.SessionID() + 1,
			Version:     uint32(flooder.OriginVersion() + 100),
		}}},
	}
	conflictingWire, err := proto.Marshal(conflicting)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err = service.HandleMethod(MethodOSPFRouteSync, context.Background(), 1, conflictingWire)
	if err != nil {
		t.Fatal(err)
	}
	response = &peerrpc.SyncRouteInfoResponse{}
	if err := proto.Unmarshal(responseBody, response); err != nil {
		t.Fatal(err)
	}
	if response.GetError() != peerrpc.SyncRouteInfoError_DuplicatePeerId {
		t.Fatalf("own-duplicate error = %v, want DuplicatePeerId", response.GetError())
	}
}

// Credential peers may only propagate their own route info; their
// connection info requires a verified relay permission.
func TestOSPFServiceEnforcesCredentialPolicy(t *testing.T) {
	flooder, err := NewFlooder(2, nil, func(ctx context.Context, a Advertisement, e uint32) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	credentialPeer := &peerrpc.TrustedCredentialPubkey{Pubkey: make([]byte, 32)}
	proof, err := SignTrustedCredentialProof(credentialPeer, "mesh-secret")
	if err != nil {
		t.Fatal(err)
	}
	service := NewOSPFService(flooder, &OSPFServiceConfig{
		NetworkSecret: "mesh-secret",
		IsCredentialPeer: func(peerID uint32) bool {
			return peerID == 1
		},
	})

	request := &peerrpc.SyncRouteInfoRequest{
		MyPeerId:    1,
		MySessionId: 7,
		PeerInfos: &peerrpc.RoutePeerInfos{Items: []*peerrpc.RoutePeerInfo{{
			PeerId:                   1,
			PeerRouteId:              555,
			Version:                  2,
			TrustedCredentialPubkeys: []*peerrpc.TrustedCredentialPubkeyProof{{Credential: credentialPeer, CredentialHmac: proof}},
		}}},
		ConnInfo: &peerrpc.SyncRouteInfoRequest_ConnPeerList{
			ConnPeerList: &peerrpc.RouteConnPeerList{PeerConnInfos: []*peerrpc.RouteConnPeerList_PeerConnInfo{{
				PeerId:           &peerrpc.PeerIdVersion{PeerId: 1},
				ConnectedPeerIds: []uint32{9},
			}}},
		},
	}
	wire, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.HandleMethod(MethodOSPFRouteSync, context.Background(), 1, wire); err != nil {
		t.Fatal(err)
	}
	// The verified relay permission keeps the connection edges; a route to
	// the unknown peer 9 appears through the credential peer's LSA.
	found := false
	for _, item := range flooder.Routes() {
		if item.Destination == 9 {
			found = true
		}
	}
	if !found {
		t.Fatalf("verified relay credential must accept conn info, routes = %v", flooder.Routes())
	}
}

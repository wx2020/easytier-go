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
	service := NewOSPFService(flooder)
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

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"context"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/rpc"
)

func TestOSPFServiceInstallsAnnouncedLSA(t *testing.T) {
	flooder, err := NewFlooder(2, nil, func(ctx context.Context, a Advertisement, e uint32) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	service := NewOSPFService(flooder)
	if service.ServiceName() != rpc.ServiceNameOSPFRoute {
		t.Fatalf("service name = %q", service.ServiceName())
	}
	advertisement := Advertisement{
		Origin:  1,
		Version: 1,
		Peers:   []PeerCost{{Peer: 2, Cost: 10}},
	}
	wire, err := advertisement.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.HandleMethod(MethodOSPFAnnounce, context.Background(), 1, wire); err != nil {
		t.Fatal(err)
	}
	routes := flooder.Routes()
	found := false
	for _, item := range routes {
		if item.Destination == 1 && item.NextHop == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("announced LSA did not converge, routes = %v", routes)
	}
	if _, err := service.HandleMethod(MethodOSPFAnnounce, context.Background(), 1, []byte("junk")); err == nil {
		t.Fatal("malformed advertisement must fail")
	}
	if _, err := service.HandleMethod(999, context.Background(), 1, wire); err == nil {
		t.Fatal("unknown method must fail")
	}
}

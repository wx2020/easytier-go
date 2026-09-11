// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package management

import (
	"context"
	"net/netip"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/mapping"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
)

func TestMappedListenerAddRemoveViaManager(t *testing.T) {
	mgr := mapping.NewManager(nil)
	cfg := config.Config{NetworkIdentity: config.NetworkIdentity{NetworkName: "mesh"}}
	service := NewServiceWithOptions(ServiceOptions{
		NodeInfo:        NodeInfo{ID: "node"},
		Config:          &cfg,
		MappedListeners: &mappingManagerAdapter{mgr},
		UpdateConfig:    func(context.Context, config.Config) error { return nil },
	})
	server, err := rpc.NewServer([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, service.Handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(context.Background()) }()
	client := NewClient(server.Addr().String(), 1, 2)
	ctx := context.Background()

	// Initially empty
	list, err := client.MappedListenerList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("initial list %v", list)
	}
	// Add tcp listener
	if err := client.MappedListenerAdd(ctx, "tcp://1.2.3.4:11010"); err != nil {
		t.Fatal(err)
	}
	list, err = client.MappedListenerList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].URL != "tcp://1.2.3.4:11010" || list[0].State != "active" {
		t.Fatalf("after add list %v", list)
	}
	// Add ws without port (allowed)
	if err := client.MappedListenerAdd(ctx, "ws://example.com"); err != nil {
		t.Fatal(err)
	}
	list, _ = client.MappedListenerList(ctx)
	if len(list) != 2 {
		t.Fatalf("list %v", list)
	}
	// Duplicate should error
	if err := client.MappedListenerAdd(ctx, "tcp://1.2.3.4:11010"); err == nil {
		t.Fatal("duplicate add should fail")
	}
	// Remove
	if err := client.MappedListenerRemove(ctx, "tcp://1.2.3.4:11010"); err != nil {
		t.Fatal(err)
	}
	list, _ = client.MappedListenerList(ctx)
	if len(list) != 1 {
		t.Fatalf("after remove list %v", list)
	}
	// Remove non-existent should error
	if err := client.MappedListenerRemove(ctx, "tcp://9.9.9.9:1"); err == nil {
		t.Fatal("remove non-existent should fail")
	}
	// Invalid URL should error
	if err := client.MappedListenerAdd(ctx, "ring://peer"); err == nil {
		t.Fatal("invalid url should fail")
	}
	// Ensure config is kept in sync (via Service's config)
	info, err := client.ConfigGet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range info.Config.MappedListeners {
		if u == "ws://example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("config should contain ws listener, got %v", info.Config.MappedListeners)
	}
}

// adapter to match MappedListenerStore interface using mapping.Manager
type mappingManagerAdapter struct {
	*mapping.Manager
}

func (a *mappingManagerAdapter) List() []MappedListenerStatus {
	list := a.Manager.List()
	out := make([]MappedListenerStatus, len(list))
	for i, s := range list {
		out[i] = MappedListenerStatus{URL: s.URL, State: s.State, Error: s.Error}
	}
	return out
}

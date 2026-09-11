// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package mapping

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestShouldMapUDPListener(t *testing.T) {
	if !ShouldMapUDPListener("udp://0.0.0.0:11010") {
		t.Fatal("unspecified should map")
	}
	if !ShouldMapUDPListener("udp://192.168.1.10:11010") {
		t.Fatal("private should map")
	}
	if !ShouldMapUDPListener("udp://169.254.1.1:11010") {
		t.Fatal("link-local should map")
	}
	if ShouldMapUDPListener("udp://127.0.0.1:11010") {
		t.Fatal("loopback should not map")
	}
	if ShouldMapUDPListener("udp://8.8.8.8:11010") {
		t.Fatal("public should not map")
	}
	if ShouldMapUDPListener("tcp://0.0.0.0:11010") {
		t.Fatal("tcp should not map")
	}
	if ShouldMapUDPListener("udp://255.255.255.255:11010") {
		t.Fatal("broadcast should not map")
	}
}

func TestMockGatewayAddAnyAndRemove(t *testing.T) {
	gw := NewMockGateway(netip.MustParseAddr("1.2.3.4"), BackendIGD)
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.10:11010")
	port, err := gw.AddAnyPort(ctx, local, LeaseDuration, Description)
	if err != nil {
		t.Fatalf("AddAnyPort: %v", err)
	}
	if port == 0 {
		t.Fatal("port is zero")
	}
	if !gw.HasMapping(port) {
		t.Fatal("mapping not found")
	}
	if err := gw.RemovePort(ctx, port); err != nil {
		t.Fatal(err)
	}
	if gw.HasMapping(port) {
		t.Fatal("mapping still exists after remove")
	}
}

func TestMockGatewayExpiry(t *testing.T) {
	gw := NewMockGateway(netip.MustParseAddr("1.2.3.4"), BackendIGD)
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.10:11010")
	// Use very short lease for expiry test
	port, err := gw.AddAnyPort(ctx, local, 100*time.Millisecond, Description)
	if err != nil {
		t.Fatal(err)
	}
	if !gw.HasMapping(port) {
		t.Fatal("mapping missing")
	}
	time.Sleep(150 * time.Millisecond)
	if gw.HasMapping(port) {
		t.Fatal("mapping should have expired")
	}
	if gw.Count() != 0 {
		t.Fatal("count should be 0 after expiry")
	}
}

func TestMockGatewayAddPortLeaseZeroRemoves(t *testing.T) {
	gw := NewMockGateway(netip.MustParseAddr("1.2.3.4"), BackendNATPMP)
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.10:11010")
	port, err := gw.AddAnyPort(ctx, local, LeaseDuration, Description)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate NAT-PMP renewal with same port
	if err := gw.AddPort(ctx, port, local, LeaseDuration, Description); err != nil {
		t.Fatal(err)
	}
	if !gw.HasMapping(port) {
		t.Fatal("mapping missing after renew")
	}
	// Remove via lease 0
	if err := gw.AddPort(ctx, port, local, 0, Description); err != nil {
		t.Fatal(err)
	}
	if gw.HasMapping(port) {
		t.Fatal("mapping should be removed via lease 0")
	}
}

func TestMapperAddsViaIGD(t *testing.T) {
	igd := NewMockGateway(netip.MustParseAddr("11.22.33.44"), BackendIGD)
	mapper := NewMapper(MapperOptions{
		DiscoverIGD:    func(ctx context.Context) (Gateway, error) { return igd, nil },
		DiscoverNATPMP: func(ctx context.Context) (Gateway, error) { return NewMockGateway(netip.MustParseAddr("5.6.7.8"), BackendNATPMP), nil },
		LeaseDuration:  300 * time.Millisecond,
		RenewInterval:  100 * time.Millisecond,
	})
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.2:11010")
	lease, err := mapper.AddMapping(ctx, "udp://192.168.1.2:11010", local)
	if err != nil {
		t.Fatalf("AddMapping: %v", err)
	}
	defer lease.Close()
	if lease.Backend != BackendIGD {
		t.Fatalf("backend = %q, want igd", lease.Backend)
	}
	if !igd.HasMapping(lease.ExternalPort) {
		t.Fatal("igd gateway should have mapping")
	}
	// Verify List
	if len(mapper.ListMappings()) != 1 {
		t.Fatal("mapper list should have 1")
	}
}

func TestMapperFallbackToNATPMP(t *testing.T) {
	igd := NewMockGateway(netip.MustParseAddr("11.22.33.44"), BackendIGD)
	igd.FailAddAny = true
	igd.FailAddPort = true
	nat := NewMockGateway(netip.MustParseAddr("5.6.7.8"), BackendNATPMP)
	mapper := NewMapper(MapperOptions{
		DiscoverIGD: func(ctx context.Context) (Gateway, error) { return igd, nil },
		DiscoverNATPMP: func(ctx context.Context) (Gateway, error) { return nat, nil },
	})
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.2:11010")
	lease, err := mapper.AddMapping(ctx, "udp://192.168.1.2:11010", local)
	if err != nil {
		t.Fatalf("AddMapping fallback: %v", err)
	}
	defer lease.Close()
	if lease.Backend != BackendNATPMP {
		t.Fatalf("backend = %q, want nat-pmp", lease.Backend)
	}
	if !nat.HasMapping(lease.ExternalPort) {
		t.Fatal("natpmp should have mapping")
	}
	if igd.HasMapping(lease.ExternalPort) {
		t.Fatal("igd should not have mapping on fallback")
	}
}

func TestMapperIGDDiscoveryFailureFallback(t *testing.T) {
	nat := NewMockGateway(netip.MustParseAddr("5.6.7.8"), BackendNATPMP)
	mapper := NewMapper(MapperOptions{
		DiscoverIGD: func(ctx context.Context) (Gateway, error) {
			return nil, context.DeadlineExceeded
		},
		DiscoverNATPMP: func(ctx context.Context) (Gateway, error) { return nat, nil },
	})
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.2:11010")
	lease, err := mapper.AddMapping(ctx, "udp://192.168.1.2:11010", local)
	if err != nil {
		t.Fatalf("fallback after discovery failure: %v", err)
	}
	defer lease.Close()
	if lease.Backend != BackendNATPMP {
		t.Fatal("should fallback to nat-pmp")
	}
}

func TestMapperBothFail(t *testing.T) {
	mapper := NewMapper(MapperOptions{
		DiscoverIGD:    func(ctx context.Context) (Gateway, error) { return nil, context.DeadlineExceeded },
		DiscoverNATPMP: func(ctx context.Context) (Gateway, error) { return nil, context.DeadlineExceeded },
	})
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.2:11010")
	if _, err := mapper.AddMapping(ctx, "udp://192.168.1.2:11010", local); err == nil {
		t.Fatal("should fail when both discoveries fail")
	}
}

func TestMapperRenewalKeepsMappingAlive(t *testing.T) {
	leaseDur := 200 * time.Millisecond
	renew := 80 * time.Millisecond
	gw := NewMockGateway(netip.MustParseAddr("11.22.33.44"), BackendIGD)
	mapper := NewMapper(MapperOptions{
		DiscoverIGD:    func(ctx context.Context) (Gateway, error) { return gw, nil },
		DiscoverNATPMP: func(ctx context.Context) (Gateway, error) { return gw, nil },
		LeaseDuration:  leaseDur,
		RenewInterval:  renew,
	})
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.2:11010")
	lease, err := mapper.AddMapping(ctx, "udp://192.168.1.2:11010", local)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	port := lease.ExternalPort
	// Wait longer than lease but renewal should keep it alive.
	time.Sleep(500 * time.Millisecond)
	if !gw.HasMapping(port) {
		t.Fatal("mapping should still exist after renewal")
	}
	// Stop renewal by closing lease, then after lease duration it should expire.
	_ = lease.Close()
	// After close, mapping should be removed immediately (deferred RemovePort).
	time.Sleep(50 * time.Millisecond)
	if gw.HasMapping(port) {
		t.Fatal("mapping should be removed after lease Close")
	}
}

func TestMapperExpiryWithoutRenewal(t *testing.T) {
	// Direct gateway without mapper renewal to test pure expiry.
	gw := NewMockGateway(netip.MustParseAddr("11.22.33.44"), BackendIGD)
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.2:11010")
	port, err := gw.AddAnyPort(ctx, local, 100*time.Millisecond, Description)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if gw.HasMapping(port) {
		t.Fatal("mapping should have expired without renewal")
	}
}

func TestMapperAddAnyPortFallbackToSamePort(t *testing.T) {
	gw := NewMockGateway(netip.MustParseAddr("11.22.33.44"), BackendIGD)
	gw.FailAddAny = true // force fallback to AddPort with same port
	mapper := NewMapper(MapperOptions{
		DiscoverIGD:   func(ctx context.Context) (Gateway, error) { return gw, nil },
		LeaseDuration: LeaseDuration,
	})
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.2:12345")
	lease, err := mapper.AddMapping(ctx, "udp://192.168.1.2:12345", local)
	if err != nil {
		t.Fatalf("fallback to same port: %v", err)
	}
	defer lease.Close()
	if lease.ExternalPort != 12345 {
		t.Fatalf("external port %d, want 12345 fallback", lease.ExternalPort)
	}
}

func TestMapperRemove(t *testing.T) {
	gw := NewMockGateway(netip.MustParseAddr("11.22.33.44"), BackendIGD)
	mapper := NewMapper(MapperOptions{
		DiscoverIGD: func(ctx context.Context) (Gateway, error) { return gw, nil },
	})
	ctx := context.Background()
	local := netip.MustParseAddrPort("192.168.1.2:11010")
	lease, err := mapper.AddMapping(ctx, "udp://192.168.1.2:11010", local)
	if err != nil {
		t.Fatal(err)
	}
	port := lease.ExternalPort
	// Remove via Mapper RemoveMapping (not lease.Close)
	if err := mapper.RemoveMapping(ctx, "udp://192.168.1.2:11010"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if gw.HasMapping(port) {
		t.Fatal("mapping should be gone after RemoveMapping")
	}
	if mapper.HasMapping("udp://192.168.1.2:11010") {
		t.Fatal("mapper should not have mapping after remove")
	}
}

func TestManagerAddRemoveList(t *testing.T) {
	mgr := NewManager(nil)
	if err := mgr.Add("tcp://203.0.113.10:11010"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Add("udp://203.0.113.10:11010"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Add("ws://example.com"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Add("wss://example.com:443"); err != nil {
		t.Fatal(err)
	}
	// Duplicate should fail.
	if err := mgr.Add("tcp://203.0.113.10:11010"); err == nil {
		t.Fatal("duplicate should fail")
	}
	// Invalid should fail: ring without port.
	if err := mgr.Add("ring://peer"); err == nil {
		t.Fatal("ring without port should fail")
	}
	list := mgr.List()
	if len(list) != 4 {
		t.Fatalf("list len %d, want 4", len(list))
	}
	if err := mgr.Remove("udp://203.0.113.10:11010"); err != nil {
		t.Fatal(err)
	}
	if mgr.Contains("udp://203.0.113.10:11010") {
		t.Fatal("should be removed")
	}
	if err := mgr.Remove("udp://1.1.1.1:1"); err == nil {
		t.Fatal("removing non-existent should fail")
	}
	// List should be sorted
	urls := mgr.URLs()
	if len(urls) != 3 {
		t.Fatal("urls len")
	}
}

func TestValidateMappedListenerURL(t *testing.T) {
	valid := []string{
		"tcp://127.0.0.1:11010",
		"tcp://127.0.0.1",
		"udp://0.0.0.0:11010",
		"ws://example.com",
		"wss://example.com/path",
		"wg://10.0.0.1:11011",
	}
	for _, u := range valid {
		if err := ValidateMappedListenerURL(u); err != nil {
			t.Fatalf("valid %q failed: %v", u, err)
		}
	}
	invalid := []string{
		"ring://peer-id",
		"://missing",
		"tcp://",
	}
	for _, u := range invalid {
		if err := ValidateMappedListenerURL(u); err == nil {
			t.Fatalf("invalid %q should fail", u)
		}
	}
}

func TestManagerInitialFromConfig(t *testing.T) {
	mgr := NewManager([]string{"tcp://1.1.1.1:11010", "invalid://nope", "udp://2.2.2.2:11010"})
	if len(mgr.List()) != 2 {
		t.Fatalf("initial filtered length %d", len(mgr.List()))
	}
}

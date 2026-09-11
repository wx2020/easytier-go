//go:build linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func isPrivilegedForTest() bool {
	if v := os.Getenv("EASYTIER_FORCE_PRIVILEGED"); v == "1" {
		return true
	}
	return os.Geteuid() == 0
}

func hasIPCommand() bool {
	_, err := exec.LookPath("ip")
	return err == nil
}

func runIP(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v failed: %v output: %s", args, err, out)
	}
}

func runIPSilent(args ...string) error {
	cmd := exec.Command("ip", args...)
	_, err := cmd.CombinedOutput()
	return err
}

func TestPrivilegedDummyInterfaceAddressAndRoute(t *testing.T) {
	if !isPrivilegedForTest() {
		t.Skip("requires privileged execution (root or EASYTIER_FORCE_PRIVILEGED=1)")
	}
	if !hasIPCommand() {
		t.Skip("ip command not available")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil && os.Getenv("EASYTIER_FORCE_PRIVILEGED") != "1" {
		t.Skip("tun not available")
	}
	ifName := fmt.Sprintf("et%d", os.Getpid()%10000)
	// Ensure clean start
	_ = runIPSilent("link", "del", ifName)
	t.Cleanup(func() { _ = runIPSilent("link", "del", ifName) })

	// 1. Dry-run planner should generate valid plans
	tunPlan, err := PlanTun("linux", Config{Name: ifName, MTU: 1380})
	if err != nil {
		t.Fatalf("PlanTun: %v", err)
	}
	if len(tunPlan.Actions) == 0 {
		t.Fatal("expected tun plan actions")
	}

	addrPlan, err := PlanAddresses("linux", AddressConfig{IfName: ifName, Addresses: []string{"10.144.144.10/24"}})
	if err != nil {
		t.Fatalf("PlanAddresses: %v", err)
	}
	if len(addrPlan.Actions) == 0 {
		t.Fatal("expected addr plan")
	}

	routePlan, err := PlanRoutes("linux", RouteConfig{IfName: ifName, Routes: []string{"10.10.0.0/16"}, Metric: 100})
	if err != nil {
		t.Fatalf("PlanRoutes: %v", err)
	}
	if len(routePlan.Actions) == 0 {
		t.Fatal("expected route plan")
	}

	// 2. Actually create dummy interface (privileged)
	runIP(t, "link", "add", ifName, "type", "dummy")
	runIP(t, "link", "set", ifName, "up")
	// Verify interface exists via netlink helper: check PlanWaitInterface would succeed
	// Use ip link show
	cmd := exec.Command("ip", "link", "show", ifName)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ip link show failed after create: %v %s", err, out)
	}

	// 3. Assign address using plan's underlying command (ip addr add)
	pfx := netip.MustParsePrefix("10.144.144.10/24")
	runIP(t, "addr", "add", pfx.String(), "dev", ifName)
	// Verify address present
	out, err := exec.Command("ip", "-4", "addr", "show", "dev", ifName).CombinedOutput()
	if err != nil {
		t.Fatalf("ip addr show: %v %s", err, out)
	}
	if !strings.Contains(string(out), "10.144.144.10") {
		t.Fatalf("address not found after add: %s", out)
	}

	// 4. MTU via PlanLink
	mtu := 1400
	linkPlan, err := PlanLink("linux", LinkConfig{IfName: ifName, MTU: &mtu})
	if err != nil {
		t.Fatalf("PlanLink: %v", err)
	}
	if len(linkPlan.Actions) == 0 {
		t.Fatal("expected link plan")
	}
	runIP(t, "link", "set", "dev", ifName, "mtu", "1400")
	out, err = exec.Command("ip", "link", "show", ifName).CombinedOutput()
	if err != nil {
		t.Fatalf("ip link show mtu: %v %s", err, out)
	}
	if !strings.Contains(string(out), "mtu 1400") {
		t.Fatalf("mtu not set: %s", out)
	}

	// 5. Add route
	runIP(t, "route", "add", "10.10.0.0/16", "dev", ifName, "metric", "100")
	out, err = exec.Command("ip", "route", "show", "dev", ifName).CombinedOutput()
	if err != nil {
		t.Fatalf("ip route show: %v %s", err, out)
	}
	if !strings.Contains(string(out), "10.10.0.0/16") {
		t.Fatalf("route not found: %s", out)
	}
	if !strings.Contains(string(out), "100") {
		t.Fatalf("route metric not found: %s", out)
	}

	// 6. DNS dry-run (no privileged op, just plan)
	dnsPlan, err := PlanDNS("linux", DNSConfig{IfName: ifName, Servers: []string{"1.1.1.1"}})
	if err != nil {
		t.Fatalf("PlanDNS: %v", err)
	}
	if len(dnsPlan.Actions) == 0 {
		t.Fatal("expected dns plan")
	}

	// 7. NetNS plan (dry-run only, not actually switching)
	nsPlan, err := PlanNetNS("linux", NewNetNS("testns"))
	if err != nil {
		t.Fatalf("PlanNetNS: %v", err)
	}
	if len(nsPlan.Actions) == 0 {
		t.Fatal("expected netns plan")
	}

	// 8. Bind-device plan
	bindPlan, err := PlanBind("linux", BindConfig{Mode: BindModeCustom, Device: ifName})
	if err != nil {
		t.Fatalf("PlanBind: %v", err)
	}
	if len(bindPlan.Actions) == 0 {
		t.Fatal("expected bind plan")
	}

	// 9. Normal exit cleanup: use CleanupManager
	mgr := NewCleanupManager("linux", ifName)
	mgr.Track(addrPlan)
	mgr.Track(routePlan)
	cleanPlan := mgr.PlanCleanup()
	if len(cleanPlan.Actions) == 0 {
		t.Fatal("cleanup plan empty")
	}
	// Actually clean up routes and addresses
	_ = runIPSilent("route", "del", "10.10.0.0/16", "dev", ifName)
	_ = runIPSilent("addr", "del", pfx.String(), "dev", ifName)
	// Verify cleanup
	out, _ = exec.Command("ip", "-4", "addr", "show", "dev", ifName).CombinedOutput()
	if strings.Contains(string(out), "10.144.144.10") {
		t.Fatalf("address still present after cleanup: %s", out)
	}
	out, _ = exec.Command("ip", "route", "show", "dev", ifName).CombinedOutput()
	if strings.Contains(string(out), "10.10.0.0/16") {
		t.Fatalf("route still present after cleanup: %s", out)
	}

	// 10. Crash recovery simulation: create stale interface then detect
	// Recreate interface to simulate crash leftover
	runIP(t, "link", "add", "et_crash0", "type", "dummy")
	runIP(t, "link", "set", "et_crash0", "up")
	t.Cleanup(func() { _ = runIPSilent("link", "del", "et_crash0") })
	crashPlan, err := PlanCrashRecovery("linux", []string{"et_crash0", "lo"})
	if err != nil {
		t.Fatalf("PlanCrashRecovery: %v", err)
	}
	if len(crashPlan.Actions) == 0 {
		t.Fatal("crash recovery should have actions for et_crash0")
	}
	// Apply crash recovery cleanup (dry-run validation: ensure plan contains delete)
	found := false
	for _, a := range crashPlan.Actions {
		if strings.Contains(strings.Join(a.Command, " "), "et_crash0") {
			found = true
		}
	}
	if !found {
		t.Fatalf("crash recovery plan missing et_crash0: %v", crashPlan.Actions)
	}
	// Actually delete stale
	_ = runIPSilent("link", "del", "et_crash0")
	out, _ = exec.Command("ip", "link", "show", "et_crash0").CombinedOutput()
	if !strings.Contains(string(out), "does not exist") && err == nil {
		// ip link show returns error when not exist; we check via command success
		if strings.Contains(string(out), "et_crash0") {
			t.Fatalf("stale interface not cleaned: %s", out)
		}
	}

	// 11. Full cleanup covers everything
	full, err := PlanFullCleanup("linux", ifName, []string{"10.10.0.0/16"}, []string{pfx.String()})
	if err != nil {
		t.Fatalf("PlanFullCleanup: %v", err)
	}
	if len(full.Actions) < 3 {
		t.Fatalf("full cleanup too few actions: %d", len(full.Actions))
	}
}

func TestPrivilegedNetworkNamespaceDryRun(t *testing.T) {
	if !isPrivilegedForTest() {
		t.Skip("requires privileged")
	}
	// Test netns plan generation and integration with bind
	cfg := NetNSBindConfig{
		NetNS: NewNetNS("testns2"),
		Bind:  BindConfig{Mode: BindModeCustom, Device: "et0"},
	}
	plan, err := PlanNetNSBind("linux", cfg)
	if err != nil {
		t.Fatalf("PlanNetNSBind: %v", err)
	}
	if len(plan.Actions) < 2 {
		t.Fatalf("netns+bind should have at least 2 actions, got %d", len(plan.Actions))
	}
}

func TestAddressBroadcastCalculation(t *testing.T) {
	pfx := netip.MustParsePrefix("10.0.0.0/24")
	bc := prefixBroadcast(pfx)
	if bc != "10.0.0.255" {
		t.Fatalf("broadcast %q want 10.0.0.255", bc)
	}
	pfx = netip.MustParsePrefix("10.144.144.10/24")
	bc = prefixBroadcast(pfx)
	if bc != "10.144.144.255" {
		t.Fatalf("broadcast %q want 10.144.144.255", bc)
	}
}

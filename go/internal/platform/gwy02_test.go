// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"strings"
	"testing"
)

func TestPlanTunPerPlatform(t *testing.T) {
	cases := []struct {
		osName string
		cfg    Config
		valid  bool
		check  func(t *testing.T, plan Plan)
	}{
		{
			osName: "linux",
			cfg:    Config{Name: "et0", MTU: 1380},
			valid:  true,
			check: func(t *testing.T, plan Plan) {
				if !containsCmd(plan, "open") {
					t.Fatalf("linux tun should contain open: %v", plan.Actions)
				}
				if !containsFull(plan, "ip link set") {
					t.Fatalf("linux tun should contain ip link: %v", plan.Actions)
				}
			},
		},
		{
			osName: "linux",
			cfg:    Config{Name: "", MTU: 1380},
			valid:  false,
		},
		{
			osName: "windows",
			cfg:    Config{Name: "et_test", MTU: 1380},
			valid:  true,
			check: func(t *testing.T, plan Plan) {
				if !containsCmd(plan, "wintun") {
					t.Fatalf("windows tun should contain wintun: %v", plan.Actions)
				}
				if !containsCmd(plan, "netsh") {
					t.Fatalf("windows tun should contain netsh: %v", plan.Actions)
				}
			},
		},
		{
			osName: "windows",
			cfg:    Config{Name: "", MTU: 1380},
			valid:  true,
			check: func(t *testing.T, plan Plan) {
				if len(plan.Warnings) == 0 {
					t.Fatalf("windows empty name should warn about random et_*")
				}
			},
		},
		{
			osName: "darwin",
			cfg:    Config{MTU: 1380},
			valid:  true,
			check: func(t *testing.T, plan Plan) {
				if !containsCmd(plan, "ifconfig") {
					t.Fatalf("darwin tun should contain ifconfig: %v", plan.Actions)
				}
			},
		},
		{
			osName: "freebsd",
			cfg:    Config{Name: "tun_test", MTU: 1500},
			valid:  true,
			check: func(t *testing.T, plan Plan) {
				if !containsCmd(plan, "ifconfig") {
					t.Fatalf("freebsd tun should contain ifconfig")
				}
			},
		},
		{
			osName: "android",
			cfg:    Config{Name: "tun0", MTU: 1380},
			valid:  true,
			check: func(t *testing.T, plan Plan) {
				if !containsCmd(plan, "vpn-builder") {
					t.Fatalf("android tun should contain vpn-builder: %v", plan.Actions)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.osName+" valid="+boolStr(tc.valid), func(t *testing.T) {
			plan, err := PlanTun(tc.osName, tc.cfg)
			if tc.valid && err != nil {
				t.Fatalf("PlanTun(%q) unexpected error: %v", tc.osName, err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("PlanTun(%q) expected error", tc.osName)
			}
			if tc.valid && tc.check != nil {
				tc.check(t, plan)
			}
			if tc.valid && !plan.DryRun {
				t.Fatalf("plan should be dry-run")
			}
		})
	}
}

func TestPlanAddressesPerPlatform(t *testing.T) {
	for _, osName := range []string{"linux", "windows", "darwin", "freebsd"} {
		t.Run(osName, func(t *testing.T) {
			plan, err := PlanAddresses(osName, AddressConfig{IfName: "et0", Addresses: []string{"10.144.144.1/24", "fd00::1/64"}})
			if err != nil {
				t.Fatalf("PlanAddresses %q: %v", osName, err)
			}
			if len(plan.Actions) < 2 {
				t.Fatalf("expected at least 2 address actions for %q, got %d", osName, len(plan.Actions))
			}
			// Check cleanup path
			clean, err := CleanupAddresses(osName, "et0", nil)
			if err != nil {
				t.Fatalf("CleanupAddresses %q: %v", osName, err)
			}
			if len(clean.Actions) == 0 {
				t.Fatalf("cleanup should have actions for %q", osName)
			}
		})
	}
}

func TestPlanAddressesInvalidCIDR(t *testing.T) {
	if _, err := PlanAddresses("linux", AddressConfig{IfName: "et0", Addresses: []string{"not-a-cidr"}}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if _, err := PlanAddresses("linux", AddressConfig{IfName: "", Addresses: []string{"10.0.0.1/24"}}); err == nil {
		t.Fatal("expected error for empty ifname")
	}
}

func TestPlanLinkMTUAndStatus(t *testing.T) {
	mtu := 1400
	up := true
	plan, err := PlanLink("linux", LinkConfig{IfName: "et0", MTU: &mtu, Up: &up})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 2 {
		t.Fatalf("link plan actions = %d want 2", len(plan.Actions))
	}
	down := false
	plan2, err := PlanLink("darwin", LinkConfig{IfName: "utun0", Up: &down})
	if err != nil {
		t.Fatal(err)
	}
	if !containsCmd(plan2, "ifconfig") {
		t.Fatalf("darwin link down should use ifconfig")
	}
	// Invalid MTU
	bad := 99999
	if _, err := PlanLink("linux", LinkConfig{IfName: "et0", MTU: &bad}); err == nil {
		t.Fatal("expected error for bad MTU")
	}
}

func TestPlanWaitInterface(t *testing.T) {
	for _, osName := range []string{"linux", "windows", "darwin"} {
		plan, err := PlanWaitInterface(osName, "et0")
		if err != nil {
			t.Fatalf("PlanWaitInterface %q: %v", osName, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("wait plan empty for %q", osName)
		}
	}
}

func TestPlanRoutesMetrics(t *testing.T) {
	// Linux metric defaults to 65535
	plan, err := PlanRoutes("linux", RouteConfig{IfName: "et0", Routes: []string{"10.10.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan.Actions[0].Command, " "), "65535") {
		t.Fatalf("linux default metric should be 65535, got %v", plan.Actions[0].Command)
	}
	// Darwin hopcount 7
	plan, err = PlanRoutes("darwin", RouteConfig{IfName: "utun0", Routes: []string{"10.10.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan.Actions[0].Command, " "), "7") {
		t.Fatalf("darwin default hopcount should be 7, got %v", plan.Actions[0].Command)
	}
	// Windows 9000
	plan, err = PlanRoutes("windows", RouteConfig{IfName: "et0", Routes: []string{"10.10.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan.Actions[0].Command, " "), "9000") {
		t.Fatalf("windows default metric should be 9000, got %v", plan.Actions[0].Command)
	}
	// Explicit metric
	plan, err = PlanRoutes("linux", RouteConfig{IfName: "et0", Routes: []string{"10.10.0.0/16"}, Metric: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan.Actions[0].Command, " "), "100") {
		t.Fatalf("explicit metric 100 not found: %v", plan.Actions[0].Command)
	}
	// IPv6 routes
	plan, err = PlanRoutes("linux", RouteConfig{IfName: "et0", Routes: []string{"2001:db8::/32"}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Actions[0].Command[0] != "ip" {
		t.Fatalf("ipv6 linux route should use ip: %v", plan.Actions[0].Command)
	}
}

func TestPlanDNSPerPlatform(t *testing.T) {
	// Linux resolved
	plan, err := PlanDNS("linux", DNSConfig{IfName: "et0", Servers: []string{"1.1.1.1"}, Search: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !containsCmd(plan, "resolvectl") {
		t.Fatal("linux dns should use resolvectl")
	}
	// Windows
	plan, err = PlanDNS("windows", DNSConfig{IfName: "et0", Servers: []string{"8.8.8.8"}})
	if err != nil {
		t.Fatal(err)
	}
	if !containsFull(plan, "netsh") && !containsFull(plan, "reg") {
		t.Fatalf("windows dns should contain netsh/reg: %v", plan.Actions)
	}
	// Darwin
	plan, err = PlanDNS("darwin", DNSConfig{IfName: "utun0", Servers: []string{"1.1.1.1"}, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsCmd(plan, "scutil") {
		t.Fatalf("darwin dns should use scutil: %v", plan.Actions)
	}
}

func TestPlanNetNS(t *testing.T) {
	// No ns
	plan, err := PlanNetNS("linux", NewNetNS(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 0 {
		t.Fatalf("empty netns should have no actions")
	}
	// Linux netns
	plan, err = PlanNetNS("linux", NewNetNS("testns"))
	if err != nil {
		t.Fatal(err)
	}
	if !containsCmd(plan, "setns") {
		t.Fatalf("linux netns should contain setns: %v", plan.Actions)
	}
	// Non-linux is no-op
	plan, err = PlanNetNS("windows", NewNetNS("testns"))
	if err != nil {
		t.Fatal(err)
	}
	if !containsFull(plan, "noop") {
		t.Fatalf("non-linux netns should be noop")
	}
	// Exec helper
	plan, err = PlanNetNSExec("linux", NewNetNS("ns1"), []string{"ip", "link", "show"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsCmd(plan, "ip") {
		t.Fatalf("netns exec should contain ip: %v", plan.Actions)
	}
}

func TestPlanBindDevice(t *testing.T) {
	// Disabled
	plan, err := PlanBind("linux", BindConfig{Mode: BindModeDisabled})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Warnings) == 0 {
		t.Fatal("disabled bind should warn")
	}
	// Custom
	plan, err = PlanBind("linux", BindConfig{Mode: BindModeCustom, Device: "et0"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsFull(plan, "SO_BINDTODEVICE") {
		t.Fatalf("linux custom bind should contain SO_BINDTODEVICE: %v", plan.Actions)
	}
	// Darwin
	plan, err = PlanBind("darwin", BindConfig{Mode: BindModeCustom, Device: "utun0"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsFull(plan, "IP_BOUND_IF") {
		t.Fatalf("darwin bind should contain IP_BOUND_IF")
	}
	// Windows
	plan, err = PlanBind("windows", BindConfig{Mode: BindModeCustom, Device: "et0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("windows bind should have actions")
	}
	// Invalid custom empty
	if _, err := PlanBind("linux", BindConfig{Mode: BindModeCustom, Device: ""}); err == nil {
		t.Fatal("expected error for empty custom device")
	}
}

func TestPlanCleanupAndCrashRecovery(t *testing.T) {
	// Normal cleanup tracking
	mgr := NewCleanupManager("linux", "et0")
	plan, _ := PlanRoutes("linux", RouteConfig{IfName: "et0", Routes: []string{"10.0.0.0/24"}})
	mgr.Track(plan)
	clean := mgr.PlanCleanup()
	if len(clean.Actions) == 0 {
		t.Fatal("cleanup should have actions")
	}
	// Full cleanup
	full, err := PlanFullCleanup("linux", "et0", []string{"10.0.0.0/24"}, []string{"10.144.144.1/24"})
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Actions) < 3 {
		t.Fatalf("full cleanup should have at least 3 actions, got %d", len(full.Actions))
	}
	// Crash recovery with stale names
	crash, err := PlanCrashRecovery("linux", []string{"et0", "et1", "lo"})
	if err != nil {
		t.Fatal(err)
	}
	// lo should be skipped (not easytier-like) but et0/et1 should be cleaned
	foundET := false
	for _, a := range crash.Actions {
		if strings.Contains(strings.Join(a.Command, " "), "et0") {
			foundET = true
		}
	}
	if !foundET {
		t.Fatalf("crash recovery should handle et0: %v", crash.Actions)
	}
	// Empty stale list
	empty, err := PlanCrashRecovery("linux", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Actions) != 0 {
		t.Fatalf("empty crash recovery should have no actions")
	}
}

func TestEffectiveMTU(t *testing.T) {
	if EffectiveMTU(1380, false) != 1380 {
		t.Fatalf("mtu without encryption should be 1380")
	}
	if EffectiveMTU(1380, true) != 1360 {
		t.Fatalf("mtu with encryption should be 1360")
	}
	if EffectiveMTU(0, false) != DefaultMTU {
		t.Fatalf("zero mtu should default")
	}
	if EffectiveMTU(1280, true) != 1280 {
		t.Fatalf("min mtu clamp failed")
	}
}

func TestPlanServiceWindows(t *testing.T) {
	plan, err := PlanService("windows", ServiceConfig{Name: "easytier", Exec: "/usr/bin/easytier-core", Args: []string{"-c", "/etc/easytier.toml"}})
	if err != nil {
		t.Fatal(err)
	}
	if !containsCmd(plan, "sc") {
		t.Fatalf("windows service should contain sc: %v", plan.Actions)
	}
	// Darwin launchd
	plan, err = PlanService("darwin", ServiceConfig{Name: "easytier", Exec: "/opt/easytier/easytier-core"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsCmd(plan, "launchctl") {
		t.Fatalf("darwin service should contain launchctl")
	}
}

func containsCmd(plan Plan, substr string) bool {
	for _, a := range plan.Actions {
		for _, c := range a.Command {
			if strings.Contains(c, substr) {
				return true
			}
		}
		if strings.Contains(a.Description, substr) {
			return true
		}
	}
	return false
}

func containsFull(plan Plan, substr string) bool {
	for _, a := range plan.Actions {
		joined := strings.Join(a.Command, " ") + " " + a.Description
		if strings.Contains(joined, substr) {
			return true
		}
	}
	return false
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

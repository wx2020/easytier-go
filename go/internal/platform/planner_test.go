// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"testing"
)

func TestPlanRoutesLinux(t *testing.T) {
	plan, err := PlanRoutes("linux", RouteConfig{IfName: "et0", Routes: []string{"10.144.144.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("actions = %d want 1", len(plan.Actions))
	}
	if plan.Actions[0].Command[0] != "ip" {
		t.Fatalf("unexpected command: %v", plan.Actions[0].Command)
	}
	if !plan.DryRun {
		t.Fatal("dry-run must be true")
	}
}

func TestPlanRoutesInvalidCIDR(t *testing.T) {
	if _, err := PlanRoutes("linux", RouteConfig{IfName: "et0", Routes: []string{"not-a-cidr"}}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestPlanDNSLinuxResolved(t *testing.T) {
	plan, err := PlanDNS("linux", DNSConfig{IfName: "et0", Servers: []string{"1.1.1.1"}, Mode: "systemd-resolved"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range plan.Actions {
		if a.Command[0] == "resolvectl" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected resolvectl")
	}
}

func TestPlanDNSAndroid(t *testing.T) {
	plan, err := PlanDNS("android", DNSConfig{Servers: []string{"8.8.8.8"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected android dns actions")
	}
	if plan.Actions[0].Command[0] != "builder.addDnsServer" {
		t.Fatalf("unexpected android dns command: %v", plan.Actions[0].Command)
	}
}

func TestPlanServiceLinux(t *testing.T) {
	cfg := ServiceConfig{Name: "easytier", Exec: "/usr/bin/easytier-core", Args: []string{"-c", "/etc/easytier.toml"}}
	plan, err := PlanService("linux", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected service actions")
	}
}

func TestPlanServiceEscaping(t *testing.T) {
	cfg := ServiceConfig{Name: "bad\n[Service]\nExecStart=/tmp/evil", Exec: "/usr/bin/worker"}
	plan, err := PlanService("linux", cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Plan should be generated; actual escaping is validated in internal/service tests.
	// Ensure plan was created and not empty.
	if len(plan.Actions) == 0 {
		t.Fatal("expected actions for service plan")
	}
}

func TestPlanAndroidTun(t *testing.T) {
	ReleaseAndroidTun()
	defer ReleaseAndroidTun()
	plan, err := PlanAndroidTun(Config{Name: "tun0", MTU: 1380}, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected android tun plan")
	}
	if err := AcquireAndroidTun("tun0", 42); err != nil {
		t.Fatal(err)
	}
	if !IsAndroidTunActive() {
		t.Fatal("should be active")
	}
	if err := AcquireAndroidTun("tun1", 43); err == nil {
		t.Fatal("second should fail")
	}
	ReleaseAndroidTun()
	if IsAndroidTunActive() {
		t.Fatal("should be inactive after release")
	}
}

func TestCleanupRoutes(t *testing.T) {
	plan, err := CleanupRoutes("linux", RouteConfig{IfName: "et0", Routes: []string{"10.0.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("cleanup actions = %d want 1", len(plan.Actions))
	}
	if plan.Actions[0].Command[0] != "ip" || plan.Actions[0].Command[1] != "route" {
		t.Fatalf("unexpected cleanup: %v", plan.Actions[0].Command)
	}
}

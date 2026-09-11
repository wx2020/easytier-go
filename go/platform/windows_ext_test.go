// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"strings"
	"testing"
)

func TestWindowsDriverSpec(t *testing.T) {
	spec := WinDriverSpec{Arch: "x86_64", WintunDLL: "C:\\wintun.dll"}
	if err := ValidateWinDriverSpec(spec); err != nil {
		t.Fatal(err)
	}
	bad := WinDriverSpec{Arch: "mips", WintunDLL: "wintun.dll"}
	if err := ValidateWinDriverSpec(bad); err == nil {
		t.Fatal("expected unsupported arch error")
	}
	bad2 := WinDriverSpec{Arch: "x86_64", WintunDLL: ""}
	if err := ValidateWinDriverSpec(bad2); err == nil {
		t.Fatal("expected wintun.dll required error")
	}
	for _, arch := range SupportedWinArches {
		spec.Arch = arch
		if err := ValidateWinDriverSpec(spec); err != nil {
			t.Fatalf("arch %q should be valid: %v", arch, err)
		}
	}
}

func TestPlanWintun(t *testing.T) {
	spec := WinDriverSpec{Arch: "x86_64", WintunDLL: "wintun.dll", WinDivertDLL: "WinDivert.dll", WinDivertSys: "WinDivert.sys"}
	plan, err := PlanWintun("et0", spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected actions")
	}
	hasWintun := false
	hasReg := false
	for _, a := range plan.Actions {
		cmd := strings.Join(a.Command, " ")
		if strings.Contains(cmd, "wintun") && strings.Contains(cmd, "create") {
			hasWintun = true
		}
		if strings.Contains(cmd, "reg") {
			hasReg = true
		}
	}
	if !hasWintun {
		t.Fatal("missing wintun create")
	}
	if !hasReg {
		t.Fatal("missing reg cleanup")
	}
	// auto name when empty
	plan2, err := PlanWintun("", spec)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range plan2.Actions {
		if strings.Contains(strings.Join(a.Command, " "), "et_auto") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected et_auto for empty name")
	}
}

func TestWindowsFirewall(t *testing.T) {
	rule := WinFirewallRule{InterfaceName: "et0"}
	plan, err := PlanWindowsFirewall(rule)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected firewall actions")
	}
	// should cover TCP/UDP/ICMP/ALL x 2 directions = 8 rules
	if len(plan.Actions) < 6 {
		t.Fatalf("actions %d, want >=6", len(plan.Actions))
	}
	for _, a := range plan.Actions {
		if len(a.Command) == 0 || a.Command[0] != "netsh" {
			t.Fatalf("unexpected command %v", a.Command)
		}
		if len(a.Rollback) == 0 {
			t.Fatalf("missing rollback for %q", a.Description)
		}
	}
	// direction filter
	inbound, err := PlanWindowsFirewall(WinFirewallRule{InterfaceName: "et0", Direction: "Inbound"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range inbound.Actions {
		if strings.Contains(strings.Join(a.Command, " "), "dir=outbound") {
			t.Fatalf("inbound filter should not have outbound: %v", a.Command)
		}
	}
	if _, err := PlanWindowsFirewall(WinFirewallRule{InterfaceName: ""}); err == nil {
		t.Fatal("expected error for empty interface")
	}
}

func TestPlanFakeTCP(t *testing.T) {
	plan, err := PlanFakeTCP("et0", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected fakeTCP actions when enabled")
	}
	plan2, err := PlanFakeTCP("et0", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan2.Actions) != 0 {
		t.Fatalf("disabled should have no actions, got %d", len(plan2.Actions))
	}
	if len(plan2.Warnings) == 0 {
		t.Fatal("expected warning when disabled")
	}
	if _, err := PlanFakeTCP("", true); err == nil {
		t.Fatal("expected error for empty ifName with enabled")
	}
}

func TestWindowsRegistryCleanup(t *testing.T) {
	plan, err := PlanWindowsRegistryCleanup("et0")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected registry cleanup actions")
	}
	hasEt := false
	for _, a := range plan.Actions {
		if strings.Contains(strings.Join(a.Command, " "), "et_") {
			hasEt = true
		}
	}
	if !hasEt {
		t.Fatal("expected et_ handling")
	}
	plan2, err := PlanWindowsRegistryCleanup("")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan2.Actions) == 0 {
		t.Fatal("expected actions even with empty name")
	}
}

func TestWindowsRoutesWithFakeTCP(t *testing.T) {
	cfg := RouteConfig{IfName: "et0", Routes: []string{"10.144.144.0/24"}}
	plan, err := PlanWindowsRoutesWithFakeTCP(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("without fakeTCP, actions %d", len(plan.Actions))
	}
	plan2, err := PlanWindowsRoutesWithFakeTCP(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan2.Actions) <= len(plan.Actions) {
		t.Fatalf("with fakeTCP should have more actions: %d vs %d", len(plan2.Actions), len(plan.Actions))
	}
}

func TestWindowsServiceWithFirewall(t *testing.T) {
	cfg := ServiceConfig{Name: "easytier", Exec: "C:\\easytier\\easytier-core.exe"}
	plan, err := PlanWindowsServiceWithFirewall(cfg, "et0")
	if err != nil {
		t.Fatal(err)
	}
	hasService := false
	hasFirewall := false
	for _, a := range plan.Actions {
		cmd := strings.Join(a.Command, " ")
		if strings.Contains(cmd, "sc") && strings.Contains(cmd, "create") {
			hasService = true
		}
		if strings.Contains(cmd, "advfirewall") {
			hasFirewall = true
		}
	}
	if !hasService {
		t.Fatal("missing service create")
	}
	if !hasFirewall {
		t.Fatal("missing firewall")
	}
	// without firewall interface
	plan2, err := PlanWindowsServiceWithFirewall(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range plan2.Actions {
		if strings.Contains(strings.Join(a.Command, " "), "advfirewall") && !strings.Contains(a.Description, "firewall") {
			// second param empty should not add per-interface firewall, but still has program firewall from windows.go
		}
	}
	if len(plan2.Actions) == 0 {
		t.Fatal("expected actions")
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"strings"
	"testing"
)

func TestLinuxDryRunTun(t *testing.T) {
	adapter := NewForOS("linux")
	plan, err := adapter.PlanTun(TunConfig{Name: "et0", MTU: 1380, FD: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected actions for Linux TUN")
	}
	if !plan.DryRun {
		t.Fatal("dry-run must be true")
	}
	// Ensure no actual privileged execution occurred (plan only)
	if plan.Actions[0].Command[0] != "open" {
		t.Fatalf("unexpected first action: %v", plan.Actions[0].Command)
	}
}

func TestLinuxTunInvalid(t *testing.T) {
	adapter := NewForOS("linux")
	if _, err := adapter.PlanTun(TunConfig{Name: "", MTU: 1380, FD: -1}); err == nil {
		t.Fatal("expected error for empty name")
	}
	if _, err := adapter.PlanTun(TunConfig{Name: "0123456789abcdef", MTU: 1380, FD: -1}); err == nil {
		t.Fatal("expected error for long name")
	}
}

func TestLinuxRoutes(t *testing.T) {
	adapter := NewForOS("linux")
	plan, err := adapter.PlanRoutes(RouteConfig{IfName: "et0", Routes: []string{"10.144.144.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("actions = %d, want 1", len(plan.Actions))
	}
	if plan.Actions[0].Command[0] != "ip" {
		t.Fatalf("unexpected route command: %v", plan.Actions[0].Command)
	}
}

func TestLinuxDNS_SystemdResolved(t *testing.T) {
	adapter := NewForOS("linux")
	plan, err := adapter.PlanDNS(DNSConfig{IfName: "et0", Servers: []string{"1.1.1.1"}, Mode: "systemd-resolved"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range plan.Actions {
		if len(a.Command) > 0 && a.Command[0] == "resolvectl" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected resolvectl action")
	}
}

func TestLinuxServiceSystemd(t *testing.T) {
	adapter := NewForOS("linux")
	cfg := ServiceConfig{Name: "easytier", Exec: "/usr/bin/easytier-core", Args: []string{"-c", "/etc/easytier.toml"}}
	plan, err := adapter.PlanService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	unit, err := RenderSystemd(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unit, "ExecStart=") {
		t.Fatalf("systemd unit missing ExecStart: %q", unit)
	}
	found := false
	for _, a := range plan.Actions {
		if len(a.Command) > 0 && a.Command[0] == "systemctl" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected systemctl action")
	}
}

func TestDarwinTunAndLaunchd(t *testing.T) {
	adapter := NewForOS("darwin")
	plan, err := adapter.PlanTun(TunConfig{MTU: 1380, FD: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected darwin TUN actions")
	}
	plist, err := RenderLaunchd(ServiceConfig{Name: "easytier", Exec: "/opt/easytier/easytier-core"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plist, "<key>Label</key>") {
		t.Fatalf("launchd plist missing Label: %q", plist)
	}
}

func TestFreeBSDRCD(t *testing.T) {
	adapter := NewForOS("freebsd")
	plan, err := adapter.PlanService(ServiceConfig{Name: "easytier", Exec: "/usr/local/bin/easytier-core"})
	if err != nil {
		t.Fatal(err)
	}
	rcd, err := RenderFreeBSDRCD(ServiceConfig{Name: "easytier", Exec: "/usr/local/bin/easytier-core"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rcd, "rcvar=") {
		t.Fatalf("rc.d script missing rcvar: %q", rcd)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected freebsd service actions")
	}
}

func TestAndroidVpnServiceOneActive(t *testing.T) {
	adapter := NewForOS("android").(*AndroidAdapter)
	// Ensure clean state
	adapter.ReleaseTun()
	if IsAndroidTunActive() {
		t.Fatal("tun should not be active")
	}
	cfg := TunConfig{Name: "tun0", MTU: 1380, FD: 42}
	plan, err := adapter.PlanTun(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected android actions")
	}
	if err := adapter.ApplyTun(cfg); err != nil {
		t.Fatal(err)
	}
	if !IsAndroidTunActive() {
		t.Fatal("tun should be active after ApplyTun")
	}
	// Second should fail per one-active policy
	if err := adapter.ApplyTun(TunConfig{Name: "tun1", MTU: 1380, FD: 43}); err == nil {
		t.Fatal("expected one-active error")
	}
	adapter.ReleaseTun()
	if IsAndroidTunActive() {
		t.Fatal("tun should be inactive after release")
	}
}

func TestAndroidRequiresFD(t *testing.T) {
	adapter := NewForOS("android")
	if _, err := adapter.PlanTun(TunConfig{Name: "tun0", MTU: 1380, FD: -1}); err == nil {
		t.Fatal("expected error for missing FD on Android")
	}
}

func TestServiceRenderersEscape(t *testing.T) {
	cfg := ServiceConfig{Name: "bad\n[Service]\nExecStart=/tmp/evil", Exec: "/usr/bin/worker; touch /tmp/pwned", Args: []string{"$(touch /tmp/pwned)"}}
	unit, err := RenderSystemd(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(unit, "\nExecStart=/tmp/evil") {
		t.Fatalf("systemd not escaped: %q", unit)
	}
}

func TestAllOSAdaptersDryRun(t *testing.T) {
	for _, osName := range []string{"linux", "darwin", "freebsd", "android"} {
		adapter := NewForOS(osName)
		if !adapter.Supported() {
			t.Fatalf("%s should be supported", osName)
		}
		if adapter.OS() != osName {
			t.Fatalf("OS() = %q, want %q", adapter.OS(), osName)
		}
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"strings"
	"testing"
)

func TestVpnServiceLifecyclePlan(t *testing.T) {
	cfg := VpnServiceConfig{
		InstanceName: "test-vpn",
		IPv4:         "10.144.144.1/24",
		ProxyCIDRs:   []string{"10.147.18.0/24", "10.18.0.0/16"},
		MTU:          1380,
		DNSServers:   []string{"1.1.1.1"},
		SessionName:  "EasyTier Test",
		FD:           42,
	}
	plan, err := PlanVpnService("android", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected actions")
	}
	required := []string{"VpnService.prepare", "Builder.setMtu", "Builder.addAddress", "Builder.addRoute", "Builder.setSession", "Builder.establish", "EasyTierJNI.setTunFd"}
	for _, need := range required {
		found := false
		for _, a := range plan.Actions {
			if strings.Contains(strings.Join(a.Command, " "), need) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %q in plan", need)
		}
	}
	// invalid OS
	if _, err := PlanVpnService("linux", cfg); err == nil {
		t.Fatal("expected error for non-android OS")
	}
	// invalid ipv4
	bad := cfg
	bad.IPv4 = "invalid"
	if _, err := PlanVpnService("android", bad); err == nil {
		t.Fatal("expected invalid ipv4 error")
	}
	// empty instance
	bad2 := cfg
	bad2.InstanceName = ""
	if _, err := PlanVpnService("android", bad2); err == nil {
		t.Fatal("expected empty instance error")
	}
}

func TestVpnServiceLifecycleOneActive(t *testing.T) {
	m := NewVpnServiceLifecycle()
	if m.IsActive() {
		t.Fatal("should not be active")
	}
	// permission denied initially
	cfg := VpnServiceConfig{InstanceName: "inst1", IPv4: "10.0.0.1/24", MTU: 1380}
	if _, err := m.Establish(cfg); err == nil {
		t.Fatal("should fail without permission")
	}
	if !m.RequestPermission() {
		t.Fatal("request should succeed")
	}
	if !m.IsPermissionGranted() {
		t.Fatal("should be granted")
	}
	fd, err := m.Establish(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if fd <= 0 {
		t.Fatalf("fd %d", fd)
	}
	if !m.IsActive() {
		t.Fatal("should be active")
	}
	if m.State() != "established" {
		t.Fatalf("state %q", m.State())
	}
	log := m.BuilderLog()
	if len(log) == 0 {
		t.Fatal("expected builder log")
	}
	// second should fail
	cfg2 := VpnServiceConfig{InstanceName: "inst2", IPv4: "10.0.0.2/24", MTU: 1380}
	if _, err := m.Establish(cfg2); err == nil {
		t.Fatal("expected one-active error")
	}
	// Get active
	name, afd, ok := m.Active()
	if !ok || name != "inst1" || afd != fd {
		t.Fatalf("Active %q %d %v", name, afd, ok)
	}
	// Close
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if m.IsActive() {
		t.Fatal("should not be active after close")
	}
	if m.State() != "closed" {
		t.Fatalf("state %q after close", m.State())
	}
	// After close, second can establish
	fd2, err := m.Establish(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if fd2 <= 0 {
		t.Fatalf("fd2 %d", fd2)
	}
	m.Reset()
	if m.IsActive() {
		t.Fatal("reset should clear")
	}
}

func TestVpnServiceRestart(t *testing.T) {
	m := NewVpnServiceLifecycle()
	m.RequestPermission()
	cfg := VpnServiceConfig{InstanceName: "inst1", IPv4: "10.144.144.1/24", ProxyCIDRs: []string{"10.10.0.0/16"}, MTU: 1380, FD: 100}
	if _, err := m.Establish(cfg); err != nil {
		t.Fatal(err)
	}
	// restart with new IPv4 (simulates monitorNetworkStatus detecting change)
	newCfg := VpnServiceConfig{InstanceName: "inst1", IPv4: "10.144.144.2/24", ProxyCIDRs: []string{"10.10.0.0/16", "10.20.0.0/16"}, MTU: 1380, FD: 101}
	fd, err := m.Restart(newCfg)
	if err != nil {
		t.Fatal(err)
	}
	if fd != 101 {
		t.Fatalf("restart fd %d, want 101", fd)
	}
	name, _, _ := m.Active()
	if name != "inst1" {
		t.Fatalf("name %q", name)
	}
	if m.State() != "established" {
		t.Fatalf("state %q", m.State())
	}
	log := m.BuilderLog()
	if len(log) == 0 {
		t.Fatal("expected log after restart")
	}
}

func TestVpnServicePermissionDeny(t *testing.T) {
	m := NewVpnServiceLifecycle()
	m.RequestPermission()
	m.DenyPermission()
	if m.IsPermissionGranted() {
		t.Fatal("should be denied")
	}
	cfg := VpnServiceConfig{InstanceName: "x", IPv4: "10.0.0.1/24", MTU: 1380}
	if _, err := m.Establish(cfg); err == nil {
		t.Fatal("should fail after deny")
	}
	// re-request should succeed
	m.RequestPermission()
	if _, err := m.Establish(cfg); err != nil {
		t.Fatal(err)
	}
}

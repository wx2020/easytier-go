// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package jni

import (
	"testing"
)

func TestVpnServiceManagerLifecycle(t *testing.T) {
	m := NewVpnServiceManager()
	if m.IsActive() {
		t.Fatal("should not be active initially")
	}
	if m.IsPermissionGranted() {
		t.Fatal("permission should not be granted initially")
	}
	// Deny then prepare
	m.DenyPermission()
	if m.IsPermissionGranted() {
		t.Fatal("deny should clear permission")
	}
	if !m.Prepare() {
		t.Fatal("prepare should grant permission")
	}
	if !m.IsPermissionGranted() {
		t.Fatal("permission should be granted after prepare")
	}
	// Establish
	cfg := VpnServiceConfig{
		InstanceName: "test-vpn",
		IPv4:         "10.144.144.1/24",
		ProxyCIDRs:   []string{"10.147.18.0/24"},
		MTU:          1380,
		DNSServers:   []string{"1.1.1.1"},
		SessionName:  "Test",
	}
	fd, err := m.Establish(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if fd < 0 {
		t.Fatalf("fd %d invalid", fd)
	}
	if !m.IsActive() {
		t.Fatal("should be active after establish")
	}
	if m.State() != VpnStateEstablished {
		t.Fatalf("state = %q, want established", m.State())
	}
	actions := m.BuilderActions()
	if len(actions) == 0 {
		t.Fatal("expected builder actions")
	}
	// one-active should fail for second instance
	m2cfg := VpnServiceConfig{
		InstanceName: "second",
		IPv4:         "10.144.144.2/24",
		MTU:          1380,
	}
	if _, err := m.Establish(m2cfg); err == nil {
		t.Fatal("expected one-active error")
	}
	// GetActive
	name, activeFD, ok := m.GetActive()
	if !ok || name != "test-vpn" || activeFD != fd {
		t.Fatalf("GetActive = %q %d %v, want test-vpn %d true", name, activeFD, ok, fd)
	}
	// Close
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if m.IsActive() {
		t.Fatal("should not be active after close")
	}
	// Restart
	if !m.Prepare() {
		t.Fatal("prepare for restart")
	}
	fd2, err := m.Restart(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if fd2 < 0 {
		t.Fatalf("restart fd %d", fd2)
	}
	if !m.IsActive() {
		t.Fatal("should be active after restart")
	}
	m.Reset()
	if m.IsActive() {
		t.Fatal("reset should clear active")
	}
}

func TestVpnServiceConfigValidate(t *testing.T) {
	good := VpnServiceConfig{InstanceName: "a", IPv4: "10.0.0.1/24", MTU: 1380}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := VpnServiceConfig{InstanceName: "", IPv4: "10.0.0.1/24"}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected error for empty instanceName")
	}
	bad2 := VpnServiceConfig{InstanceName: "a", IPv4: "invalid"}
	if err := bad2.Validate(); err == nil {
		t.Fatal("expected invalid ipv4 error")
	}
	bad3 := VpnServiceConfig{InstanceName: "a", IPv4: "10.0.0.1/24", ProxyCIDRs: []string{"bad"}}
	if err := bad3.Validate(); err == nil {
		t.Fatal("expected invalid proxy cidr error")
	}
}

func TestVpnServiceSetTunFd(t *testing.T) {
	m := NewVpnServiceManager()
	m.Prepare()
	if err := m.SetTunFd("inst1", 42); err != nil {
		t.Fatal(err)
	}
	if err := m.SetTunFd("inst2", 43); err == nil {
		t.Fatal("expected one-active for setTunFd")
	}
	if err := m.SetTunFd("inst1", -1); err == nil {
		t.Fatal("expected error for negative fd")
	}
	m.Reset()
	if err := m.SetTunFd("inst1", 100); err != nil {
		t.Fatal(err)
	}
	if _, fd, _ := m.GetActive(); fd != 100 {
		t.Fatalf("fd %d", fd)
	}
}

func TestVpnServicePermissionDenied(t *testing.T) {
	m := NewVpnServiceManager()
	cfg := VpnServiceConfig{InstanceName: "a", IPv4: "10.0.0.1/24", MTU: 1380}
	if _, err := m.Establish(cfg); err == nil {
		t.Fatal("should fail without permission")
	}
	m.Prepare()
	if _, err := m.Establish(cfg); err != nil {
		t.Fatal(err)
	}
}

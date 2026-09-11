// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// VpnServiceLifecycle mirrors Android VpnService permission + Builder + restart (NTV-03).
type VpnServiceLifecycle struct {
	mu                sync.Mutex
	permissionGranted bool
	activeInstance    string
	activeFD          int
	builderLog        []string
	mtu               int
	ipv4              string
	proxyCIDRs        []string
	dnsServers        []string
	state             string // idle, preparing, established, closed, failed
}

func NewVpnServiceLifecycle() *VpnServiceLifecycle {
	return &VpnServiceLifecycle{activeFD: -1, state: "idle"}
}

// RequestPermission simulates VpnService.prepare() check.
func (v *VpnServiceLifecycle) RequestPermission() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.permissionGranted {
		return true
	}
	v.state = "preparing"
	v.permissionGranted = true
	v.state = "idle"
	return true
}

func (v *VpnServiceLifecycle) IsPermissionGranted() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.permissionGranted
}

func (v *VpnServiceLifecycle) DenyPermission() {
	v.mu.Lock()
	v.permissionGranted = false
	v.state = "idle"
	v.mu.Unlock()
}

// PlanVpnService returns the dry-run plan for VpnService.Builder operations.
// Mirrors EasyTierManager.monitorNetworkStatus -> restartVpnService logic.
func PlanVpnService(osName string, cfg VpnServiceConfig) (Plan, error) {
	if osName != "android" {
		return Plan{}, fmt.Errorf("%w: VpnService only on android", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.InstanceName) == "" {
		return Plan{}, fmt.Errorf("%w: instanceName required", ErrInvalidConfig)
	}
	if _, err := netip.ParsePrefix(cfg.IPv4); err != nil {
		return Plan{}, fmt.Errorf("%w: invalid ipv4 %q: %v", ErrInvalidConfig, cfg.IPv4, err)
	}
	for _, cidr := range cfg.ProxyCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return Plan{}, fmt.Errorf("%w: invalid proxy cidr %q: %v", ErrInvalidConfig, cidr, err)
		}
	}
	plan := newPlan("android")
	plan.Add("VpnService.prepare check", []string{"VpnService.prepare", cfg.InstanceName}, false, nil)
	plan.Add("Builder.setMtu", []string{"Builder.setMtu", fmt.Sprintf("%d", cfg.MTU)}, false, nil)
	plan.Add("Builder.addAddress", []string{"Builder.addAddress", cfg.IPv4}, false, nil)
	for _, cidr := range cfg.ProxyCIDRs {
		plan.Add("Builder.addRoute", []string{"Builder.addRoute", cidr}, false, []string{"Builder.removeRoute", cidr})
	}
	for _, dns := range cfg.DNSServers {
		plan.Add("Builder.addDnsServer", []string{"Builder.addDnsServer", dns}, false, nil)
	}
	if cfg.FakeIP != "" {
		plan.Add("Builder.addAddress (fake)", []string{"Builder.addAddress", cfg.FakeIP}, false, nil)
	}
	plan.Add("Builder.setSession", []string{"Builder.setSession", cfg.InstanceName}, false, nil)
	plan.Add("Builder.establish (returns ParcelFileDescriptor)", []string{"Builder.establish"}, false, []string{"ParcelFileDescriptor.close"})
	plan.Add("setTunFd injection", []string{"EasyTierJNI.setTunFd", cfg.InstanceName, fmt.Sprintf("fd=%d", cfg.FD)}, false, []string{"close fd"})
	plan.Warnings = append(plan.Warnings, "VpnService owns FD lifecycle; one-active-TUN enforced")
	return plan, nil
}

// VpnServiceConfig is the expanded config for VpnService.Builder (NTV-03).
type VpnServiceConfig struct {
	InstanceName string
	IPv4         string // CIDR
	ProxyCIDRs   []string
	MTU          int
	DNSServers   []string
	SessionName  string
	FakeIP       string
	FD           int // if >0, use injected; else establish() provides
}

// Establish performs one-active-TUN checked establish.
func (v *VpnServiceLifecycle) Establish(cfg VpnServiceConfig) (int, error) {
	if _, err := PlanVpnService("android", cfg); err != nil {
		return -1, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.permissionGranted {
		v.state = "failed"
		return -1, fmt.Errorf("VpnService permission not granted")
	}
	if v.activeInstance != "" && v.activeInstance != cfg.InstanceName {
		v.state = "failed"
		return -1, ErrOneActiveTUN
	}
	v.builderLog = nil
	v.builderLog = append(v.builderLog, fmt.Sprintf("setMtu=%d", cfg.MTU))
	v.builderLog = append(v.builderLog, fmt.Sprintf("addAddress=%s", cfg.IPv4))
	for _, r := range cfg.ProxyCIDRs {
		v.builderLog = append(v.builderLog, fmt.Sprintf("addRoute=%s", r))
	}
	v.builderLog = append(v.builderLog, "establish")
	fd := cfg.FD
	if fd <= 0 {
		fd = 200
	}
	v.activeInstance = cfg.InstanceName
	v.activeFD = fd
	v.ipv4 = cfg.IPv4
	v.proxyCIDRs = append([]string(nil), cfg.ProxyCIDRs...)
	v.dnsServers = append([]string(nil), cfg.DNSServers...)
	v.mtu = cfg.MTU
	v.state = "established"
	return fd, nil
}

// Restart closes then re-establishes (monitorNetworkStatus change detection).
func (v *VpnServiceLifecycle) Restart(cfg VpnServiceConfig) (int, error) {
	_ = v.Close()
	v.mu.Lock()
	v.state = "idle"
	v.permissionGranted = true
	v.mu.Unlock()
	return v.Establish(cfg)
}

func (v *VpnServiceLifecycle) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.activeInstance == "" {
		v.state = "closed"
		return nil
	}
	v.builderLog = append(v.builderLog, "ParcelFileDescriptor.close")
	v.builderLog = append(v.builderLog, "VpnService.close")
	v.activeInstance = ""
	v.activeFD = -1
	v.state = "closed"
	return nil
}

func (v *VpnServiceLifecycle) IsActive() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.activeInstance != ""
}

func (v *VpnServiceLifecycle) Active() (string, int, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.activeInstance == "" {
		return "", -1, false
	}
	return v.activeInstance, v.activeFD, true
}

func (v *VpnServiceLifecycle) BuilderLog() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]string, len(v.builderLog))
	copy(out, v.builderLog)
	return out
}

func (v *VpnServiceLifecycle) State() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.state
}

func (v *VpnServiceLifecycle) Reset() {
	v.mu.Lock()
	v.activeInstance = ""
	v.activeFD = -1
	v.builderLog = nil
	v.state = "idle"
	v.permissionGranted = false
	v.ipv4 = ""
	v.proxyCIDRs = nil
	v.dnsServers = nil
	v.mu.Unlock()
}

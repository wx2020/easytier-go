// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package jni

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// VpnServiceState mirrors Android VpnService lifecycle (NTV-03).
type VpnServiceState string

const (
	VpnStateIdle        VpnServiceState = "idle"
	VpnStatePreparing   VpnServiceState = "preparing"
	VpnStateEstablished VpnServiceState = "established"
	VpnStateFailed      VpnServiceState = "failed"
	VpnStateClosed      VpnServiceState = "closed"
)

// VpnServiceConfig describes desired VPN tunnel via VpnService.Builder.
type VpnServiceConfig struct {
	InstanceName string
	IPv4         string   // CIDR e.g. 10.144.144.1/24
	ProxyCIDRs   []string // CIDRs to route via VPN
	MTU          int
	DNSServers   []string
	SessionName  string
	FD           int // injected fd after Builder.establish()
}

// Validate checks VpnService config.
func (c VpnServiceConfig) Validate() error {
	if c.InstanceName == "" {
		return fmt.Errorf("%w: instanceName required", ErrInvalidConfig)
	}
	if c.IPv4 == "" {
		return fmt.Errorf("%w: ipv4 required", ErrInvalidConfig)
	}
	if _, err := netip.ParsePrefix(c.IPv4); err != nil {
		return fmt.Errorf("%w: invalid ipv4 %q: %v", ErrInvalidConfig, c.IPv4, err)
	}
	for _, cidr := range c.ProxyCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("%w: invalid proxy_cidr %q: %v", ErrInvalidConfig, cidr, err)
		}
	}
	if c.MTU < 0 || c.MTU > 65535 {
		return fmt.Errorf("%w: mtu %d", ErrInvalidConfig, c.MTU)
	}
	return nil
}

// VpnServiceManager enforces one-active-TUN and VpnService permission lifecycle.
type VpnServiceManager struct {
	mu           sync.Mutex
	state        VpnServiceState
	activeTUN    string // instanceName holding TUN
	activeFD     int
	permissionGranted bool
	builderActions []string
	instanceFDs  map[string]int
	lastError    string
}

func NewVpnServiceManager() *VpnServiceManager {
	return &VpnServiceManager{
		state:       VpnStateIdle,
		activeFD:    -1,
		instanceFDs: make(map[string]int),
	}
}

var DefaultVpnServiceManager = NewVpnServiceManager()

// Prepare requests VpnService permission (dry-run).
func (m *VpnServiceManager) Prepare() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.permissionGranted {
		return true
	}
	m.state = VpnStatePreparing
	// Simulate permission grant; in real Android this would launch intent.
	m.permissionGranted = true
	m.state = VpnStateIdle
	return true
}

// IsPermissionGranted reports whether VpnService permission is granted.
func (m *VpnServiceManager) IsPermissionGranted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.permissionGranted
}

// DenyPermission simulates user denying VpnService permission (for tests).
func (m *VpnServiceManager) DenyPermission() {
	m.mu.Lock()
	m.permissionGranted = false
	m.state = VpnStateIdle
	m.mu.Unlock()
}

// Establish simulates VpnService.Builder.establish() and FD injection.
func (m *VpnServiceManager) Establish(cfg VpnServiceConfig) (int, error) {
	if err := cfg.Validate(); err != nil {
		return -1, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.permissionGranted {
		m.lastError = "VpnService permission not granted"
		return -1, errors.New(m.lastError)
	}
	if m.activeTUN != "" && m.activeTUN != cfg.InstanceName {
		m.lastError = "one-active-TUN: existing tunnel must be closed"
		return -1, ErrOneActiveTUN
	}
	m.builderActions = nil
	m.builderActions = append(m.builderActions, fmt.Sprintf("Builder.setMtu(%d)", cfg.MTU))
	m.builderActions = append(m.builderActions, fmt.Sprintf("Builder.addAddress(%s)", cfg.IPv4))
	for _, cidr := range cfg.ProxyCIDRs {
		m.builderActions = append(m.builderActions, fmt.Sprintf("Builder.addRoute(%s)", cidr))
	}
	for _, dns := range cfg.DNSServers {
		m.builderActions = append(m.builderActions, fmt.Sprintf("Builder.addDnsServer(%s)", dns))
	}
	session := cfg.SessionName
	if session == "" {
		session = "EasyTier VPN"
	}
	m.builderActions = append(m.builderActions, fmt.Sprintf("Builder.setSession(%s)", session))
	fd := cfg.FD
	if fd <= 0 {
		fd = 100 + len(m.instanceFDs) + 1 // simulated FD
	}
	m.builderActions = append(m.builderActions, fmt.Sprintf("Builder.establish() -> fd=%d", fd))
	m.activeTUN = cfg.InstanceName
	m.activeFD = fd
	m.instanceFDs[cfg.InstanceName] = fd
	m.state = VpnStateEstablished
	m.lastError = ""
	return fd, nil
}

// SetTunFd injects an externally obtained FD (from ParcelFileDescriptor).
func (m *VpnServiceManager) SetTunFd(instanceName string, fd int) error {
	if fd < 0 {
		return fmt.Errorf("%w: invalid fd %d", ErrInvalidConfig, fd)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeTUN != "" && m.activeTUN != instanceName {
		return ErrOneActiveTUN
	}
	m.activeTUN = instanceName
	m.activeFD = fd
	m.instanceFDs[instanceName] = fd
	m.state = VpnStateEstablished
	return nil
}

// GetActive returns current active TUN info.
func (m *VpnServiceManager) GetActive() (string, int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeTUN == "" {
		return "", -1, false
	}
	return m.activeTUN, m.activeFD, true
}

// Close releases the active TUN (VpnService.close / ParcelFileDescriptor.close).
func (m *VpnServiceManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeTUN == "" {
		m.state = VpnStateClosed
		return nil
	}
	m.builderActions = append(m.builderActions, "ParcelFileDescriptor.close()")
	m.builderActions = append(m.builderActions, "VpnService.close()")
	delete(m.instanceFDs, m.activeTUN)
	m.activeTUN = ""
	m.activeFD = -1
	m.state = VpnStateClosed
	m.lastError = ""
	return nil
}

// Restart closes existing and establishes new config (mirrors EasyTierManager.restartVpnService).
func (m *VpnServiceManager) Restart(cfg VpnServiceConfig) (int, error) {
	_ = m.Close()
	m.mu.Lock()
	m.state = VpnStateIdle
	m.permissionGranted = true // retain permission across restart
	m.mu.Unlock()
	return m.Establish(cfg)
}

// BuilderActions returns the sequence of Builder calls for verification (dry-run).
func (m *VpnServiceManager) BuilderActions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.builderActions))
	copy(out, m.builderActions)
	return out
}

// State returns current VpnService state.
func (m *VpnServiceManager) State() VpnServiceState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// IsActive reports whether a TUN is currently active.
func (m *VpnServiceManager) IsActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeTUN != ""
}

// Reset clears all state (for tests).
func (m *VpnServiceManager) Reset() {
	m.mu.Lock()
	m.activeTUN = ""
	m.activeFD = -1
	m.instanceFDs = make(map[string]int)
	m.builderActions = nil
	m.state = VpnStateIdle
	m.permissionGranted = false
	m.lastError = ""
	m.mu.Unlock()
}

// LastError returns last VpnService error.
func (m *VpnServiceManager) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastError
}

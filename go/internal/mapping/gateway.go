// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package mapping provides UPnP IGD and NAT-PMP port mapping with a mockable
// Gateway interface, lease renewal, and mapped listener management.
package mapping

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// LeaseDuration is the UPnP lease duration, matching Rust UPNP_LEASE_DURATION_SECS = 300.
const LeaseDuration = 300 * time.Second

// RenewInterval is the renewal period, matching Rust UPNP_RENEW_INTERVAL = 240s.
const RenewInterval = 240 * time.Second

// Description is the port mapping description, matching Rust UPNP_DESCRIPTION.
const Description = "EasyTier udp hole punch"

// Backend names matching Rust.
const (
	BackendIGD    = "igd"
	BackendNATPMP = "nat-pmp"
)

// Gateway is a mockable router gateway that can create and remove UDP port mappings.
// This abstracts both IGD (UPnP) and NAT-PMP backends.
type Gateway interface {
	// AddAnyPort creates a UDP mapping for localAddr with any external port, using lease.
	// Returns the allocated external port.
	AddAnyPort(ctx context.Context, localAddr netip.AddrPort, lease time.Duration, description string) (uint16, error)
	// AddPort creates a UDP mapping for localAddr with a specific externalPort.
	AddPort(ctx context.Context, externalPort uint16, localAddr netip.AddrPort, lease time.Duration, description string) error
	// RemovePort removes the UDP mapping for externalPort.
	RemovePort(ctx context.Context, externalPort uint16) error
	// GetExternalIP returns the gateway's external IP.
	GetExternalIP(ctx context.Context) (netip.Addr, error)
	// Backend returns the backend name ("igd" or "nat-pmp").
	Backend() string
}

// Discovery discovers a gateway. Used for dependency injection and testing.
type Discovery func(ctx context.Context) (Gateway, error)

// PortMappingEntry represents a stored mapping for introspection.
type PortMappingEntry struct {
	ExternalPort uint16
	InternalAddr netip.AddrPort
	Protocol     string
	Description  string
	Lease        time.Duration
	ExpiresAt    time.Time
}

// MockGateway simulates a router emulator like Rust's miniupnpd test.
// It stores UDP mappings with expiry and simulates lease durations.
type MockGateway struct {
	mu         sync.Mutex
	mappings   map[uint16]*PortMappingEntry
	externalIP netip.Addr
	nextPort   uint16
	backend    string
	// fail flags simulate discovery or mapping failures for fallback tests.
	FailAddAny     bool
	FailAddPort    bool
	FailRemove     bool
	FailExternalIP bool
}

// NewMockGateway creates a mock gateway with the given external IP and backend.
func NewMockGateway(externalIP netip.Addr, backend string) *MockGateway {
	if !externalIP.IsValid() {
		externalIP = netip.MustParseAddr("11.22.33.44")
	}
	if backend == "" {
		backend = BackendIGD
	}
	return &MockGateway{
		mappings:   make(map[uint16]*PortMappingEntry),
		externalIP: externalIP,
		nextPort:   50000,
		backend:    backend,
	}
}

func (m *MockGateway) Backend() string { return m.backend }

func (m *MockGateway) AddAnyPort(ctx context.Context, localAddr netip.AddrPort, lease time.Duration, description string) (uint16, error) {
	if m.FailAddAny {
		return 0, fmt.Errorf("mock gateway %s: AddAnyPort failed", m.backend)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Try to find next free port.
	for i := 0; i < 1000; i++ {
		port := m.nextPort
		m.nextPort++
		if m.nextPort == 0 {
			m.nextPort = 50000
		}
		if _, exists := m.mappings[port]; !exists {
			m.mappings[port] = &PortMappingEntry{
				ExternalPort: port,
				InternalAddr: localAddr,
				Protocol:     "UDP",
				Description:  description,
				Lease:        lease,
				ExpiresAt:    time.Now().Add(lease),
			}
			return port, nil
		}
	}
	return 0, fmt.Errorf("mock gateway: no free port")
}

func (m *MockGateway) AddPort(ctx context.Context, externalPort uint16, localAddr netip.AddrPort, lease time.Duration, description string) error {
	if m.FailAddPort {
		return fmt.Errorf("mock gateway %s: AddPort failed", m.backend)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if lease == 0 {
		// removal via lease 0 (NAT-PMP removal)
		delete(m.mappings, externalPort)
		return nil
	}
	// Renew or create: if mapping exists, update expiry; otherwise create.
	m.mappings[externalPort] = &PortMappingEntry{
		ExternalPort: externalPort,
		InternalAddr: localAddr,
		Protocol:     "UDP",
		Description:  description,
		Lease:        lease,
		ExpiresAt:    time.Now().Add(lease),
	}
	return nil
}

func (m *MockGateway) RemovePort(ctx context.Context, externalPort uint16) error {
	if m.FailRemove {
		return fmt.Errorf("mock gateway %s: RemovePort failed", m.backend)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mappings, externalPort)
	return nil
}

func (m *MockGateway) GetExternalIP(ctx context.Context) (netip.Addr, error) {
	if m.FailExternalIP {
		return netip.Addr{}, fmt.Errorf("mock gateway %s: GetExternalIP failed", m.backend)
	}
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	return m.externalIP, nil
}

// ListMappings returns non-expired mappings (expired entries are purged lazily).
func (m *MockGateway) ListMappings() []PortMappingEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var result []PortMappingEntry
	for port, entry := range m.mappings {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(m.mappings, port)
			continue
		}
		result = append(result, *entry)
	}
	return result
}

// HasMapping reports whether a non-expired mapping for externalPort exists.
func (m *MockGateway) HasMapping(externalPort uint16) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.mappings[externalPort]
	if !ok {
		return false
	}
	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		delete(m.mappings, externalPort)
		return false
	}
	return true
}

// GetMapping returns the mapping for externalPort if present and not expired.
func (m *MockGateway) GetMapping(externalPort uint16) (*PortMappingEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.mappings[externalPort]
	if !ok {
		return nil, false
	}
	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		delete(m.mappings, externalPort)
		return nil, false
	}
	copy := *entry
	return &copy, true
}

// CleanupExpired removes expired mappings, simulating lease expiry.
func (m *MockGateway) CleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for port, entry := range m.mappings {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(m.mappings, port)
		}
	}
}

// Count returns number of non-expired mappings.
func (m *MockGateway) Count() int {
	return len(m.ListMappings())
}

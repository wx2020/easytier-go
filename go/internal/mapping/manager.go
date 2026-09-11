// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package mapping

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Manager stores mapped listeners and reports status.
// It mirrors Rust's TomlConfigLoader mapped_listeners handling.
type Manager struct {
	mu        sync.RWMutex
	listeners map[string]string // url -> state ("active")
}

// NewManager creates a Manager with optional initial listeners.
func NewManager(initial []string) *Manager {
	m := &Manager{listeners: make(map[string]string)}
	for _, u := range initial {
		if err := ValidateMappedListenerURL(u); err == nil {
			m.listeners[u] = "active"
		}
	}
	return m
}

// ValidateMappedListenerURL validates a mapped listener URL.
// Mirrors Rust validate_mapped_listener_url: port required unless scheme is IP-based (tcp/udp/ws/wss/wg/quic/faketcp).
func ValidateMappedListenerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("mapped listener is not a valid url: %q: %w", raw, err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("mapped listener port is missing: %q", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	// IP-based schemes allow implicit port (use default)
	ipSchemes := map[string]bool{
		"tcp": true, "udp": true, "ws": true, "wss": true, "wg": true, "quic": true, "faketcp": true,
	}
	allowsImplicit := ipSchemes[scheme]
	if u.Port() == "" && !allowsImplicit {
		return fmt.Errorf("mapped listener port is missing: %q", raw)
	}
	// Check host presence for non-unix
	if u.Host == "" {
		return fmt.Errorf("mapped listener host is missing: %q", raw)
	}
	return nil
}

// List returns sorted listener statuses.
func (m *Manager) List() []MappedListenerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]MappedListenerStatus, 0, len(m.listeners))
	for u, state := range m.listeners {
		result = append(result, MappedListenerStatus{URL: u, State: state})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].URL < result[j].URL })
	return result
}

// MappedListenerStatus mirrors management.MappedListenerStatus for internal use.
type MappedListenerStatus struct {
	URL   string `json:"url"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

// Add stores a new mapped listener.
func (m *Manager) Add(raw string) error {
	if err := ValidateMappedListenerURL(raw); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.listeners[raw]; exists {
		return fmt.Errorf("mapped listener already exists: %q", raw)
	}
	m.listeners[raw] = "active"
	return nil
}

// Remove deletes a mapped listener.
func (m *Manager) Remove(raw string) error {
	if err := ValidateMappedListenerURL(raw); err != nil {
		// Allow removal even if validation fails? Check exact raw string match instead.
		// If URL is invalid but exists in store, allow removal by exact match fallback.
		m.mu.Lock()
		defer m.mu.Unlock()
		if _, exists := m.listeners[raw]; exists {
			delete(m.listeners, raw)
			return nil
		}
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.listeners[raw]; !exists {
		return fmt.Errorf("mapped listener not found: %q", raw)
	}
	delete(m.listeners, raw)
	return nil
}

// Contains reports whether the listener is stored.
func (m *Manager) Contains(raw string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.listeners[raw]
	return ok
}

// URLs returns sorted listener URLs for config persistence.
func (m *Manager) URLs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	urls := make([]string, 0, len(m.listeners))
	for u := range m.listeners {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return urls
}

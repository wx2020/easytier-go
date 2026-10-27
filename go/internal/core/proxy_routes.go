// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package core

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/platform"
)

// defaultProxyRouteOS is the command dialect used when OSName is unset.
var defaultProxyRouteOS = runtime.GOOS

// execCommand runs one planned route command.
func execCommand(command []string) error {
	if len(command) == 0 {
		return nil
	}
	out, err := exec.Command(command[0], command[1:]...).CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if strings.Contains(text, "File exists") {
			return nil
		}
		return fmt.Errorf("%s: %w (%s)", strings.Join(command, " "), err, text)
	}
	return nil
}

// ProxyRouteManager keeps the kernel routes for remote peers' proxy networks in
// sync with the routing table. The reference daemon installs a route per
// withdrawn/advertised remote proxy CIDR so traffic to those subnets enters the
// overlay through the TUN device; without it, learned proxy networks stay
// invisible to the host.
type ProxyRouteManager struct {
	// OSName selects the command dialect (linux, darwin, freebsd, windows).
	OSName string
	// IfName is the overlay interface routes point at.
	IfName string
	// Metric overrides the per-OS default route metric.
	Metric int
	// Run replaces the command executor; nil uses exec.Command.
	Run func(command []string) error

	mu        sync.Mutex
	installed map[string]bool
}

// normalizeCIDRs parses, masks and sorts unique CIDRs, dropping invalid
// entries (reported through the returned warnings).
func normalizeCIDRs(cidrs []string) (valid []string, warnings []string) {
	seen := make(map[string]bool, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("invalid proxy cidr %q: %v", cidr, err))
			continue
		}
		key := prefix.Masked().String()
		if seen[key] {
			continue
		}
		seen[key] = true
		valid = append(valid, key)
	}
	sort.Strings(valid)
	return valid, warnings
}

func (m *ProxyRouteManager) run(command []string) error {
	if m.Run != nil {
		return m.Run(command)
	}
	return execCommand(command)
}

// Sync installs routes for cidrs that are not yet present and removes the ones
// that disappeared. It returns the CIDRs it added and removed.
func (m *ProxyRouteManager) Sync(cidrs []string) (added, removed []string, warnings []string, err error) {
	desired, warnings := normalizeCIDRs(cidrs)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.installed == nil {
		m.installed = make(map[string]bool)
	}

	desiredSet := make(map[string]bool, len(desired))
	for _, cidr := range desired {
		desiredSet[cidr] = true
	}
	var gone []string
	for cidr := range m.installed {
		if !desiredSet[cidr] {
			gone = append(gone, cidr)
		}
	}
	sort.Strings(gone)

	for _, cidr := range gone {
		plan, planErr := platform.CleanupRoutes(m.osName(), platform.RouteConfig{IfName: m.IfName, Routes: []string{cidr}})
		if planErr != nil {
			return added, removed, warnings, fmt.Errorf("plan proxy route cleanup %s: %w", cidr, planErr)
		}
		if err := m.execute(plan); err != nil {
			return added, removed, warnings, fmt.Errorf("remove proxy route %s: %w", cidr, err)
		}
		delete(m.installed, cidr)
		removed = append(removed, cidr)
	}

	var fresh []string
	for _, cidr := range desired {
		if !m.installed[cidr] {
			fresh = append(fresh, cidr)
		}
	}
	sort.Strings(fresh)

	for _, cidr := range fresh {
		plan, planErr := platform.PlanRoutes(m.osName(), platform.RouteConfig{IfName: m.IfName, Routes: []string{cidr}, Metric: m.Metric})
		if planErr != nil {
			return added, removed, warnings, fmt.Errorf("plan proxy route %s: %w", cidr, planErr)
		}
		if err := m.execute(plan); err != nil {
			return added, removed, warnings, fmt.Errorf("install proxy route %s: %w", cidr, err)
		}
		m.installed[cidr] = true
		added = append(added, cidr)
	}
	return added, removed, warnings, nil
}

// Clear removes every route the manager installed.
func (m *ProxyRouteManager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for cidr := range m.installed {
		plan, planErr := platform.CleanupRoutes(m.osName(), platform.RouteConfig{IfName: m.IfName, Routes: []string{cidr}})
		if planErr != nil {
			errs = append(errs, planErr)
			continue
		}
		if err := m.execute(plan); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(m.installed, cidr)
	}
	m.installed = map[string]bool{}
	return errors.Join(errs...)
}

func (m *ProxyRouteManager) osName() string {
	if m.OSName != "" {
		return m.OSName
	}
	return defaultProxyRouteOS
}

func (m *ProxyRouteManager) execute(plan platform.Plan) error {
	var errs []error
	for _, action := range plan.Actions {
		if len(action.Command) == 0 {
			continue
		}
		if err := m.run(action.Command); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

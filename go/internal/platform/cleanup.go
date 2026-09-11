// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"strings"
)

// CleanupManager tracks applied state so it can be rolled back on normal exit
// and provides crash-recovery detection for stale EasyTier interfaces.
type CleanupManager struct {
	OS        string
	IfName    string
	Applied   []PlannedAction
	Rollbacks [][]string
}

// NewCleanupManager creates a manager for interface ifName on osName.
func NewCleanupManager(osName, ifName string) *CleanupManager {
	return &CleanupManager{OS: osName, IfName: ifName}
}

// Track merges a Plan's actions into the manager so Close can roll them back.
func (m *CleanupManager) Track(plan Plan) {
	for _, a := range plan.Actions {
		m.Applied = append(m.Applied, a)
		if len(a.Rollback) > 0 {
			m.Rollbacks = append(m.Rollbacks, a.Rollback)
		}
	}
}

// PlanCleanup returns a plan that undoes all tracked actions in reverse order.
// This is used for normal exit cleanup (supervisor shutdown).
func (m *CleanupManager) PlanCleanup() Plan {
	plan := newPlan(m.OS)
	// Reverse order
	for i := len(m.Applied) - 1; i >= 0; i-- {
		a := m.Applied[i]
		if len(a.Rollback) > 0 {
			plan.add("rollback: "+a.Description, a.Rollback, true, nil)
		}
	}
	if len(plan.Actions) == 0 {
		plan.Warnings = append(plan.Warnings, "no tracked state to clean up")
	}
	return plan
}

// PlanCrashRecovery returns a plan that cleans up stale EasyTier interfaces
// left behind after a crash. It mirrors Rust's cleanup on startup:
// - Linux: ip link show with et_* or configured dev_name
// - Windows: RegistryManager::reg_delete_obsoleted_items and firewall rule removal
// - FreeBSD: ifconfig -g tun and drivername restore
// - Darwin: ifconfig down for stale utun
func PlanCrashRecovery(osName string, staleIfNames []string) (Plan, error) {
	plan := newPlan(osName)
	if len(staleIfNames) == 0 {
		plan.Warnings = append(plan.Warnings, "no stale interfaces detected; nothing to recover")
		return plan, nil
	}
	for _, name := range staleIfNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		// Only clean up EasyTier-like names to avoid touching unrelated interfaces
		if !isEasytierInterface(name) {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("skip non-EasyTier interface %q", name))
			continue
		}
		clean, err := PlanTunCleanup(osName, name)
		if err != nil {
			return Plan{}, err
		}
		for _, a := range clean.Actions {
			plan.add(a.Description, a.Command, a.Privileged, nil)
		}
		// Also flush routes and addresses that may remain
		routeClean, _ := CleanupRoutes(osName, RouteConfig{IfName: name, Routes: []string{"0.0.0.0/0"}})
		_ = routeClean
		addrClean, _ := CleanupAddresses(osName, name, nil)
		for _, a := range addrClean.Actions {
			plan.add(a.Description, a.Command, a.Privileged, nil)
		}
		dnsClean := PlanDNSCleanup(osName, name)
		for _, a := range dnsClean.Actions {
			plan.add(a.Description, a.Command, a.Privileged, nil)
		}
	}
	if len(plan.Actions) == 0 {
		plan.Warnings = append(plan.Warnings, "no EasyTier stale interfaces to clean")
	}
	return plan, nil
}

// PlanDNSCleanup returns a plan that reverts DNS changes for an interface.
func PlanDNSCleanup(osName, ifName string) Plan {
	plan := newPlan(osName)
	switch osName {
	case "linux":
		plan.add("revert systemd-resolved", []string{"resolvectl", "revert", ifName}, true, nil)
		plan.add("restore resolv.conf", []string{"restore", "/etc/resolv.conf"}, true, nil)
	case "windows":
		plan.add("flush DNS", []string{"ipconfig", "/flushdns"}, true, nil)
		plan.add("reset DNS servers", []string{"netsh", "interface", "ip", "set", "dns", ifName, "dhcp"}, true, nil)
	case "darwin":
		plan.add("revert scutil DNS", []string{"scutil", "--revert"}, true, nil)
		plan.add("remove resolver files", []string{"rm", "-rf", "/etc/resolver/*et*"}, true, nil)
	case "freebsd":
		plan.add("restore resolv.conf", []string{"restore", "/etc/resolv.conf"}, true, nil)
	default:
		plan.add("revert DNS", []string{"dns-revert", ifName}, true, nil)
	}
	return plan
}

// PlanFullCleanup returns a plan that removes interface, routes, addresses and DNS.
func PlanFullCleanup(osName, ifName string, routes []string, addrs []string) (Plan, error) {
	if strings.TrimSpace(ifName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	// Routes
	if len(routes) > 0 {
		rc, err := CleanupRoutes(osName, RouteConfig{IfName: ifName, Routes: routes})
		if err != nil {
			return Plan{}, err
		}
		plan.Actions = append(plan.Actions, rc.Actions...)
		plan.Warnings = append(plan.Warnings, rc.Warnings...)
		if rc.Privileged {
			plan.Privileged = true
		}
	}
	// Addresses
	if len(addrs) > 0 {
		ac, err := CleanupAddresses(osName, ifName, addrs)
		if err != nil {
			return Plan{}, err
		}
		plan.Actions = append(plan.Actions, ac.Actions...)
		if ac.Privileged {
			plan.Privileged = true
		}
	} else {
		ac, _ := CleanupAddresses(osName, ifName, nil)
		plan.Actions = append(plan.Actions, ac.Actions...)
		if ac.Privileged {
			plan.Privileged = true
		}
	}
	// DNS
	dns := PlanDNSCleanup(osName, ifName)
	plan.Actions = append(plan.Actions, dns.Actions...)
	if dns.Privileged {
		plan.Privileged = true
	}
	// TUN itself last
	tun, err := PlanTunCleanup(osName, ifName)
	if err != nil {
		return Plan{}, err
	}
	plan.Actions = append(plan.Actions, tun.Actions...)
	if tun.Privileged {
		plan.Privileged = true
	}
	return plan, nil
}

func isEasytierInterface(name string) bool {
	// Rust uses et_<n>_<rand> on Windows and configurable dev_name on other OS.
	// For crash recovery we treat et*, tun*, utun* and names containing "easytier" as candidates.
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "et") ||
		strings.HasPrefix(lower, "tun") ||
		strings.HasPrefix(lower, "utun") ||
		strings.Contains(lower, "easytier")
}

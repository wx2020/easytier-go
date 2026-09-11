// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"strings"
)

// LinkConfig describes link layer configuration.
type LinkConfig struct {
	IfName string
	MTU    *int
	Up     *bool
}

// PlanLink returns a dry-run plan for MTU and link status.
func PlanLink(osName string, cfg LinkConfig) (Plan, error) {
	if strings.TrimSpace(cfg.IfName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	if cfg.MTU != nil {
		mtu := *cfg.MTU
		if mtu <= 0 || mtu > 65535 {
			return Plan{}, fmt.Errorf("%w: %d", ErrInvalidMTU, mtu)
		}
		switch osName {
		case "linux":
			plan.Add("set MTU", []string{"ip", "link", "set", "dev", cfg.IfName, "mtu", fmt.Sprintf("%d", mtu)}, true, nil)
		case "windows":
			plan.Add("set MTU", []string{"netsh", "interface", "ipv4", "set", "subinterface", cfg.IfName, fmt.Sprintf("mtu=%d", mtu)}, true, nil)
		case "darwin", "freebsd":
			plan.Add("set MTU", []string{"ifconfig", cfg.IfName, "mtu", fmt.Sprintf("%d", mtu)}, true, nil)
		default:
			plan.Add("set MTU", []string{"link-set-mtu", cfg.IfName, fmt.Sprintf("%d", mtu)}, true, nil)
		}
	}
	if cfg.Up != nil {
		up := *cfg.Up
		status := "down"
		if up {
			status = "up"
		}
		switch osName {
		case "linux":
			plan.Add(fmt.Sprintf("set link %s", status), []string{"ip", "link", "set", "dev", cfg.IfName, status}, true, nil)
		case "windows":
			action := "enable"
			if !up {
				action = "disable"
			}
			plan.Add(fmt.Sprintf("set link %s", status), []string{"netsh", "interface", action, "interface", cfg.IfName}, true, nil)
		case "darwin", "freebsd":
			plan.Add(fmt.Sprintf("set link %s", status), []string{"ifconfig", cfg.IfName, status}, true, nil)
		default:
			plan.Add(fmt.Sprintf("set link %s", status), []string{"link-set", cfg.IfName, status}, true, nil)
		}
	}
	if cfg.MTU == nil && cfg.Up == nil {
		plan.Warnings = append(plan.Warnings, "no link changes requested")
	}
	return plan, nil
}

// PlanWaitInterface waits for an interface to appear.
func PlanWaitInterface(osName string, ifName string) (Plan, error) {
	if strings.TrimSpace(ifName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	switch osName {
	case "linux", "windows":
		plan.Add("wait for interface", []string{"wait-iface", ifName, "timeout=10s"}, false, nil)
	default:
		plan.Add("wait for interface", []string{"ifconfig", ifName}, false, nil)
	}
	return plan, nil
}

func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }

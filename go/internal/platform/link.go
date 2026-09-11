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
	MTU    *int  // nil means no change
	Up     *bool // nil means no change
}

// PlanLink returns a dry-run plan for link status and MTU changes.
// Mirrors IfConfiger::set_mtu, set_link_status, and wait_interface_show.
func PlanLink(osName string, cfg LinkConfig) (Plan, error) {
	if strings.TrimSpace(cfg.IfName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	if cfg.MTU != nil {
		mtu := *cfg.MTU
		if mtu <= 0 || mtu > MaxMTU {
			return Plan{}, fmt.Errorf("%w: %d", ErrInvalidMTU, mtu)
		}
		switch osName {
		case "linux":
			plan.add("set MTU", []string{"ip", "link", "set", "dev", cfg.IfName, "mtu", fmt.Sprintf("%d", mtu)}, true, nil)
		case "windows":
			plan.add("set MTU", []string{"netsh", "interface", "ipv4", "set", "subinterface", cfg.IfName, fmt.Sprintf("mtu=%d", mtu)}, true, nil)
			plan.add("set IPv6 MTU", []string{"netsh", "interface", "ipv6", "set", "subinterface", cfg.IfName, fmt.Sprintf("mtu=%d", mtu)}, true, nil)
		case "darwin", "freebsd":
			plan.add("set MTU", []string{"ifconfig", cfg.IfName, "mtu", fmt.Sprintf("%d", mtu)}, true, nil)
		default:
			plan.add("set MTU", []string{"link-set-mtu", cfg.IfName, fmt.Sprintf("%d", mtu)}, true, nil)
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
			plan.add(fmt.Sprintf("set link %s", status), []string{"ip", "link", "set", "dev", cfg.IfName, status}, true, nil)
		case "windows":
			// Windows uses GetIfEntry/SetIfEntry via dwAdminStatus 1=up 2=down
			action := "enable"
			if !up {
				action = "disable"
			}
			plan.add(fmt.Sprintf("set link %s", status), []string{"netsh", "interface", action, "interface", cfg.IfName}, true, nil)
		case "darwin", "freebsd":
			plan.add(fmt.Sprintf("set link %s", status), []string{"ifconfig", cfg.IfName, status}, true, nil)
		default:
			plan.add(fmt.Sprintf("set link %s", status), []string{"link-set", cfg.IfName, status}, true, nil)
		}
	}
	if cfg.MTU == nil && cfg.Up == nil {
		plan.Warnings = append(plan.Warnings, "no link changes requested")
	}
	return plan, nil
}

// PlanWaitInterface returns a plan that waits for an interface to appear.
// On Windows this mirrors wait_interface_show with 10s timeout; on other
// platforms it is a simple poll via ip/ifconfig.
func PlanWaitInterface(osName string, ifName string) (Plan, error) {
	if strings.TrimSpace(ifName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	switch osName {
	case "linux":
		plan.add("wait for interface", []string{"wait-iface", ifName, "timeout=10s"}, false, nil)
		plan.Warnings = append(plan.Warnings, "polls via if_nametoindex with 100ms interval")
	case "windows":
		plan.add("wait for interface", []string{"wait-iface", ifName, "timeout=10s"}, false, nil)
		plan.Warnings = append(plan.Warnings, "polls interface index via find_interface_index with 100ms interval, 10s timeout")
	case "darwin", "freebsd":
		plan.add("wait for interface", []string{"ifconfig", ifName}, false, nil)
	default:
		plan.add("wait for interface", []string{"wait-iface", ifName}, false, nil)
	}
	return plan, nil
}

// EffectiveMTU computes MTU after subtracting encryption overhead when needed,
// mirroring internal/tun logic and instance/virtual_nic.rs mtu_in_config -20.
func EffectiveMTU(mtu int, encryption bool) int {
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if mtu > MaxMTU {
		mtu = MaxMTU
	}
	if mtu < 1280 {
		mtu = 1280
	}
	if encryption {
		mtu -= 20
		if mtu < 1280 {
			mtu = 1280
		}
	}
	return mtu
}

func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }

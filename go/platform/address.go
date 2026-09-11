// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
	"strings"
)

// AddressConfig describes addresses to assign to an interface (GWY-02).
type AddressConfig struct {
	IfName    string
	Addresses []string // CIDRs e.g. "10.144.144.1/24"
}

// PlanAddresses returns a dry-run plan for assigning addresses.
// Mirrors internal/platform PlanAddresses for adapter parity.
func PlanAddresses(osName string, cfg AddressConfig) (Plan, error) {
	if strings.TrimSpace(cfg.IfName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	if len(cfg.Addresses) == 0 {
		plan.Warnings = append(plan.Warnings, "no addresses to configure")
		return plan, nil
	}
	for _, cidr := range cfg.Addresses {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return Plan{}, fmt.Errorf("%w: invalid CIDR %q: %v", ErrInvalidConfig, cidr, err)
		}
		isV4 := pfx.Addr().Is4()
		switch osName {
		case "linux":
			if isV4 {
				bc := prefixBroadcast(pfx)
				cmd := []string{"ip", "addr", "add", pfx.String(), "dev", cfg.IfName, "broadcast", bc}
				rollback := []string{"ip", "addr", "del", pfx.String(), "dev", cfg.IfName}
				plan.Add(fmt.Sprintf("add IPv4 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			} else {
				cmd := []string{"ip", "-6", "addr", "add", pfx.String(), "dev", cfg.IfName}
				rollback := []string{"ip", "-6", "addr", "del", pfx.String(), "dev", cfg.IfName}
				plan.Add(fmt.Sprintf("add IPv6 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			}
		case "windows":
			if isV4 {
				cmd := []string{"netsh", "interface", "ipv4", "add", "address", cfg.IfName, pfx.Addr().String(), prefixMask(pfx)}
				rollback := []string{"netsh", "interface", "ipv4", "delete", "address", cfg.IfName, pfx.Addr().String()}
				plan.Add(fmt.Sprintf("add IPv4 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			} else {
				cmd := []string{"netsh", "interface", "ipv6", "add", "address", cfg.IfName, pfx.String()}
				rollback := []string{"netsh", "interface", "ipv6", "delete", "address", cfg.IfName, pfx.String()}
				plan.Add(fmt.Sprintf("add IPv6 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			}
		case "darwin":
			if isV4 {
				cmd := []string{"ifconfig", cfg.IfName, "inet", pfx.Addr().String() + "/" + fmt.Sprintf("%d", pfx.Bits()), pfx.Addr().String(), "up"}
				rollback := []string{"ifconfig", cfg.IfName, "inet", pfx.Addr().String(), "delete"}
				plan.Add(fmt.Sprintf("add IPv4 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
				plan.Add(fmt.Sprintf("add route for %s", pfx), []string{"route", "-n", "add", pfx.Addr().String(), "-netmask", prefixMask(pfx), "-interface", cfg.IfName, "-hopcount", "7"}, true, []string{"route", "-n", "delete", pfx.Addr().String(), "-netmask", prefixMask(pfx), "-interface", cfg.IfName})
			} else {
				cmd := []string{"ifconfig", cfg.IfName, "inet6", pfx.String(), "add"}
				rollback := []string{"ifconfig", cfg.IfName, "inet6", pfx.Addr().String(), "delete"}
				plan.Add(fmt.Sprintf("add IPv6 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			}
		case "freebsd":
			if isV4 {
				cmd := []string{"ifconfig", cfg.IfName, "inet", pfx.Addr().String() + "/" + fmt.Sprintf("%d", pfx.Bits()), pfx.Addr().String(), "up"}
				rollback := []string{"ifconfig", cfg.IfName, "inet", pfx.Addr().String(), "delete"}
				plan.Add(fmt.Sprintf("add IPv4 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			} else {
				cmd := []string{"ifconfig", cfg.IfName, "inet6", pfx.String(), "add"}
				rollback := []string{"ifconfig", cfg.IfName, "inet6", pfx.Addr().String(), "delete"}
				plan.Add(fmt.Sprintf("add IPv6 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			}
		default:
			cmd := []string{"addr-add", cfg.IfName, pfx.String()}
			rollback := []string{"addr-del", cfg.IfName, pfx.String()}
			plan.Add(fmt.Sprintf("add %s to %s", pfx, cfg.IfName), cmd, true, rollback)
		}
	}
	return plan, nil
}

// CleanupAddresses returns a plan that removes addresses.
func CleanupAddresses(osName string, ifName string, filter []string) (Plan, error) {
	if strings.TrimSpace(ifName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	if len(filter) == 0 {
		switch osName {
		case "linux":
			plan.Add("flush IPv4 addresses", []string{"ip", "addr", "flush", "dev", ifName}, true, nil)
			plan.Add("flush IPv6 addresses", []string{"ip", "-6", "addr", "flush", "dev", ifName}, true, nil)
		case "windows":
			plan.Add("flush IPv4 addresses", []string{"netsh", "interface", "ipv4", "flush", ifName}, true, nil)
		case "darwin", "freebsd":
			plan.Add("remove IPv4 addresses", []string{"ifconfig", ifName, "inet", "delete"}, true, nil)
		default:
			plan.Add("flush addresses", []string{"addr-flush", ifName}, true, nil)
		}
		return plan, nil
	}
	for _, cidr := range filter {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return Plan{}, fmt.Errorf("%w: invalid CIDR %q: %v", ErrInvalidConfig, cidr, err)
		}
		switch osName {
		case "linux":
			if pfx.Addr().Is4() {
				plan.Add(fmt.Sprintf("remove IPv4 %s", pfx), []string{"ip", "addr", "del", pfx.String(), "dev", ifName}, true, nil)
			} else {
				plan.Add(fmt.Sprintf("remove IPv6 %s", pfx), []string{"ip", "-6", "addr", "del", pfx.String(), "dev", ifName}, true, nil)
			}
		case "windows":
			if pfx.Addr().Is4() {
				plan.Add(fmt.Sprintf("remove IPv4 %s", pfx), []string{"netsh", "interface", "ipv4", "delete", "address", ifName, pfx.Addr().String()}, true, nil)
			} else {
				plan.Add(fmt.Sprintf("remove IPv6 %s", pfx), []string{"netsh", "interface", "ipv6", "delete", "address", ifName, pfx.String()}, true, nil)
			}
		default:
			plan.Add(fmt.Sprintf("remove %s", pfx), []string{"addr-del", ifName, pfx.String()}, true, nil)
		}
	}
	return plan, nil
}

func prefixMask(p netip.Prefix) string {
	if p.Addr().Is4() {
		bits := p.Bits()
		if bits == 0 {
			return "0.0.0.0"
		}
		mask := ^uint32(0) << (32 - bits)
		return fmt.Sprintf("%d.%d.%d.%d", byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
	}
	return fmt.Sprintf("%d", p.Bits())
}

func prefixBroadcast(p netip.Prefix) string {
	if !p.Addr().Is4() {
		return ""
	}
	b := p.Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	bits := p.Bits()
	if bits == 32 {
		return p.Addr().String()
	}
	mask := ^uint32(0) >> bits
	v |= mask
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

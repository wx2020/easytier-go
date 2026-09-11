// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
	"strings"
)

// AddressConfig describes addresses to assign to an interface.
type AddressConfig struct {
	IfName    string
	Addresses []string // CIDRs e.g. "10.144.144.1/24" or "fd00::1/64"
}

// PlanAddresses returns a dry-run plan for assigning addresses to an interface.
// It mirrors IfConfiger::add_ipv4_ip / add_ipv6_ip and remove_ip logic
// for each platform (netlink on Linux, ifconfig on Darwin/FreeBSD, LUID on Windows).
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
		if !pfx.IsValid() {
			return Plan{}, fmt.Errorf("%w: invalid CIDR %q", ErrInvalidConfig, cidr)
		}
		isV4 := pfx.Addr().Is4()
		switch osName {
		case "linux":
			// netlink: NewAddress with IFA_ADDRESS + IFA_LOCAL + IFA_BROADCAST for v4
			if isV4 {
				addr := pfx.Addr().String()
				broadcast := prefixBroadcast(pfx)
				cmd := []string{"ip", "addr", "add", pfx.String(), "dev", cfg.IfName, "broadcast", broadcast}
				rollback := []string{"ip", "addr", "del", pfx.String(), "dev", cfg.IfName}
				plan.add(fmt.Sprintf("add IPv4 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
				_ = addr
			} else {
				cmd := []string{"ip", "-6", "addr", "add", pfx.String(), "dev", cfg.IfName}
				rollback := []string{"ip", "-6", "addr", "del", pfx.String(), "dev", cfg.IfName}
				plan.add(fmt.Sprintf("add IPv6 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			}
		case "windows":
			// LUID: add_ipv4_address / add_ipv6_address via netsh or Wintun LUID
			if isV4 {
				cmd := []string{"netsh", "interface", "ipv4", "add", "address", cfg.IfName, pfx.Addr().String(), prefixMask(pfx)}
				rollback := []string{"netsh", "interface", "ipv4", "delete", "address", cfg.IfName, pfx.Addr().String()}
				plan.add(fmt.Sprintf("add IPv4 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			} else {
				cmd := []string{"netsh", "interface", "ipv6", "add", "address", cfg.IfName, pfx.String()}
				rollback := []string{"netsh", "interface", "ipv6", "delete", "address", cfg.IfName, pfx.String()}
				plan.add(fmt.Sprintf("add IPv6 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			}
			plan.Warnings = append(plan.Warnings, "Windows LUID path disables dynamic DNS and NetBIOS; rollback flushes addresses")
		case "darwin":
			if isV4 {
				// darwin.rs: ifconfig {name} {addr}/{prefix} {addr} up
				cmd := []string{"ifconfig", cfg.IfName, "inet", pfx.Addr().String() + "/" + fmt.Sprintf("%d", pfx.Bits()), pfx.Addr().String(), "up"}
				rollback := []string{"ifconfig", cfg.IfName, "inet", pfx.Addr().String(), "delete"}
				plan.add(fmt.Sprintf("add IPv4 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
				// also add route for network (macos needs explicit route)
				plan.add(fmt.Sprintf("add route for %s", pfx), []string{"route", "-n", "add", pfx.Addr().String(), "-netmask", prefixMask(pfx), "-interface", cfg.IfName, "-hopcount", "7"}, true, []string{"route", "-n", "delete", pfx.Addr().String(), "-netmask", prefixMask(pfx), "-interface", cfg.IfName})
			} else {
				cmd := []string{"ifconfig", cfg.IfName, "inet6", pfx.String(), "add"}
				rollback := []string{"ifconfig", cfg.IfName, "inet6", pfx.Addr().String(), "delete"}
				plan.add(fmt.Sprintf("add IPv6 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
				plan.add(fmt.Sprintf("add IPv6 route for %s", pfx), []string{"route", "-n", "add", "-inet6", pfx.String(), "-interface", cfg.IfName}, true, []string{"route", "-n", "delete", "-inet6", pfx.String(), "-interface", cfg.IfName})
			}
		case "freebsd":
			if isV4 {
				cmd := []string{"ifconfig", cfg.IfName, "inet", pfx.Addr().String() + "/" + fmt.Sprintf("%d", pfx.Bits()), pfx.Addr().String(), "up"}
				rollback := []string{"ifconfig", cfg.IfName, "inet", pfx.Addr().String(), "delete"}
				plan.add(fmt.Sprintf("add IPv4 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
				plan.add(fmt.Sprintf("add route for %s", pfx), []string{"route", "add", "-net", pfx.String(), "-interface", cfg.IfName}, true, []string{"route", "delete", "-net", pfx.String()})
			} else {
				cmd := []string{"ifconfig", cfg.IfName, "inet6", pfx.String(), "add"}
				rollback := []string{"ifconfig", cfg.IfName, "inet6", pfx.Addr().String(), "delete"}
				plan.add(fmt.Sprintf("add IPv6 %s to %s", pfx, cfg.IfName), cmd, true, rollback)
			}
		default:
			cmd := []string{"addr-add", cfg.IfName, pfx.String()}
			rollback := []string{"addr-del", cfg.IfName, pfx.String()}
			plan.add(fmt.Sprintf("add %s to %s", pfx, cfg.IfName), cmd, true, rollback)
		}
	}
	return plan, nil
}

// CleanupAddresses returns a plan that removes all addresses from an interface,
// or a specific prefix if filter is non-empty.
// Passing empty filter produces a flush (remove all).
func CleanupAddresses(osName string, ifName string, filter []string) (Plan, error) {
	if strings.TrimSpace(ifName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	if len(filter) == 0 {
		switch osName {
		case "linux":
			plan.add("flush IPv4 addresses", []string{"ip", "addr", "flush", "dev", ifName}, true, nil)
			plan.add("flush IPv6 addresses", []string{"ip", "-6", "addr", "flush", "dev", ifName}, true, nil)
		case "windows":
			plan.add("flush IPv4 addresses", []string{"netsh", "interface", "ipv4", "flush", ifName}, true, nil)
			plan.add("flush IPv6 addresses", []string{"netsh", "interface", "ipv6", "flush", ifName}, true, nil)
		case "darwin", "freebsd":
			plan.add("remove IPv4 addresses", []string{"ifconfig", ifName, "inet", "delete"}, true, nil)
			plan.add("remove IPv6 addresses", []string{"ifconfig", ifName, "inet6", "delete"}, true, nil)
		default:
			plan.add("flush addresses", []string{"addr-flush", ifName}, true, nil)
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
				plan.add(fmt.Sprintf("remove IPv4 %s", pfx), []string{"ip", "addr", "del", pfx.String(), "dev", ifName}, true, nil)
			} else {
				plan.add(fmt.Sprintf("remove IPv6 %s", pfx), []string{"ip", "-6", "addr", "del", pfx.String(), "dev", ifName}, true, nil)
			}
		case "windows":
			if pfx.Addr().Is4() {
				plan.add(fmt.Sprintf("remove IPv4 %s", pfx), []string{"netsh", "interface", "ipv4", "delete", "address", ifName, pfx.Addr().String()}, true, nil)
			} else {
				plan.add(fmt.Sprintf("remove IPv6 %s", pfx), []string{"netsh", "interface", "ipv6", "delete", "address", ifName, pfx.String()}, true, nil)
			}
		case "darwin", "freebsd":
			if pfx.Addr().Is4() {
				plan.add(fmt.Sprintf("remove IPv4 %s", pfx), []string{"ifconfig", ifName, "inet", pfx.Addr().String(), "delete"}, true, nil)
			} else {
				plan.add(fmt.Sprintf("remove IPv6 %s", pfx), []string{"ifconfig", ifName, "inet6", pfx.Addr().String(), "delete"}, true, nil)
			}
		default:
			plan.add(fmt.Sprintf("remove %s", pfx), []string{"addr-del", ifName, pfx.String()}, true, nil)
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

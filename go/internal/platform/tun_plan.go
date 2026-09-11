// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"strings"
)

// PlanTun returns a dry-run plan for creating a TUN device on the given OS.
// It mirrors the per-platform handling in easytier/src/instance/virtual_nic.rs
// and common/ifcfg for each target. The planner never touches the host.
func PlanTun(osName string, cfg Config) (Plan, error) {
	if err := validateTunConfig(cfg, osName); err != nil {
		return Plan{}, err
	}
	plan := newPlan(osName)
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	name := cfg.Name
	switch osName {
	case "linux":
		if name == "" {
			return Plan{}, fmt.Errorf("%w: TUN name is required on Linux", ErrInvalidConfig)
		}
		plan.add("open TUN device", []string{"open", "/dev/net/tun", "O_RDWR|O_CLOEXEC"}, true, []string{"close fd"})
		plan.add("create TUN interface", []string{"ioctl", "TUNSETIFF", name, "IFF_TUN|IFF_NO_PI"}, true, []string{"ip link delete " + name})
		plan.add("set MTU", []string{"ip", "link", "set", "dev", name, "mtu", fmt.Sprintf("%d", mtu)}, true, nil)
		plan.add("bring link up", []string{"ip", "link", "set", "dev", name, "up"}, true, []string{"ip link set dev " + name + " down"})
		if cfg.MaxPacketSize != 0 && cfg.MaxPacketSize != mtu {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("MaxPacketSize %d differs from MTU %d", cfg.MaxPacketSize, mtu))
		}
		// Ensure TUN device node exists (mirrors ensure_tun_device_node)
		plan.add("ensure TUN device node", []string{"ensure", "/dev/net/tun", "c", "10", "200"}, true, nil)
	case "windows":
		if name == "" {
			// Rust generates random et_<count>_<rand> when empty
			name = "et_auto"
			plan.Warnings = append(plan.Warnings, "empty dev_name: will generate random et_<n>_<rand> like Rust (easytier/src/instance/virtual_nic.rs)")
		}
		plan.add("create Wintun adapter", []string{"wintun", "create", name}, true, []string{"wintun", "delete", name})
		plan.add("disable dynamic DNS registration", []string{"reg", "set", "RegistrationEnabled=0", "DisableDynamicUpdate=1", name}, true, []string{"reg", "revert", name})
		plan.add("disable NetBIOS", []string{"reg", "set", "NetbiosOptions=2", name}, true, nil)
		plan.add("set MTU", []string{"netsh", "interface", "ipv4", "set", "subinterface", name, fmt.Sprintf("mtu=%d", mtu)}, true, nil)
		plan.add("add firewall allowlist", []string{"netsh", "advfirewall", "firewall", "add", "rule", "name=EasyTier", "dir=in", "action=allow", "interface=" + name}, true, []string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=EasyTier", "interface=" + name})
		plan.Warnings = append(plan.Warnings, "requires Wintun driver and firewall allowlist; registry cleanup via reg_delete_obsoleted_items")
	case "darwin":
		if name == "" {
			name = "utun"
		}
		plan.add("create utun device", []string{"open", "/dev/" + name}, true, []string{"close", "/dev/" + name})
		plan.add("configure MTU", []string{"ifconfig", name, "mtu", fmt.Sprintf("%d", mtu)}, true, nil)
		plan.add("bring up interface", []string{"ifconfig", name, "up"}, true, []string{"ifconfig", name, "down"})
		plan.Warnings = append(plan.Warnings, "macOS utun uses packet_information=false; network extension when feature macos-ne is enabled")
	case "freebsd":
		if name == "" {
			name = "tun0"
		}
		plan.add("create tun device", []string{"open", "/dev/" + name}, true, []string{"close /dev/" + name})
		plan.add("set MTU", []string{"ifconfig", name, "mtu", fmt.Sprintf("%d", mtu)}, true, nil)
		plan.add("up interface", []string{"ifconfig", name, "up"}, true, []string{"ifconfig", name, "down"})
		if cfg.Name != "" && cfg.Name != name {
			plan.add("rename interface", []string{"ifconfig", name, "name", cfg.Name}, true, []string{"ifconfig", cfg.Name, "name", name})
		}
		plan.Warnings = append(plan.Warnings, "FreeBSD may rename TUN; crash recovery restores original drivername via ifconfig -g tun")
	case "android":
		plan.add("validate VpnService FD (dry-run)", []string{"validate-fd", "android-tun", cfg.Name}, false, nil)
		plan.add("wrap injected FD", []string{"dup", "android-fd"}, false, []string{"close dup fd"})
		if name == "" {
			name = "tun0"
		}
		plan.add("configure TUN via VpnService", []string{"vpn-builder", name, fmt.Sprintf("mtu=%d", mtu)}, false, nil)
		plan.Warnings = append(plan.Warnings, "Android VpnService TUN is managed by system; one-active policy enforced")
	default:
		plan.add("create TUN device", []string{"tun-create", name, fmt.Sprintf("mtu=%d", mtu)}, true, []string{"tun-delete", name})
		plan.Warnings = append(plan.Warnings, "unknown OS: generic TUN plan")
	}
	return plan, nil
}

// PlanTunCleanup returns a plan that removes a previously created TUN device.
func PlanTunCleanup(osName string, ifName string) (Plan, error) {
	if strings.TrimSpace(ifName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	switch osName {
	case "linux":
		plan.add("delete TUN interface", []string{"ip", "link", "delete", ifName}, true, nil)
		plan.add("remove firewall rules", []string{"iptables", "-D", "FORWARD", "-i", ifName, "-j", "ACCEPT"}, true, nil)
	case "windows":
		plan.add("remove firewall rules", []string{"netsh", "advfirewall", "firewall", "delete", "rule", "interface=" + ifName}, true, nil)
		plan.add("delete Wintun adapter", []string{"wintun", "delete", ifName}, true, nil)
		plan.add("cleanup registry obsoleted items", []string{"reg", "delete", "Profiles", "et_*"}, true, nil)
	case "darwin":
		plan.add("bring down interface", []string{"ifconfig", ifName, "down"}, true, nil)
		plan.add("close utun device", []string{"close", "/dev/" + ifName}, true, nil)
	case "freebsd":
		plan.add("bring down interface", []string{"ifconfig", ifName, "down"}, true, nil)
		plan.add("restore original tun name", []string{"ifconfig", "-g", "tun", "restore", ifName}, true, nil)
	default:
		plan.add("delete TUN interface", []string{"tun-delete", ifName}, true, nil)
	}
	return plan, nil
}

func validateTunConfig(cfg Config, osName string) error {
	if osName == "android" {
		// Android uses FD, name can be empty; validation handled in PlanAndroidTun
		return nil
	}
	if cfg.Name != "" {
		if strings.Contains(cfg.Name, "\x00") {
			return fmt.Errorf("%w: TUN name contains NUL", ErrInvalidConfig)
		}
		if len(cfg.Name) >= 16 {
			return fmt.Errorf("%w: TUN name %q too long (max 15)", ErrInvalidConfig, cfg.Name)
		}
	}
	if cfg.MTU < 0 || cfg.MTU > MaxMTU {
		return fmt.Errorf("%w: %d", ErrInvalidMTU, cfg.MTU)
	}
	if cfg.MaxPacketSize != 0 && (cfg.MaxPacketSize < cfg.MTU || cfg.MaxPacketSize > MaxPacketSize) {
		return fmt.Errorf("%w: %w: %d", ErrInvalidConfig, ErrInvalidPacketMax, cfg.MaxPacketSize)
	}
	// On Linux, name is required for normal creation (except FD injection)
	if osName == "linux" && cfg.Name == "" {
		// Allow empty for dry-run auto generation? But Linux requires name
		return fmt.Errorf("%w: TUN name is required on Linux", ErrInvalidConfig)
	}
	return nil
}

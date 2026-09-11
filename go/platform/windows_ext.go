// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"strings"
)

// Windows extensions for Wintun/WinDivert/fake-TCP packaging, firewall per-interface, registry (NTV-06).

// WinDriverSpec describes driver packaging for Windows.
type WinDriverSpec struct {
	Arch         string // x86, x86_64, arm64
	WintunDLL    string // path to wintun.dll
	WinDivertDLL string // path to WinDivert.dll (for fake-TCP)
	WinDivertSys string // path to WinDivert.sys
}

var SupportedWinArches = []string{"x86", "x86_64", "arm64"}

func ValidateWinDriverSpec(spec WinDriverSpec) error {
	found := false
	for _, a := range SupportedWinArches {
		if spec.Arch == a {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: unsupported windows arch %q", ErrInvalidConfig, spec.Arch)
	}
	if strings.TrimSpace(spec.WintunDLL) == "" {
		return fmt.Errorf("%w: wintun.dll required", ErrInvalidConfig)
	}
	return nil
}

// PlanWintun returns plan for Wintun adapter creation (already in windows.go but extended here with driver details).
func PlanWintun(ifName string, spec WinDriverSpec) (Plan, error) {
	if err := ValidateWinDriverSpec(spec); err != nil {
		return Plan{}, err
	}
	if strings.TrimSpace(ifName) == "" {
		ifName = "et_auto"
	}
	plan := newPlan("windows")
	plan.Add("ensure wintun.dll for "+spec.Arch, []string{"copy", spec.WintunDLL, "C:\\Windows\\System32\\wintun.dll"}, true, []string{"del", "C:\\Windows\\System32\\wintun.dll"})
	if spec.WinDivertDLL != "" {
		plan.Add("ensure WinDivert.dll", []string{"copy", spec.WinDivertDLL, "C:\\Windows\\System32\\WinDivert.dll"}, true, []string{"del", "C:\\Windows\\System32\\WinDivert.dll"})
	}
	if spec.WinDivertSys != "" {
		plan.Add("install WinDivert.sys driver", []string{"sc", "create", "WinDivert", "binPath=", spec.WinDivertSys}, true, []string{"sc", "delete", "WinDivert"})
	}
	plan.Add("create Wintun adapter", []string{"wintun", "create", ifName, "tunnel-type", "easytier"}, true, []string{"wintun", "delete", ifName})
	plan.Add("disable dynamic DNS registration", []string{"reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\<guid>", "/v", "RegistrationEnabled", "/t", "REG_DWORD", "/d", "0", "/f"}, true, []string{"reg", "delete", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\<guid>", "/v", "RegistrationEnabled"})
	plan.Add("disable NetBIOS", []string{"reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_<guid>", "/v", "NetbiosOptions", "/t", "REG_DWORD", "/d", "2", "/f"}, true, nil)
	plan.Add("cleanup obsoleted registry items", []string{"reg", "delete", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\et_*"}, true, nil)
	return plan, nil
}

// WinFirewallRule describes per-interface firewall allowlist (mirrors src/arch/windows.rs).
type WinFirewallRule struct {
	InterfaceName string
	Protocols     []string // TCP, UDP, ICMP, ALL
	Direction     string   // Inbound, Outbound, Both
}

func PlanWindowsFirewall(rule WinFirewallRule) (Plan, error) {
	if strings.TrimSpace(rule.InterfaceName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required for firewall rule", ErrInvalidConfig)
	}
	protocols := rule.Protocols
	if len(protocols) == 0 {
		protocols = []string{"TCP", "UDP", "ICMP", "ALL"}
	}
	directions := []string{"Inbound", "Outbound"}
	if rule.Direction == "Inbound" {
		directions = []string{"Inbound"}
	} else if rule.Direction == "Outbound" {
		directions = []string{"Outbound"}
	}
	plan := newPlan("windows")
	for _, proto := range protocols {
		num := ""
		switch proto {
		case "TCP":
			num = "6"
		case "UDP":
			num = "17"
		case "ICMP":
			num = "1"
		default:
			num = "any"
		}
		for _, dir := range directions {
			name := fmt.Sprintf("EasyTier %s - %s Protocol (%s)", rule.InterfaceName, proto, dir)
			plan.Add(fmt.Sprintf("allow %s %s on %s", dir, proto, rule.InterfaceName),
				[]string{"netsh", "advfirewall", "firewall", "add", "rule", "name=" + name, "dir=" + strings.ToLower(dir), "action=allow", "protocol=" + num, "interface=" + rule.InterfaceName},
				true,
				[]string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + name})
		}
	}
	plan.Warnings = append(plan.Warnings, "requires COM INetFwPolicy2; grouping EasyTier; removes existing rule before add")
	return plan, nil
}

// PlanFakeTCP returns plan for fake-TCP transport on Windows (requires WinDivert).
func PlanFakeTCP(ifName string, enabled bool) (Plan, error) {
	plan := newPlan("windows")
	if !enabled {
		plan.Warnings = append(plan.Warnings, "fake-TCP disabled; no WinDivert driver needed")
		return plan, nil
	}
	if strings.TrimSpace(ifName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required for fake-TCP", ErrInvalidConfig)
	}
	plan.Add("ensure WinDivert driver for fake-TCP", []string{"WinDivert", "install", "fake-tcp", ifName}, true, []string{"WinDivert", "uninstall"})
	plan.Add("configure fake-TCP filter", []string{"netsh", "advfirewall", "firewall", "add", "rule", "name=EasyTier-fakeTCP", "dir=in", "action=allow", "protocol=6", "interface=" + ifName}, true, []string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=EasyTier-fakeTCP"})
	plan.Add("start fake-TCP handler", []string{"easytier-core", "--transport", "faketcp", "--interface", ifName}, true, []string{"taskkill", "/f", "/im", "easytier-core.exe"})
	plan.Warnings = append(plan.Warnings, "fake-TCP requires privileged WinDivert; fallback to TCP on driver failure")
	return plan, nil
}

// PlanWindowsRegistryCleanup mirrors RegistryManager::reg_delete_obsoleted_items.
func PlanWindowsRegistryCleanup(ifName string) (Plan, error) {
	plan := newPlan("windows")
	plan.Add("delete obsoleted NetworkList Profiles containing et_", []string{"reg", "delete", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", "/f", "et_*"}, true, nil)
	if ifName != "" {
		plan.Add("delete profile for "+ifName, []string{"reg", "delete", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", "/f", ifName}, true, nil)
		plan.Add("delete unmanaged signature for et_*", []string{"reg", "delete", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged", "/f", "et_*"}, true, nil)
	}
	plan.Add("set Category=1 (private) for active profile", []string{"reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\<guid>", "/v", "Category", "/t", "REG_DWORD", "/d", "1", "/f"}, true, nil)
	return plan, nil
}

// PlanWindowsRoutesWithFakeTCP combines routes and optional fakeTCP handling.
func PlanWindowsRoutesWithFakeTCP(cfg RouteConfig, fakeTCPEnabled bool) (Plan, error) {
	base, err := NewForOS("windows").PlanRoutes(cfg)
	if err != nil {
		return Plan{}, err
	}
	if !fakeTCPEnabled {
		return base, nil
	}
	fake, err := PlanFakeTCP(cfg.IfName, true)
	if err != nil {
		return Plan{}, err
	}
	for _, a := range fake.Actions {
		base.Add(a.Description, a.Command, a.Privileged, a.Rollback)
	}
	base.Warnings = append(base.Warnings, fake.Warnings...)
	return base, nil
}

// WindowsServicePlan returns Windows service installation plan (wrapper for convenience).
func PlanWindowsServiceWithFirewall(cfg ServiceConfig, firewallInterface string) (Plan, error) {
	base, err := NewForOS("windows").PlanService(cfg)
	if err != nil {
		return Plan{}, err
	}
	if firewallInterface != "" {
		fw, err := PlanWindowsFirewall(WinFirewallRule{InterfaceName: firewallInterface})
		if err != nil {
			return Plan{}, err
		}
		for _, a := range fw.Actions {
			base.Add(a.Description, a.Command, a.Privileged, a.Rollback)
		}
	}
	return base, nil
}

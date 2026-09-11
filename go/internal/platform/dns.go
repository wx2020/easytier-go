// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
	"strings"
)

// DNSConfig describes resolver configuration.
type DNSConfig struct {
	IfName  string
	Servers []string
	Search  []string
	Domain  string
	Mode    string // "systemd-resolved", "resolv.conf", "scutil", "android"
}

// PlanDNS returns a dry-run plan for DNS configuration.
func PlanDNS(osName string, cfg DNSConfig) (Plan, error) {
	plan := newPlan(osName)
	if len(cfg.Servers) == 0 {
		plan.Warnings = append(plan.Warnings, "no DNS servers configured")
		return plan, nil
	}
	for _, s := range cfg.Servers {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.IsValid() {
			if strings.Contains(s, "/") {
				return Plan{}, fmt.Errorf("%w: invalid DNS server %q", ErrInvalidConfig, s)
			}
		}
	}
	mode := cfg.Mode
	if mode == "" {
		switch osName {
		case "linux":
			mode = "systemd-resolved"
		case "darwin":
			mode = "scutil"
		case "freebsd":
			mode = "resolv.conf"
		case "windows":
			mode = "windows"
		case "android":
			mode = "android"
		default:
			mode = "resolv.conf"
		}
	}
	switch mode {
	case "systemd-resolved":
		for _, srv := range cfg.Servers {
			plan.add("configure systemd-resolved DNS", []string{"resolvectl", "dns", cfg.IfName, srv}, true, []string{"resolvectl", "revert", cfg.IfName})
		}
		if len(cfg.Search) > 0 {
			plan.add("configure DNS search domains", []string{"resolvectl", "domain", cfg.IfName, strings.Join(cfg.Search, " ")}, true, nil)
		}
		plan.Warnings = append(plan.Warnings, "requires systemd-resolved; rollback via resolvectl revert")
		if osName == "linux" {
			plan.Warnings = append(plan.Warnings, "will also set DNSOverTLS=no and LLMNR=no for EasyTier interface")
		}
	case "resolv.conf":
		plan.add("update /etc/resolv.conf", []string{"update-resolv-conf", strings.Join(cfg.Servers, ",")}, true, []string{"restore /etc/resolv.conf"})
		if len(cfg.Search) > 0 {
			plan.add("add search domains to resolv.conf", []string{"resolv-search", strings.Join(cfg.Search, " ")}, true, nil)
		}
		if cfg.Domain != "" {
			plan.add("add domain to resolv.conf", []string{"resolv-domain", cfg.Domain}, true, nil)
		}
	case "scutil":
		plan.add("configure DNS via scutil", []string{"scutil", "--dns", strings.Join(cfg.Servers, ",")}, true, []string{"scutil", "--revert"})
		if cfg.Domain != "" {
			plan.add("configure resolver for domain", []string{"mkdir", "-p", "/etc/resolver/" + cfg.Domain}, true, []string{"rm -rf /etc/resolver/" + cfg.Domain})
			plan.add("write resolver file", []string{"write", "/etc/resolver/" + cfg.Domain, "nameserver " + cfg.Servers[0]}, true, nil)
		}
		plan.Warnings = append(plan.Warnings, "requires scutil or resolver file update; will restore on cleanup")
		if len(cfg.Search) > 0 {
			plan.add("configure search domains via scutil", []string{"scutil", "--search", strings.Join(cfg.Search, " ")}, true, nil)
		}
	case "android":
		for _, srv := range cfg.Servers {
			plan.add("add VpnService DNS", []string{"builder.addDnsServer", srv}, false, nil)
		}
		if len(cfg.Search) > 0 {
			for _, d := range cfg.Search {
				plan.add("add search domain", []string{"builder.addSearchDomain", d}, false, nil)
			}
		}
		plan.Warnings = append(plan.Warnings, "VpnService.Builder DNS is managed by Android system; no privileged op")
	case "windows":
		for _, srv := range cfg.Servers {
			plan.add("set DNS server", []string{"netsh", "interface", "ip", "set", "dns", cfg.IfName, "static", srv}, true, []string{"netsh", "interface", "ip", "set", "dns", cfg.IfName, "dhcp"})
		}
		plan.add("disable dynamic DNS updates", []string{"reg", "set", "RegistrationEnabled=0", "DisableDynamicUpdate=1", cfg.IfName}, true, []string{"reg", "revert", cfg.IfName})
		plan.add("disable NetBIOS", []string{"reg", "set", "NetbiosOptions=2", cfg.IfName}, true, nil)
		if len(cfg.Search) > 0 {
			plan.add("set DNS suffix search list", []string{"netsh", "interface", "ip", "set", "dns", cfg.IfName, "search", strings.Join(cfg.Search, ",")}, true, nil)
		}
		plan.Warnings = append(plan.Warnings, "Windows registry tweaks mute dynamic updates; rollback restores via reg revert and ipconfig /flushdns")
	default:
		plan.add("configure DNS ("+mode+")", []string{"dns-config", cfg.IfName, strings.Join(cfg.Servers, ",")}, true, nil)
	}
	return plan, nil
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
	"strings"
)

// WindowsAdapter implements Wintun, routes, DNS, firewall, Windows service.
type WindowsAdapter struct{ BaseAdapter }

func (a *WindowsAdapter) Supported() bool { return true }

func (a *WindowsAdapter) PlanTun(cfg TunConfig) (Plan, error) {
	if err := validateTunConfig(cfg, false); err != nil {
		return Plan{}, err
	}
	plan := newPlan("windows")
	name := cfg.Name
	if name == "" {
		name = "et_auto"
		plan.Warnings = append(plan.Warnings, "empty dev_name: will generate random et_<n>_<rand> like Rust")
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1380
	}
	plan.Add("create Wintun adapter", []string{"wintun", "create", name}, true, []string{"wintun", "delete", name})
	plan.Add("disable dynamic DNS registration", []string{"reg", "set", "RegistrationEnabled=0", "DisableDynamicUpdate=1", name}, true, []string{"reg", "revert", name})
	plan.Add("disable NetBIOS", []string{"reg", "set", "NetbiosOptions=2", name}, true, nil)
	plan.Add("set MTU", []string{"netsh", "interface", "ipv4", "set", "subinterface", name, fmt.Sprintf("mtu=%d", mtu)}, true, nil)
	plan.Add("add firewall allowlist", []string{"netsh", "advfirewall", "firewall", "add", "rule", "name=EasyTier", "dir=in", "action=allow", "interface=" + name}, true, []string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=EasyTier", "interface=" + name})
	plan.Warnings = append(plan.Warnings, "requires Wintun driver and firewall allowlist; registry cleanup via reg_delete_obsoleted_items")
	return plan, nil
}

func (a *WindowsAdapter) PlanRoutes(cfg RouteConfig) (Plan, error) {
	if cfg.IfName == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan("windows")
	if len(cfg.Routes) == 0 {
		plan.Warnings = append(plan.Warnings, "no routes to configure")
		return plan, nil
	}
	for _, r := range cfg.Routes {
		pfx, err := netip.ParsePrefix(r)
		if err != nil {
			return Plan{}, fmt.Errorf("%w: invalid CIDR %q: %v", ErrInvalidConfig, r, err)
		}
		metric := cfg.Metric
		if metric == 0 {
			metric = 9000
		}
		var cmd []string
		if cfg.Gateway != "" {
			cmd = []string{"route", "add", pfx.String(), cfg.Gateway, "metric", fmt.Sprintf("%d", metric), "if", cfg.IfName}
		} else {
			cmd = []string{"route", "add", pfx.String(), "0.0.0.0", "metric", fmt.Sprintf("%d", metric), "if", cfg.IfName}
		}
		if pfx.Addr().Is6() {
			if cfg.Gateway != "" {
				cmd = []string{"route", "add", pfx.String(), cfg.Gateway, "metric", fmt.Sprintf("%d", metric)}
			} else {
				cmd = []string{"route", "add", pfx.String(), "metric", fmt.Sprintf("%d", metric)}
			}
		}
		rollback := []string{"route", "delete", pfx.String()}
		plan.Add(fmt.Sprintf("add route %s metric %d", pfx.String(), metric), cmd, true, rollback)
	}
	return plan, nil
}

func (a *WindowsAdapter) PlanDNS(cfg DNSConfig) (Plan, error) {
	plan := newPlan("windows")
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
	for _, srv := range cfg.Servers {
		plan.Add("set DNS server", []string{"netsh", "interface", "ip", "set", "dns", cfg.IfName, "static", srv}, true, []string{"netsh", "interface", "ip", "set", "dns", cfg.IfName, "dhcp"})
	}
	plan.Add("disable dynamic DNS updates", []string{"reg", "set", "RegistrationEnabled=0", "DisableDynamicUpdate=1", cfg.IfName}, true, []string{"reg", "revert", cfg.IfName})
	plan.Add("disable NetBIOS", []string{"reg", "set", "NetbiosOptions=2", cfg.IfName}, true, nil)
	return plan, nil
}

func (a *WindowsAdapter) PlanService(cfg ServiceConfig) (Plan, error) {
	if err := ValidateService(cfg); err != nil {
		return Plan{}, err
	}
	plan := newPlan("windows")
	cmdline, err := RenderWindowsCommandLine(cfg)
	if err != nil {
		return Plan{}, err
	}
	_ = cmdline
	plan.Add("render Windows command line", []string{"windows-cmdline", cfg.Name}, false, nil)
	plan.Add("install Windows service", []string{"sc", "create", cfg.Name, "binPath=", cmdline, "start=", "auto"}, true, []string{"sc", "delete", cfg.Name})
	plan.Add("configure firewall allowlist", []string{"netsh", "advfirewall", "firewall", "add", "rule", "name=" + cfg.Name, "dir=in", "action=allow", "program=" + cfg.Exec}, true, []string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + cfg.Name})
	return plan, nil
}

func (a *WindowsAdapter) ApplyTun(cfg TunConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanTun(cfg); err != nil {
		return err
	}
	return nil
}
func (a *WindowsAdapter) ApplyRoutes(cfg RouteConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanRoutes(cfg); err != nil {
		return err
	}
	return nil
}
func (a *WindowsAdapter) ApplyDNS(cfg DNSConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanDNS(cfg); err != nil {
		return err
	}
	return nil
}
func (a *WindowsAdapter) ApplyService(cfg ServiceConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanService(cfg); err != nil {
		return err
	}
	return nil
}

func RenderWindowsCommandLine(cfg ServiceConfig) (string, error) {
	// Minimal reimplementation to avoid import cycle; mirrors internal/service_windows
	if cfg.Name == "" || cfg.Exec == "" {
		return "", fmt.Errorf("%w: service name/exec required", ErrInvalidConfig)
	}
	quoted := make([]string, 0, len(cfg.Args)+1)
	quoted = append(quoted, windowsQuote(cfg.Exec))
	for _, a := range cfg.Args {
		quoted = append(quoted, windowsQuote(a))
	}
	return strings.Join(quoted, " "), nil
}

func windowsQuote(v string) string {
	// Same logic as internal/service windowsQuote
	var b strings.Builder
	b.WriteByte('"')
	bs := 0
	for _, r := range v {
		switch r {
		case '\\':
			bs++
		case '"':
			b.WriteString(strings.Repeat("\\", bs*2+1))
			b.WriteByte('"')
			bs = 0
		default:
			b.WriteString(strings.Repeat("\\", bs))
			b.WriteRune(r)
			bs = 0
		}
	}
	b.WriteString(strings.Repeat("\\", bs*2))
	b.WriteByte('"')
	return b.String()
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
	"strings"
)

// DarwinAdapter implements macOS TUN, routes, DNS (scutil/resolver), launchd.
type DarwinAdapter struct{ BaseAdapter }

func (a *DarwinAdapter) Supported() bool { return true }

func (a *DarwinAdapter) PlanTun(cfg TunConfig) (Plan, error) {
	if err := validateTunConfig(cfg, false); err != nil {
		return Plan{}, err
	}
	plan := newPlan("darwin")
	if cfg.FD > 0 {
		plan.Add("use injected TUN FD", []string{"use-fd", fmt.Sprintf("%d", cfg.FD)}, true, []string{"close fd"})
		return plan, nil
	}
	name := cfg.Name
	if name == "" {
		name = "utun"
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1380
	}
	plan.Add("create utun device", []string{"open", "/dev/" + name}, true, []string{"close", "/dev/" + name})
	plan.Add("configure MTU", []string{"ifconfig", name, "mtu", fmt.Sprintf("%d", mtu)}, true, nil)
	plan.Add("bring up interface", []string{"ifconfig", name, "up"}, true, []string{"ifconfig", name, "down"})
	return plan, nil
}

func (a *DarwinAdapter) PlanRoutes(cfg RouteConfig) (Plan, error) {
	if cfg.IfName == "" {
		cfg.IfName = "utun0"
	}
	plan := newPlan("darwin")
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
			metric = 7
		}
		var cmd, rollback []string
		if pfx.Addr().Is6() {
			if cfg.Gateway != "" {
				cmd = []string{"route", "add", "-inet6", pfx.String(), cfg.Gateway, "-hopcount", fmt.Sprintf("%d", metric)}
			} else {
				cmd = []string{"route", "add", "-inet6", pfx.String(), "-interface", cfg.IfName, "-hopcount", fmt.Sprintf("%d", metric)}
			}
			rollback = []string{"route", "delete", "-inet6", pfx.String()}
		} else {
			mask := prefixMask(pfx)
			addr := pfx.Addr().String()
			if cfg.Gateway != "" {
				cmd = []string{"route", "-n", "add", addr, "-netmask", mask, cfg.Gateway}
			} else {
				cmd = []string{"route", "-n", "add", addr, "-netmask", mask, "-interface", cfg.IfName, "-hopcount", fmt.Sprintf("%d", metric)}
			}
			rollback = []string{"route", "-n", "delete", addr, "-netmask", mask, "-interface", cfg.IfName}
		}
		plan.Add(fmt.Sprintf("add route %s via %s metric %d", pfx.String(), cfg.IfName, metric), cmd, true, rollback)
	}
	return plan, nil
}

func (a *DarwinAdapter) PlanDNS(cfg DNSConfig) (Plan, error) {
	plan := newPlan("darwin")
	if len(cfg.Servers) == 0 {
		plan.Warnings = append(plan.Warnings, "no DNS servers")
		return plan, nil
	}
	// macOS uses scutil or /etc/resolver
	plan.Add("configure DNS via scutil", []string{"scutil", "--dns", strings.Join(cfg.Servers, ",")}, true, []string{"scutil", "--revert"})
	if cfg.Domain != "" {
		plan.Add("configure resolver for domain", []string{"mkdir", "-p", "/etc/resolver/" + cfg.Domain}, true, []string{"rm -rf /etc/resolver/" + cfg.Domain})
		plan.Add("write resolver file", []string{"write", "/etc/resolver/" + cfg.Domain, "nameserver " + cfg.Servers[0]}, true, nil)
	}
	plan.Warnings = append(plan.Warnings, "requires scutil or resolver file update; will restore on cleanup")
	return plan, nil
}

func (a *DarwinAdapter) PlanService(cfg ServiceConfig) (Plan, error) {
	if err := ValidateService(cfg); err != nil {
		return Plan{}, err
	}
	plan := newPlan("darwin")
	plist, err := RenderLaunchd(cfg)
	if err != nil {
		return Plan{}, err
	}
	plan.Add("render launchd plist", []string{"launchd-plist", cfg.Name}, false, nil)
	plan.Warnings = append(plan.Warnings, fmt.Sprintf("plist size %d bytes", len(plist)))
	plan.Add("load launchd service", []string{"launchctl", "load", "-w", "/Library/LaunchDaemons/" + cfg.Name + ".plist"}, true, []string{"launchctl", "unload", "-w", "/Library/LaunchDaemons/" + cfg.Name + ".plist"})
	plan.Add("enable at boot", []string{"launchctl", "enable", "system/" + cfg.Name}, true, nil)
	return plan, nil
}

func (a *DarwinAdapter) ApplyTun(cfg TunConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanTun(cfg); err != nil {
		return err
	}
	return nil
}
func (a *DarwinAdapter) ApplyRoutes(cfg RouteConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanRoutes(cfg); err != nil {
		return err
	}
	return nil
}
func (a *DarwinAdapter) ApplyDNS(cfg DNSConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanDNS(cfg); err != nil {
		return err
	}
	return nil
}
func (a *DarwinAdapter) ApplyService(cfg ServiceConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanService(cfg); err != nil {
		return err
	}
	return nil
}

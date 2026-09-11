// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
)

// FreeBSDAdapter implements TUN, routes, DNS (resolv.conf), rc.d.
type FreeBSDAdapter struct{ BaseAdapter }

func (a *FreeBSDAdapter) Supported() bool { return true }

func (a *FreeBSDAdapter) PlanTun(cfg TunConfig) (Plan, error) {
	if err := validateTunConfig(cfg, false); err != nil {
		return Plan{}, err
	}
	plan := newPlan("freebsd")
	if cfg.FD > 0 {
		plan.Add("use injected TUN FD", []string{"use-fd", fmt.Sprintf("%d", cfg.FD)}, true, nil)
		return plan, nil
	}
	name := cfg.Name
	if name == "" {
		name = "tun0"
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1380
	}
	plan.Add("create tun device", []string{"open", "/dev/" + name}, true, []string{"close /dev/" + name})
	plan.Add("set MTU", []string{"ifconfig", name, "mtu", fmt.Sprintf("%d", mtu)}, true, nil)
	plan.Add("up interface", []string{"ifconfig", name, "up"}, true, []string{"ifconfig", name, "down"})
	// FreeBSD often requires renaming
	if cfg.Name != "" && cfg.Name != name {
		plan.Add("rename interface", []string{"ifconfig", name, "name", cfg.Name}, true, []string{"ifconfig", cfg.Name, "name", name})
	}
	return plan, nil
}

func (a *FreeBSDAdapter) PlanRoutes(cfg RouteConfig) (Plan, error) {
	if cfg.IfName == "" {
		cfg.IfName = "tun0"
	}
	plan := newPlan("freebsd")
	if len(cfg.Routes) == 0 {
		plan.Warnings = append(plan.Warnings, "no routes")
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
		cmd := []string{"route", "add", "-net", pfx.String(), "-interface", cfg.IfName}
		if cfg.Gateway != "" {
			cmd = []string{"route", "add", pfx.String(), cfg.Gateway}
		}
		rollback := []string{"route", "delete", pfx.String()}
		plan.Add(fmt.Sprintf("add route %s metric %d", pfx.String(), metric), cmd, true, rollback)
	}
	return plan, nil
}

func (a *FreeBSDAdapter) PlanDNS(cfg DNSConfig) (Plan, error) {
	plan := newPlan("freebsd")
	if len(cfg.Servers) == 0 {
		plan.Warnings = append(plan.Warnings, "no DNS servers")
		return plan, nil
	}
	plan.Add("update /etc/resolv.conf", []string{"write-resolv", cfg.Servers[0]}, true, []string{"restore /etc/resolv.conf"})
	if len(cfg.Search) > 0 {
		plan.Add("add search domains", []string{"resolv-search", cfg.Search[0]}, true, nil)
	}
	plan.Warnings = append(plan.Warnings, "will restore original resolv.conf on cleanup")
	return plan, nil
}

func (a *FreeBSDAdapter) PlanService(cfg ServiceConfig) (Plan, error) {
	if err := ValidateService(cfg); err != nil {
		return Plan{}, err
	}
	plan := newPlan("freebsd")
	rcd, err := RenderFreeBSDRCD(cfg)
	if err != nil {
		return Plan{}, err
	}
	plan.Add("render rc.d script", []string{"rcd-script", cfg.Name}, false, nil)
	plan.Warnings = append(plan.Warnings, fmt.Sprintf("rc.d script size %d bytes", len(rcd)))
	plan.Add("enable rc.d service", []string{"service", cfg.Name, "enable"}, true, []string{"service", cfg.Name, "disable"})
	plan.Add("start rc.d service", []string{"service", cfg.Name, "start"}, true, []string{"service", cfg.Name, "stop"})
	return plan, nil
}

func (a *FreeBSDAdapter) ApplyTun(cfg TunConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanTun(cfg); err != nil {
		return err
	}
	return nil
}
func (a *FreeBSDAdapter) ApplyRoutes(cfg RouteConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanRoutes(cfg); err != nil {
		return err
	}
	return nil
}
func (a *FreeBSDAdapter) ApplyDNS(cfg DNSConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanDNS(cfg); err != nil {
		return err
	}
	return nil
}
func (a *FreeBSDAdapter) ApplyService(cfg ServiceConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanService(cfg); err != nil {
		return err
	}
	return nil
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
)

// RouteConfig describes desired routes for an interface.
type RouteConfig struct {
	IfName  string
	Routes  []string // CIDRs
	Gateway string
	Metric  int
}

// PlanRoutes returns a dry-run plan for installing routes.
// Linux uses `ip route`, macOS/FreeBSD use `route add` with hopcount/metric handling
// mirroring Rust ifcfg (netlink cost 65535, windows 9000, darwin hopcount 7).
func PlanRoutes(osName string, cfg RouteConfig) (Plan, error) {
	if cfg.IfName == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	if len(cfg.Routes) == 0 {
		plan.Warnings = append(plan.Warnings, "no routes to configure")
		return plan, nil
	}
	for _, r := range cfg.Routes {
		pfx, err := netip.ParsePrefix(r)
		if err != nil {
			return Plan{}, fmt.Errorf("%w: invalid CIDR %q: %v", ErrInvalidConfig, r, err)
		}
		var cmd, rollback []string
		metric := cfg.Metric
		switch osName {
		case "linux":
			if metric == 0 {
				metric = 65535
			}
			cmd = []string{"ip", "route", "add", pfx.String(), "dev", cfg.IfName}
			if cfg.Gateway != "" {
				cmd = []string{"ip", "route", "add", pfx.String(), "via", cfg.Gateway, "dev", cfg.IfName}
			}
			cmd = append(cmd, "metric", fmt.Sprintf("%d", metric))
			rollback = []string{"ip", "route", "del", pfx.String(), "dev", cfg.IfName}
			if pfx.Addr().Is6() && pfx.Bits() == 0 {
				// default ipv6 route via unspecified
				plan.Warnings = append(plan.Warnings, "default IPv6 route will use metric "+fmt.Sprintf("%d", metric))
			}
		case "darwin":
			if metric == 0 {
				metric = 7
			}
			if pfx.Addr().Is6() {
				if cfg.Gateway != "" {
					cmd = []string{"route", "add", "-inet6", pfx.String(), cfg.Gateway}
					if metric != 0 {
						cmd = append(cmd, "-hopcount", fmt.Sprintf("%d", metric))
					}
				} else {
					cmd = []string{"route", "add", "-inet6", pfx.String(), "-interface", cfg.IfName}
					if metric != 0 {
						cmd = append(cmd, "-hopcount", fmt.Sprintf("%d", metric))
					}
				}
				rollback = []string{"route", "delete", "-inet6", pfx.String()}
			} else {
				mask := prefixMask(pfx)
				addr := pfx.Addr().String()
				cmd = []string{"route", "-n", "add", addr, "-netmask", mask, "-interface", cfg.IfName, "-hopcount", fmt.Sprintf("%d", metric)}
				if cfg.Gateway != "" {
					cmd = []string{"route", "-n", "add", addr, "-netmask", mask, cfg.Gateway}
				}
				rollback = []string{"route", "-n", "delete", addr, "-netmask", mask, "-interface", cfg.IfName}
			}
		case "freebsd":
			if metric == 0 {
				metric = 7
			}
			cmd = []string{"route", "add", "-net", pfx.String(), "-interface", cfg.IfName}
			if cfg.Gateway != "" {
				cmd = []string{"route", "add", pfx.String(), cfg.Gateway}
			}
			rollback = []string{"route", "delete", pfx.String()}
		case "windows":
			if metric == 0 {
				metric = 9000
			}
			if cfg.Gateway != "" {
				cmd = []string{"route", "add", pfx.String(), cfg.Gateway, "metric", fmt.Sprintf("%d", metric), "if", cfg.IfName}
			} else {
				cmd = []string{"route", "add", pfx.String(), "0.0.0.0", "metric", fmt.Sprintf("%d", metric), "if", cfg.IfName}
			}
			rollback = []string{"route", "delete", pfx.String()}
		case "android":
			cmd = []string{"builder.addRoute", pfx.String(), cfg.IfName}
			rollback = []string{"builder.removeRoute", pfx.String()}
		default:
			cmd = []string{"route-add", pfx.String(), cfg.IfName}
			rollback = []string{"route-del", pfx.String()}
		}
		plan.add(fmt.Sprintf("add route %s via %s metric %d", pfx.String(), cfg.IfName, metric), cmd, true, rollback)
	}
	return plan, nil
}

// CleanupRoutes returns a plan that removes previously installed routes.
func CleanupRoutes(osName string, cfg RouteConfig) (Plan, error) {
	p, err := PlanRoutes(osName, cfg)
	if err != nil {
		return Plan{}, err
	}
	clean := newPlan(osName)
	for _, a := range p.Actions {
		if len(a.Rollback) > 0 {
			clean.add("remove route", a.Rollback, true, nil)
		}
	}
	return clean, nil
}

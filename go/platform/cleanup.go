// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
	"strings"
)

type CleanupManager struct {
	OS        string
	IfName    string
	Applied   []Action
	Rollbacks [][]string
}

func NewCleanupManager(osName, ifName string) *CleanupManager {
	return &CleanupManager{OS: osName, IfName: ifName}
}

func (m *CleanupManager) Track(plan Plan) {
	for _, a := range plan.Actions {
		m.Applied = append(m.Applied, a)
		if len(a.Rollback) > 0 {
			m.Rollbacks = append(m.Rollbacks, a.Rollback)
		}
	}
}

func (m *CleanupManager) PlanCleanup() Plan {
	plan := newPlan(m.OS)
	for i := len(m.Applied) - 1; i >= 0; i-- {
		a := m.Applied[i]
		if len(a.Rollback) > 0 {
			plan.Add("rollback: "+a.Description, a.Rollback, true, nil)
		}
	}
	if len(plan.Actions) == 0 {
		plan.Warnings = append(plan.Warnings, "no tracked state to clean up")
	}
	return plan
}

func PlanCrashRecovery(osName string, staleIfNames []string) (Plan, error) {
	plan := newPlan(osName)
	if len(staleIfNames) == 0 {
		plan.Warnings = append(plan.Warnings, "no stale interfaces detected; nothing to recover")
		return plan, nil
	}
	for _, name := range staleIfNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !isEasytierInterface(name) {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("skip non-EasyTier interface %q", name))
			continue
		}
		clean, err := PlanTunCleanup(osName, name)
		if err != nil {
			return Plan{}, err
		}
		for _, a := range clean.Actions {
			plan.Add(a.Description, a.Command, a.Privileged, nil)
		}
		addrClean, _ := CleanupAddresses(osName, name, nil)
		for _, a := range addrClean.Actions {
			plan.Add(a.Description, a.Command, a.Privileged, nil)
		}
		dnsClean := PlanDNSCleanup(osName, name)
		for _, a := range dnsClean.Actions {
			plan.Add(a.Description, a.Command, a.Privileged, nil)
		}
	}
	if len(plan.Actions) == 0 {
		plan.Warnings = append(plan.Warnings, "no EasyTier stale interfaces to clean")
	}
	return plan, nil
}

func PlanDNSCleanup(osName, ifName string) Plan {
	plan := newPlan(osName)
	switch osName {
	case "linux":
		plan.Add("revert systemd-resolved", []string{"resolvectl", "revert", ifName}, true, nil)
		plan.Add("restore resolv.conf", []string{"restore", "/etc/resolv.conf"}, true, nil)
	case "windows":
		plan.Add("flush DNS", []string{"ipconfig", "/flushdns"}, true, nil)
		plan.Add("reset DNS servers", []string{"netsh", "interface", "ip", "set", "dns", ifName, "dhcp"}, true, nil)
	case "darwin":
		plan.Add("revert scutil DNS", []string{"scutil", "--revert"}, true, nil)
		plan.Add("remove resolver files", []string{"rm", "-rf", "/etc/resolver/*et*"}, true, nil)
	case "freebsd":
		plan.Add("restore resolv.conf", []string{"restore", "/etc/resolv.conf"}, true, nil)
	default:
		plan.Add("revert DNS", []string{"dns-revert", ifName}, true, nil)
	}
	return plan
}

func PlanFullCleanup(osName, ifName string, routes []string, addrs []string) (Plan, error) {
	if strings.TrimSpace(ifName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	if len(routes) > 0 {
		rc, err := CleanupRoutes(osName, RouteConfig{IfName: ifName, Routes: routes})
		if err != nil {
			return Plan{}, err
		}
		plan.Actions = append(plan.Actions, rc.Actions...)
		plan.Warnings = append(plan.Warnings, rc.Warnings...)
		if rc.Privileged {
			plan.Privileged = true
		}
	}
	if len(addrs) > 0 {
		ac, err := CleanupAddresses(osName, ifName, addrs)
		if err != nil {
			return Plan{}, err
		}
		plan.Actions = append(plan.Actions, ac.Actions...)
		if ac.Privileged {
			plan.Privileged = true
		}
	} else {
		ac, _ := CleanupAddresses(osName, ifName, nil)
		plan.Actions = append(plan.Actions, ac.Actions...)
		if ac.Privileged {
			plan.Privileged = true
		}
	}
	dns := PlanDNSCleanup(osName, ifName)
	plan.Actions = append(plan.Actions, dns.Actions...)
	if dns.Privileged {
		plan.Privileged = true
	}
	tun, err := PlanTunCleanup(osName, ifName)
	if err != nil {
		return Plan{}, err
	}
	plan.Actions = append(plan.Actions, tun.Actions...)
	if tun.Privileged {
		plan.Privileged = true
	}
	return plan, nil
}

func PlanTunCleanup(osName string, ifName string) (Plan, error) {
	if strings.TrimSpace(ifName) == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	switch osName {
	case "linux":
		plan.Add("delete TUN interface", []string{"ip", "link", "delete", ifName}, true, nil)
		plan.Add("remove firewall rules", []string{"iptables", "-D", "FORWARD", "-i", ifName, "-j", "ACCEPT"}, true, nil)
	case "windows":
		plan.Add("remove firewall rules", []string{"netsh", "advfirewall", "firewall", "delete", "rule", "interface=" + ifName}, true, nil)
		plan.Add("delete Wintun adapter", []string{"wintun", "delete", ifName}, true, nil)
		plan.Add("cleanup registry obsoleted items", []string{"reg", "delete", "Profiles", "et_*"}, true, nil)
	case "darwin":
		plan.Add("bring down interface", []string{"ifconfig", ifName, "down"}, true, nil)
		plan.Add("close utun device", []string{"close", "/dev/" + ifName}, true, nil)
	case "freebsd":
		plan.Add("bring down interface", []string{"ifconfig", ifName, "down"}, true, nil)
		plan.Add("restore original tun name", []string{"ifconfig", "-g", "tun", "restore", ifName}, true, nil)
	default:
		plan.Add("delete TUN interface", []string{"tun-delete", ifName}, true, nil)
	}
	return plan, nil
}

func isEasytierInterface(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "et") ||
		strings.HasPrefix(lower, "tun") ||
		strings.HasPrefix(lower, "utun") ||
		strings.Contains(lower, "easytier")
}

func CleanupRoutes(osName string, cfg RouteConfig) (Plan, error) {
	p, err := PlanRoutes(osName, cfg)
	if err != nil {
		return Plan{}, err
	}
	clean := newPlan(osName)
	for _, a := range p.Actions {
		if len(a.Rollback) > 0 {
			clean.Add("remove route", a.Rollback, true, nil)
		}
	}
	return clean, nil
}

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
		pfx, err := parsePrefix(r)
		if err != nil {
			return Plan{}, err
		}
		metric := cfg.Metric
		var cmd, rollback []string
		switch osName {
		case "linux":
			if metric == 0 {
				metric = 65535
			}
			cmd = []string{"ip", "route", "add", pfx, "dev", cfg.IfName}
			if cfg.Gateway != "" {
				cmd = []string{"ip", "route", "add", pfx, "via", cfg.Gateway, "dev", cfg.IfName}
			}
			cmd = append(cmd, "metric", fmt.Sprintf("%d", metric))
			rollback = []string{"ip", "route", "del", pfx, "dev", cfg.IfName}
		case "darwin":
			if metric == 0 {
				metric = 7
			}
			cmd = []string{"route", "add", "-net", pfx, "-interface", cfg.IfName, "-hopcount", fmt.Sprintf("%d", metric)}
			if cfg.Gateway != "" {
				cmd = []string{"route", "add", "-net", pfx, cfg.Gateway}
			}
			rollback = []string{"route", "delete", "-net", pfx}
		case "freebsd":
			if metric == 0 {
				metric = 7
			}
			cmd = []string{"route", "add", "-net", pfx, "-interface", cfg.IfName}
			if cfg.Gateway != "" {
				cmd = []string{"route", "add", pfx, cfg.Gateway}
			}
			rollback = []string{"route", "delete", pfx}
		case "windows":
			if metric == 0 {
				metric = 9000
			}
			if cfg.Gateway != "" {
				cmd = []string{"route", "add", pfx, cfg.Gateway, "metric", fmt.Sprintf("%d", metric), "if", cfg.IfName}
			} else {
				cmd = []string{"route", "add", pfx, "0.0.0.0", "metric", fmt.Sprintf("%d", metric), "if", cfg.IfName}
			}
			rollback = []string{"route", "delete", pfx}
		default:
			cmd = []string{"route-add", pfx, cfg.IfName}
			rollback = []string{"route-del", pfx}
		}
		plan.Add(fmt.Sprintf("add route %s via %s metric %d", pfx, cfg.IfName, metric), cmd, true, rollback)
	}
	return plan, nil
}

func parsePrefix(s string) (string, error) {
	imported := strings.TrimSpace(s)
	pfx, err := netip.ParsePrefix(imported)
	if err != nil {
		return "", fmt.Errorf("%w: invalid CIDR %q: %v", ErrInvalidConfig, s, err)
	}
	return pfx.String(), nil
}

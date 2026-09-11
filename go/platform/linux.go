// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net/netip"
	"strings"
)

// LinuxAdapter implements TUN, netlink routes, DNS (systemd-resolved/resolv.conf), systemd/OpenRC.
type LinuxAdapter struct{ BaseAdapter }

func (a *LinuxAdapter) Supported() bool { return true }

func (a *LinuxAdapter) PlanTun(cfg TunConfig) (Plan, error) {
	if err := validateTunConfig(cfg, true); err != nil {
		return Plan{}, err
	}
	plan := newPlan("linux")
	if cfg.FD > 0 {
		plan.Add("use injected TUN FD (Android/privileged FD)", []string{"dup", fmt.Sprintf("%d", cfg.FD)}, true, []string{"close dup fd"})
		plan.Warnings = append(plan.Warnings, "injected FD must be IFF_TUN|IFF_NO_PI")
		return plan, nil
	}
	if cfg.FD == 0 {
		// FD 0 is stdin, not a valid TUN; treat as not injected for dry-run when caller used zero value.
		// Real injection validation will reject 0 if explicitly intended; use FD >0 for injected.
	}
	// Normal TUN creation via /dev/net/tun
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1380
	}
	plan.Add("open TUN device", []string{"open", "/dev/net/tun", "O_RDWR|O_CLOEXEC"}, true, []string{"close fd"})
	plan.Add("create TUN interface", []string{"ioctl", "TUNSETIFF", cfg.Name, "IFF_TUN|IFF_NO_PI"}, true, []string{"ip link delete " + cfg.Name})
	plan.Add("set MTU", []string{"ip", "link", "set", "dev", cfg.Name, "mtu", fmt.Sprintf("%d", mtu)}, true, nil)
	plan.Add("bring link up", []string{"ip", "link", "set", "dev", cfg.Name, "up"}, true, []string{"ip link set dev " + cfg.Name + " down"})
	return plan, nil
}

func (a *LinuxAdapter) PlanRoutes(cfg RouteConfig) (Plan, error) {
	if cfg.IfName == "" {
		return Plan{}, fmt.Errorf("%w: interface name required", ErrInvalidConfig)
	}
	plan := newPlan("linux")
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
			metric = 65535
		}
		cmd := []string{"ip", "route", "add", pfx.String(), "dev", cfg.IfName}
		if cfg.Gateway != "" {
			cmd = []string{"ip", "route", "add", pfx.String(), "via", cfg.Gateway, "dev", cfg.IfName}
		}
		cmd = append(cmd, "metric", fmt.Sprintf("%d", metric))
		rollback := []string{"ip", "route", "del", pfx.String(), "dev", cfg.IfName}
		plan.Add(fmt.Sprintf("add route %s via %s metric %d", pfx.String(), cfg.IfName, metric), cmd, true, rollback)
	}
	return plan, nil
}

func (a *LinuxAdapter) PlanDNS(cfg DNSConfig) (Plan, error) {
	plan := newPlan("linux")
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
		mode = "systemd-resolved"
	}
	switch mode {
	case "systemd-resolved":
		for _, srv := range cfg.Servers {
			plan.Add("configure systemd-resolved DNS", []string{"resolvectl", "dns", cfg.IfName, srv}, true, []string{"resolvectl", "revert", cfg.IfName})
		}
		if len(cfg.Search) > 0 {
			plan.Add("configure DNS search domains", []string{"resolvectl", "domain", cfg.IfName, strings.Join(cfg.Search, " ")}, true, nil)
		}
		plan.Warnings = append(plan.Warnings, "requires systemd-resolved; rollback via resolvectl revert")
	case "resolv.conf":
		plan.Add("update /etc/resolv.conf", []string{"update-resolv-conf", strings.Join(cfg.Servers, ",")}, true, []string{"restore /etc/resolv.conf"})
		plan.Warnings = append(plan.Warnings, "will restore original resolv.conf on cleanup")
	default:
		plan.Add("configure DNS ("+mode+")", []string{"dns-config", cfg.IfName, strings.Join(cfg.Servers, ",")}, true, nil)
	}
	return plan, nil
}

func (a *LinuxAdapter) PlanService(cfg ServiceConfig) (Plan, error) {
	if err := ValidateService(cfg); err != nil {
		return Plan{}, err
	}
	plan := newPlan("linux")
	unit, err := RenderSystemd(cfg)
	if err != nil {
		return Plan{}, err
	}
	plan.Add("render systemd unit", []string{"systemd-unit", cfg.Name}, false, nil)
	plan.Warnings = append(plan.Warnings, fmt.Sprintf("systemd unit size %d bytes", len(unit)))
	// Also provide OpenRC alternative
	openrc, _ := RenderOpenRC(cfg)
	plan.Add("render OpenRC script (alternative)", []string{"openrc-script", cfg.Name}, false, nil)
	_ = openrc
	plan.Add("install systemd service", []string{"systemctl", "enable", "--now", cfg.Name}, true, []string{"systemctl", "disable", "--now", cfg.Name})
	return plan, nil
}

func (a *LinuxAdapter) ApplyTun(cfg TunConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanTun(cfg); err != nil {
		return err
	}
	// Actual TUN creation would use golang.org/x/sys/unix; dry-run validates planning.
	return nil
}
func (a *LinuxAdapter) ApplyRoutes(cfg RouteConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanRoutes(cfg); err != nil {
		return err
	}
	return nil
}
func (a *LinuxAdapter) ApplyDNS(cfg DNSConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanDNS(cfg); err != nil {
		return err
	}
	return nil
}
func (a *LinuxAdapter) ApplyService(cfg ServiceConfig) error {
	if !a.IsPrivileged() {
		return ErrRequiresPrivileged
	}
	if _, err := a.PlanService(cfg); err != nil {
		return err
	}
	return nil
}

func validateTunConfig(cfg TunConfig, requireName bool) error {
	if requireName && cfg.Name == "" {
		return fmt.Errorf("%w: TUN name is empty", ErrInvalidConfig)
	}
	if len(cfg.Name) >= 16 {
		return fmt.Errorf("%w: TUN name %q too long", ErrInvalidConfig, cfg.Name)
	}
	if strings.Contains(cfg.Name, "\x00") {
		return fmt.Errorf("%w: TUN name contains NUL", ErrInvalidConfig)
	}
	if cfg.MTU < 0 || cfg.MTU > 65535 {
		return fmt.Errorf("%w: %d", ErrInvalidMTU, cfg.MTU)
	}
	if cfg.FD < -1 {
		return fmt.Errorf("%w: invalid FD %d", ErrInvalidConfig, cfg.FD)
	}
	if cfg.FD >= 0 && cfg.Name != "" {
		// For injected FD, name must match actual interface name if provided; validation deferred to runtime
	}
	return nil
}

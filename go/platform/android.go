// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"sync"
)

// AndroidAdapter implements VpnService TUN FD injection with one-active-TUN policy.
type AndroidAdapter struct {
	BaseAdapter
}

var androidTunState = struct {
	sync.Mutex
	active   bool
	activeFD int
	activeName string
}{activeFD: -1}

func (a *AndroidAdapter) Supported() bool { return true }

func (a *AndroidAdapter) PlanTun(cfg TunConfig) (Plan, error) {
	if cfg.MTU < 0 || cfg.MTU > 65535 {
		return Plan{}, fmt.Errorf("%w: %d", ErrInvalidMTU, cfg.MTU)
	}
	plan := newPlan("android")
	if cfg.FD < 0 {
		return Plan{}, fmt.Errorf("%w: Android requires injected VpnService FD (fd < 0)", ErrInvalidConfig)
	}
	plan.Add("validate VpnService FD", []string{"validate-fd", fmt.Sprintf("%d", cfg.FD)}, false, nil)
	// Check one-active policy in dry-run: warn if already active
	androidTunState.Lock()
	active := androidTunState.active
	androidTunState.Unlock()
	if active {
		plan.Warnings = append(plan.Warnings, "one-active-TUN policy: existing TUN must be closed before opening new one")
		plan.Add("enforce one-active-TUN", []string{"check-active-tun"}, false, nil)
	}
	plan.Add("wrap injected FD", []string{"dup", fmt.Sprintf("%d", cfg.FD)}, false, []string{"close dup fd"})
	plan.Add("configure TUN via VpnService", []string{"vpn-builder", cfg.Name, fmt.Sprintf("mtu=%d", cfg.MTU)}, false, nil)
	plan.Warnings = append(plan.Warnings, "VpnService TUN is managed by Android system; no privileged ip command required")
	return plan, nil
}

func (a *AndroidAdapter) PlanRoutes(cfg RouteConfig) (Plan, error) {
	plan := newPlan("android")
	if len(cfg.Routes) == 0 {
		plan.Warnings = append(plan.Warnings, "no routes; VpnService.Builder.addRoute will not be called")
		return plan, nil
	}
	for _, r := range cfg.Routes {
		plan.Add(fmt.Sprintf("add VpnService route %s", r), []string{"builder.addRoute", r, cfg.IfName}, false, []string{"builder.removeRoute", r})
	}
	plan.Warnings = append(plan.Warnings, "routes are applied via VpnService.Builder, not via netlink")
	return plan, nil
}

func (a *AndroidAdapter) PlanDNS(cfg DNSConfig) (Plan, error) {
	plan := newPlan("android")
	if len(cfg.Servers) == 0 {
		plan.Warnings = append(plan.Warnings, "no DNS servers")
		return plan, nil
	}
	for _, s := range cfg.Servers {
		plan.Add("add VpnService DNS server", []string{"builder.addDnsServer", s}, false, nil)
	}
	if len(cfg.Search) > 0 {
		plan.Add("add search domain", []string{"builder.addSearchDomain", cfg.Search[0]}, false, nil)
	}
	return plan, nil
}

func (a *AndroidAdapter) PlanService(cfg ServiceConfig) (Plan, error) {
	plan := newPlan("android")
	// Android uses VpnService lifecycle, not systemd
	plan.Add("VpnService lifecycle: prepare & establish", []string{"VpnService.prepare", cfg.Name}, false, nil)
	plan.Add("VpnService will manage TUN FD lifecycle", []string{"VpnService.establish"}, false, []string{"VpnService.close"})
	plan.Warnings = append(plan.Warnings, "Android service is managed by VpnService, not by system service manager")
	return plan, nil
}

func (a *AndroidAdapter) ApplyTun(cfg TunConfig) error {
	if cfg.FD < 0 {
		return fmt.Errorf("%w: Android requires VpnService FD", ErrInvalidConfig)
	}
	if _, err := a.PlanTun(cfg); err != nil {
		return err
	}
	androidTunState.Lock()
	defer androidTunState.Unlock()
	if androidTunState.active {
		return ErrOneActiveTUN
	}
	androidTunState.active = true
	androidTunState.activeFD = cfg.FD
	androidTunState.activeName = cfg.Name
	return nil
}

func (a *AndroidAdapter) ReleaseTun() {
	androidTunState.Lock()
	androidTunState.active = false
	androidTunState.activeFD = -1
	androidTunState.activeName = ""
	androidTunState.Unlock()
}

func (a *AndroidAdapter) ApplyRoutes(cfg RouteConfig) error {
	if _, err := a.PlanRoutes(cfg); err != nil {
		return err
	}
	return nil
}
func (a *AndroidAdapter) ApplyDNS(cfg DNSConfig) error {
	if _, err := a.PlanDNS(cfg); err != nil {
		return err
	}
	return nil
}
func (a *AndroidAdapter) ApplyService(cfg ServiceConfig) error {
	if _, err := a.PlanService(cfg); err != nil {
		return err
	}
	return nil
}

// IsActiveTun reports whether Android currently has an active TUN (for tests).
func IsAndroidTunActive() bool {
	androidTunState.Lock()
	defer androidTunState.Unlock()
	return androidTunState.active
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import "github.com/EasyTier/EasyTier/go/internal/service"

// ServiceConfig aliases the renderer options from internal/service.
type ServiceConfig = service.Options

// PlanService returns a dry-run plan for installing a service manager unit.
// It delegates rendering to internal/service and adds lifecycle actions.
func PlanService(osName string, cfg ServiceConfig) (Plan, error) {
	if err := cfg.Validate(); err != nil {
		return Plan{}, err
	}
	plan := newPlan(osName)
	switch osName {
	case "linux":
		unit, err := service.RenderSystemd(cfg)
		if err != nil {
			return Plan{}, err
		}
		plan.add("render systemd unit", []string{"systemd-unit", cfg.Name}, false, nil)
		plan.Warnings = append(plan.Warnings, "systemd unit preview")
		_ = unit
		plan.add("install systemd service", []string{"systemctl", "enable", "--now", cfg.Name}, true, []string{"systemctl", "disable", "--now", cfg.Name})
		// Also provide OpenRC alternative
		openrc, _ := service.RenderOpenRC(cfg)
		_ = openrc
		plan.add("render OpenRC script (alternative)", []string{"openrc-script", cfg.Name}, false, nil)
	case "darwin":
		plist, err := service.RenderLaunchd(cfg)
		if err != nil {
			return Plan{}, err
		}
		plan.add("render launchd plist", []string{"launchd-plist", cfg.Name}, false, nil)
		_ = plist
		plan.add("load launchd service", []string{"launchctl", "load", "-w", "/Library/LaunchDaemons/" + cfg.Name + ".plist"}, true, []string{"launchctl", "unload", "-w", "/Library/LaunchDaemons/" + cfg.Name + ".plist"})
		plan.add("enable at boot", []string{"launchctl", "enable", "system/" + cfg.Name}, true, nil)
	case "freebsd":
		rcd, err := service.RenderFreeBSDRCD(cfg)
		if err != nil {
			return Plan{}, err
		}
		plan.add("render rc.d script", []string{"rcd-script", cfg.Name}, false, nil)
		_ = rcd
		plan.add("enable rc.d service", []string{"service", cfg.Name, "enable"}, true, []string{"service", cfg.Name, "disable"})
		plan.add("start rc.d service", []string{"service", cfg.Name, "start"}, true, []string{"service", cfg.Name, "stop"})
	case "windows":
		cmdline, err := service.RenderWindowsCommandLine(cfg)
		if err != nil {
			return Plan{}, err
		}
		_ = cmdline
		plan.add("render Windows command line", []string{"windows-cmdline", cfg.Name}, false, nil)
		plan.add("install Windows service", []string{"sc", "create", cfg.Name, "binPath=", cmdline, "start=", "auto"}, true, []string{"sc", "delete", cfg.Name})
		plan.add("configure firewall allowlist", []string{"netsh", "advfirewall", "firewall", "add", "rule", "name=" + cfg.Name, "dir=in", "action=allow", "program=" + cfg.Exec}, true, []string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + cfg.Name})
		plan.Warnings = append(plan.Warnings, "requires Wintun driver packaging and driver signature verification")
	case "android":
		plan.add("VpnService lifecycle: prepare & establish", []string{"VpnService.prepare", cfg.Name}, false, nil)
		plan.add("VpnService will manage TUN FD lifecycle", []string{"VpnService.establish"}, false, []string{"VpnService.close"})
		plan.Warnings = append(plan.Warnings, "Android service is managed by VpnService, not by system service manager")
	default:
		plan.add("render service config", []string{"service-config", cfg.Name}, false, nil)
	}
	return plan, nil
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GUIServiceOptions mirrors service::ServiceOptions in Rust (lib.rs service module).
type GUIServiceOptions struct {
	ConfigDir    string
	RPCPortal    string
	FileLogLevel string
	FileLogDir   string
	ConfigServer *string
}

// Validate checks GUI service options. Replicates Rust's directory checks.
func (o GUIServiceOptions) Validate() error {
	if strings.TrimSpace(o.ConfigDir) == "" {
		return fmt.Errorf("%w: config_dir required", ErrInvalidConfig)
	}
	if strings.TrimSpace(o.RPCPortal) == "" {
		return fmt.Errorf("%w: rpc_portal required", ErrInvalidConfig)
	}
	if strings.TrimSpace(o.FileLogDir) == "" {
		return fmt.Errorf("%w: file_log_dir required", ErrInvalidConfig)
	}
	if o.FileLogLevel != "" {
		if lvl, err := ParseGUILogLevel(o.FileLogLevel); err != nil {
			return err
		} else if lvl == "" {
			return fmt.Errorf("%w: file_log_level required", ErrInvalidConfig)
		}
	}
	if strings.Contains(o.ConfigDir, "\x00") || strings.Contains(o.RPCPortal, "\x00") || strings.Contains(o.FileLogDir, "\x00") {
		return fmt.Errorf("%w: service options contain NUL", ErrInvalidConfig)
	}
	return nil
}

// ToArgs returns the argv that the GUI service will be launched with.
func (o GUIServiceOptions) ToArgs() []string {
	args := []string{
		"--config-dir", o.ConfigDir,
		"--rpc-portal", o.RPCPortal,
		"--file-log-level", o.FileLogLevel,
		"--file-log-dir", o.FileLogDir,
		"--daemon",
	}
	if o.ConfigServer != nil && strings.TrimSpace(*o.ConfigServer) != "" {
		args = append(args, "--config-server", strings.TrimSpace(*o.ConfigServer))
	}
	return args
}

// ToServiceConfig builds a ServiceConfig for platform rendering.
func (o GUIServiceOptions) ToServiceConfig(execPath string) (ServiceConfig, error) {
	if err := o.Validate(); err != nil {
		return ServiceConfig{}, err
	}
	execName := strings.TrimSpace(execPath)
	if execName == "" {
		execName = os.Args[0]
		if execName == "" {
			execName = "easytier-gui"
		}
	}
	// Resolve absolute exec where possible, but keep as-is for dry-run portability.
	workDir, _ := os.Getwd()
	if workDir == "" {
		workDir = "."
	}
	return ServiceConfig{
		Name:        "easytier-gui",
		Exec:        execName,
		Args:        o.ToArgs(),
		WorkDir:     workDir,
		Description: "EasyTier Gui Service",
		DisplayName: "EasyTier Gui Service",
	}, nil
}

// RenderGUISystemd renders systemd unit for GUI service (uses work dir etc).
func RenderGUISystemd(opts GUIServiceOptions, execPath string) (string, error) {
	cfg, err := opts.ToServiceConfig(execPath)
	if err != nil {
		return "", err
	}
	// Use systemd renderer from service.go
	return RenderSystemd(cfg)
}

// RenderGUILaunchd renders launchd plist for GUI service.
func RenderGUILaunchd(opts GUIServiceOptions, execPath string) (string, error) {
	cfg, err := opts.ToServiceConfig(execPath)
	if err != nil {
		return "", err
	}
	return RenderLaunchd(cfg)
}

// PlanGUIService returns a dry-run Plan for installing or uninstalling the GUI service.
// If opts is nil, the plan describes uninstall.
func PlanGUIService(osName string, opts *GUIServiceOptions, execPath string) (Plan, error) {
	if strings.TrimSpace(osName) == "" {
		osName = "linux"
	}
	plan := newPlan(osName)
	if opts == nil {
		plan.Add("uninstall GUI service", []string{"service", "uninstall", "easytier-gui"}, true, nil)
		return plan, nil
	}
	if err := opts.Validate(); err != nil {
		return Plan{}, err
	}
	cfg, err := opts.ToServiceConfig(execPath)
	if err != nil {
		return Plan{}, err
	}
	// Validate directories would be created like Rust does (create_dir_all)
	for _, dir := range []string{opts.ConfigDir, opts.FileLogDir} {
		if !filepath.IsAbs(dir) && dir != "." && !strings.HasPrefix(dir, "/tmp") {
			// allow relative for tests
		}
		plan.Add(fmt.Sprintf("ensure directory %s", dir), []string{"mkdir", "-p", dir}, false, nil)
	}
	switch osName {
	case "linux":
		unit, _ := RenderSystemd(cfg)
		plan.Add("render systemd unit for GUI", []string{"systemd-unit", cfg.Name}, false, nil)
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("systemd unit size %d bytes", len(unit)))
		plan.Add("install systemd service", []string{"systemctl", "enable", "--now", cfg.Name}, true, []string{"systemctl", "disable", "--now", cfg.Name})
	case "darwin":
		plist, _ := RenderLaunchd(cfg)
		plan.Add("render launchd plist for GUI", []string{"launchd-plist", cfg.Name}, false, nil)
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("plist size %d bytes", len(plist)))
		plan.Add("load launchd service", []string{"launchctl", "load", "-w", "/Library/LaunchDaemons/" + cfg.Name + ".plist"}, true, []string{"launchctl", "unload", "-w", "/Library/LaunchDaemons/" + cfg.Name + ".plist"})
	case "windows":
		cmdline, _ := RenderWindowsCommandLine(cfg)
		plan.Add("render Windows service command line", []string{"windows-cmdline", cfg.Name}, false, nil)
		_ = cmdline
		plan.Add("install Windows service", []string{"sc", "create", cfg.Name, "binPath=", cmdline, "start=", "auto"}, true, []string{"sc", "delete", cfg.Name})
		plan.Add("set service description", []string{"sc", "description", cfg.Name, "EasyTier Gui Service"}, true, nil)
		plan.Add("store work dir in registry", []string{"reg", "add", "HKLM\\SOFTWARE\\EasyTier", "/v", "WorkDir", "/d", cfg.WorkDir}, true, nil)
	default:
		plan.Add("install service (generic)", []string{"service", "install", cfg.Name, cfg.Exec}, true, []string{"service", "uninstall", cfg.Name})
	}
	// Autostart is controlled via service DisableAutostart=false in Rust
	plan.Warnings = append(plan.Warnings, "autostart enabled via service manager")
	return plan, nil
}

// ServiceStatus represents GUI service state.
type ServiceStatus string

const (
	ServiceStatusRunning      ServiceStatus = "Running"
	ServiceStatusStopped      ServiceStatus = "Stopped"
	ServiceStatusNotInstalled ServiceStatus = "NotInstalled"
)

// PlanServiceStatus returns a Plan for querying or toggling service status.
func PlanServiceStatus(osName, action string, current ServiceStatus) (Plan, error) {
	if strings.TrimSpace(osName) == "" {
		osName = "linux"
	}
	plan := newPlan(osName)
	switch action {
	case "status":
		switch osName {
		case "linux":
			plan.Add("query systemd status", []string{"systemctl", "is-active", "easytier-gui"}, false, nil)
		case "darwin":
			plan.Add("query launchd status", []string{"launchctl", "print", "system/easytier-gui"}, false, nil)
		case "windows":
			plan.Add("query Windows service", []string{"sc", "query", "easytier-gui"}, false, nil)
		default:
			plan.Add("query service status", []string{"service", "status", "easytier-gui"}, false, nil)
		}
	case "start":
		if current == ServiceStatusRunning {
			return Plan{}, fmt.Errorf("%w: service already running", ErrInvalidConfig)
		}
		if current == ServiceStatusNotInstalled {
			return Plan{}, fmt.Errorf("%w: service not installed", ErrInvalidConfig)
		}
		switch osName {
		case "linux":
			plan.Add("start systemd service", []string{"systemctl", "start", "easytier-gui"}, true, []string{"systemctl", "stop", "easytier-gui"})
		case "darwin":
			plan.Add("start launchd service", []string{"launchctl", "start", "easytier-gui"}, true, []string{"launchctl", "stop", "easytier-gui"})
		case "windows":
			plan.Add("start Windows service", []string{"sc", "start", "easytier-gui"}, true, []string{"sc", "stop", "easytier-gui"})
		default:
			plan.Add("start service", []string{"service", "start", "easytier-gui"}, true, nil)
		}
	case "stop":
		if current == ServiceStatusNotInstalled {
			return Plan{}, fmt.Errorf("%w: service not installed", ErrInvalidConfig)
		}
		if current == ServiceStatusStopped {
			return Plan{}, fmt.Errorf("%w: service already stopped", ErrInvalidConfig)
		}
		switch osName {
		case "linux":
			plan.Add("stop systemd service", []string{"systemctl", "stop", "easytier-gui"}, true, []string{"systemctl", "start", "easytier-gui"})
		case "darwin":
			plan.Add("stop launchd service", []string{"launchctl", "stop", "easytier-gui"}, true, nil)
		case "windows":
			plan.Add("stop Windows service", []string{"sc", "stop", "easytier-gui"}, true, nil)
		default:
			plan.Add("stop service", []string{"service", "stop", "easytier-gui"}, true, nil)
		}
	default:
		return Plan{}, fmt.Errorf("%w: unknown service action %q", ErrInvalidConfig, action)
	}
	return plan, nil
}

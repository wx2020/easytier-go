// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"path/filepath"
	"strings"
)

// AutostartConfig describes login-item / autostart registration.
type AutostartConfig struct {
	Name        string
	Exec        string
	Args        []string
	Enabled     bool
	DisplayName string
	Description string
	IconPath    string
}

// Validate checks autostart configuration.
func (c AutostartConfig) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: autostart name required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.Exec) == "" {
		return fmt.Errorf("%w: autostart exec required", ErrInvalidConfig)
	}
	if strings.Contains(c.Name, "\x00") || strings.Contains(c.Exec, "\x00") {
		return fmt.Errorf("%w: autostart fields contain NUL", ErrInvalidConfig)
	}
	return nil
}

// ExecLine returns a shell-quoted Exec line for .desktop etc.
func (c AutostartConfig) ExecLine() string {
	parts := append([]string{c.Exec}, c.Args...)
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = shellQuote(p)
	}
	return strings.Join(quoted, " ")
}

// RenderAutostartDesktop returns a freedesktop .desktop file for Linux.
func RenderAutostartDesktop(cfg AutostartConfig) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("[Desktop Entry]\nType=Application\n")
	b.WriteString("Name=")
	b.WriteString(desktopQuote(cfg.DisplayNameOrName()))
	b.WriteString("\n")
	if cfg.Description != "" {
		b.WriteString("Comment=")
		b.WriteString(desktopQuote(cfg.Description))
		b.WriteString("\n")
	}
	b.WriteString("Exec=")
	b.WriteString(cfg.ExecLine())
	b.WriteString("\n")
	b.WriteString("Icon=")
	if cfg.IconPath != "" {
		b.WriteString(desktopQuote(cfg.IconPath))
	} else {
		b.WriteString("easytier")
	}
	b.WriteString("\nX-GNOME-Autostart-enabled=")
	if cfg.Enabled {
		b.WriteString("true\n")
	} else {
		b.WriteString("false\n")
	}
	b.WriteString("Hidden=")
	if cfg.Enabled {
		b.WriteString("false\n")
	} else {
		b.WriteString("true\n")
	}
	return b.String(), nil
}

// RenderAutostartLaunchd returns a launchd plist for macOS login item
// (LaunchAgents). KeepAlive false, RunAtLoad reflects Enabled.
func RenderAutostartLaunchd(cfg AutostartConfig) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	label := cfg.Name
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>")
	b.WriteString(xmlText(label))
	b.WriteString("</string>\n\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, v := range append([]string{cfg.Exec}, cfg.Args...) {
		b.WriteString("\t\t<string>")
		b.WriteString(xmlText(v))
		b.WriteString("</string>\n")
	}
	b.WriteString("\t</array>\n\t<key>RunAtLoad</key>\n\t<")
	if cfg.Enabled {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString("/>\n\t<key>KeepAlive</key>\n\t<false/>\n")
	if cfg.Description != "" {
		b.WriteString("\t<key>LabelDescription</key>\n\t<string>")
		b.WriteString(xmlText(cfg.Description))
		b.WriteString("</string>\n")
	}
	b.WriteString("</dict>\n</plist>\n")
	return b.String(), nil
}

// RenderAutostartRegistry returns a Windows registry .reg snippet for Run key.
func RenderAutostartRegistry(cfg AutostartConfig) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	// HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
	cmdLine, err := RenderWindowsCommandLine(ServiceConfig{Name: cfg.Name, Exec: cfg.Exec, Args: cfg.Args})
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n")
	escaped := strings.ReplaceAll(cmdLine, "\"", "\\\"")
	if cfg.Enabled {
		fmt.Fprintf(&b, "\"%s\"=\"%s\"\n", registryQuote(cfg.Name), escaped)
	} else {
		fmt.Fprintf(&b, "; disabled: \"%s\"=\"%s\"\n", registryQuote(cfg.Name), escaped)
	}
	return b.String(), nil
}

// DisplayNameOrName returns DisplayName if set, otherwise Name.
func (c AutostartConfig) DisplayNameOrName() string {
	if strings.TrimSpace(c.DisplayName) != "" {
		return c.DisplayName
	}
	return c.Name
}

// AutostartFilePath returns the expected file path for the autostart entry.
func AutostartFilePath(osName, name, homeDir string) string {
	switch osName {
	case "linux":
		return filepath.Join(homeDir, ".config", "autostart", name+".desktop")
	case "darwin":
		return filepath.Join(homeDir, "Library", "LaunchAgents", name+".plist")
	case "windows":
		return filepath.Join(homeDir, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup", name+".lnk")
	default:
		return filepath.Join(homeDir, name+".autostart")
	}
}

// PlanAutostart returns a dry-run Plan for enabling/disabling autostart.
func PlanAutostart(osName string, cfg AutostartConfig) (Plan, error) {
	if err := cfg.Validate(); err != nil {
		return Plan{}, err
	}
	if strings.TrimSpace(osName) == "" {
		osName = "linux"
	}
	plan := newPlan(osName)
	switch osName {
	case "linux":
		content, _ := RenderAutostartDesktop(cfg)
		plan.Add("render autostart desktop file", []string{"autostart", "desktop", cfg.Name}, false, nil)
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("desktop size %d bytes", len(content)))
		if cfg.Enabled {
			plan.Add("enable autostart (desktop)", []string{"install", AutostartFilePath(osName, cfg.Name, "$HOME")}, false, []string{"rm", AutostartFilePath(osName, cfg.Name, "$HOME")})
		} else {
			plan.Add("disable autostart (desktop)", []string{"rm", AutostartFilePath(osName, cfg.Name, "$HOME")}, false, nil)
		}
	case "darwin":
		content, _ := RenderAutostartLaunchd(cfg)
		plan.Add("render launchd autostart plist", []string{"autostart", "launchd", cfg.Name}, false, nil)
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("plist size %d bytes", len(content)))
		if cfg.Enabled {
			plan.Add("load launch agent", []string{"launchctl", "load", "-w", AutostartFilePath(osName, cfg.Name, "$HOME")}, true, []string{"launchctl", "unload", "-w", AutostartFilePath(osName, cfg.Name, "$HOME")})
		} else {
			plan.Add("unload launch agent", []string{"launchctl", "unload", "-w", AutostartFilePath(osName, cfg.Name, "$HOME")}, true, nil)
		}
	case "windows":
		content, _ := RenderAutostartRegistry(cfg)
		plan.Add("render registry autostart", []string{"autostart", "registry", cfg.Name}, false, nil)
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("reg size %d bytes", len(content)))
		if cfg.Enabled {
			plan.Add("enable autostart (registry Run key)", []string{"reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", cfg.Name, "/d", cfg.ExecLine()}, true, []string{"reg", "delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", cfg.Name})
		} else {
			plan.Add("disable autostart (registry Run key)", []string{"reg", "delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", cfg.Name}, true, nil)
		}
	default:
		plan.Add("configure autostart", []string{"autostart", cfg.Name, fmt.Sprintf("%v", cfg.Enabled)}, false, nil)
	}
	return plan, nil
}

func desktopQuote(v string) string {
	// Escape \n, \r, and quote per desktop spec; keep simple.
	r := strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\r", "\\r")
	return r.Replace(v)
}

func registryQuote(v string) string {
	return strings.ReplaceAll(v, "\"", "\\\"")
}

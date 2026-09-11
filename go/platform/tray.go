// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"strings"
)

// TrayMenuItemKind enumerates menu entries used in the desktop tray.
type TrayMenuItemKind string

const (
	TrayMenuShow      TrayMenuItemKind = "show"
	TrayMenuSeparator TrayMenuItemKind = "separator"
	TrayMenuQuit      TrayMenuItemKind = "quit"
)

// TrayMenuItem describes a single tray menu entry.
type TrayMenuItem struct {
	Kind TrayMenuItemKind `json:"kind"`
	ID   string           `json:"id,omitempty"`
	Text string           `json:"text,omitempty"`
}

// TrayConfig describes the desired tray state. Mirrors tray.ts useTray.
type TrayConfig struct {
	Version string
	Tooltip string
	Title   string
	Icon    string // "icons/icon.ico" or "icons/icon-inactive.ico"
	Menu    []TrayMenuItem
}

// DefaultTrayConfig returns the standard EasyTier tray configuration.
func DefaultTrayConfig(version string) TrayConfig {
	return TrayConfig{
		Version: version,
		Tooltip: fmt.Sprintf("EasyTier\n%s", version),
		Title:   fmt.Sprintf("EasyTier\n%s", version),
		Icon:    "icons/icon.ico",
		Menu: []TrayMenuItem{
			{Kind: TrayMenuShow, ID: "show", Text: "Show / Hide"},
			{Kind: TrayMenuSeparator},
			{Kind: TrayMenuQuit, Text: "Exit"},
		},
	}
}

// WithRunningIcon toggles the icon based on whether the core is running.
// Matches setTrayRunState: isRunning ? inactive : active (note inversion in original TS).
func (c TrayConfig) WithRunningIcon(isRunning bool) TrayConfig {
	if isRunning {
		c.Icon = "icons/icon.ico"
	} else {
		c.Icon = "icons/icon-inactive.ico"
	}
	// Correct mapping per tray.ts: isRunning ? inactive : active was arguably inverted;
	// we keep explicit semantics: running -> active icon, stopped -> inactive.
	// Callers can override via SetTrayRunState mapping.
	return c
}

// ApplyTrayRunStateMapping matches the exact TS logic for compatibility:
// isRunning ? "icons/icon-inactive.ico" : "icons/icon.ico"
func (c TrayConfig) ApplyTrayRunStateMapping(isRunning bool) TrayConfig {
	if isRunning {
		c.Icon = "icons/icon-inactive.ico"
	} else {
		c.Icon = "icons/icon.ico"
	}
	return c
}

// WithExtraTooltip appends an extra tooltip line, mirroring setTrayTooltip.
func (c TrayConfig) WithExtraTooltip(extra string) TrayConfig {
	if strings.TrimSpace(extra) == "" {
		return c
	}
	c.Tooltip = fmt.Sprintf("EasyTier\n%s\n%s", c.Version, extra)
	c.Title = c.Tooltip
	return c
}

// Validate checks tray configuration.
func (c TrayConfig) Validate() error {
	if strings.TrimSpace(c.Version) == "" {
		return fmt.Errorf("%w: version required", ErrInvalidConfig)
	}
	if len(c.Menu) == 0 {
		return fmt.Errorf("%w: tray menu empty", ErrInvalidConfig)
	}
	return nil
}

// TrayAction describes a user interaction with the tray.
type TrayAction string

const (
	TrayActionToggleVisibility TrayAction = "toggle_visibility"
	TrayActionShow             TrayAction = "show"
	TrayActionHide             TrayAction = "hide"
	TrayActionQuit             TrayAction = "quit"
	TrayActionLeftClick        TrayAction = "left_click"
)

// TrayState tracks window visibility for toggle logic.
type TrayState struct {
	Visible   bool
	Minimized bool
	Focused   bool
}

// NextToggleTarget decides whether to show or hide based on current state.
// Mirrors toggleVisibility / toggle_window_visibility logic:
// should_show = !visible || minimized || !focused
func (s TrayState) NextToggleTarget() TrayAction {
	if !s.Visible || s.Minimized || !s.Focused {
		return TrayActionShow
	}
	return TrayActionHide
}

// PlanTray returns a dry-run Plan for tray creation/update on the given OS.
// It validates the config and describes the native tray API calls.
func PlanTray(osName string, cfg TrayConfig) (Plan, error) {
	if err := cfg.Validate(); err != nil {
		return Plan{}, err
	}
	if strings.TrimSpace(osName) == "" {
		osName = "linux"
	}
	plan := newPlan(osName)
	switch osName {
	case "windows", "linux", "darwin":
		menuDesc := make([]string, 0, len(cfg.Menu))
		for _, m := range cfg.Menu {
			menuDesc = append(menuDesc, string(m.Kind)+":"+m.Text)
		}
		plan.Add("create tray icon", []string{"tray", "create", cfg.Icon, cfg.Tooltip}, false, []string{"tray", "destroy"})
		plan.Add("set tray menu", []string{"tray", "set-menu", strings.Join(menuDesc, ",")}, false, nil)
		plan.Add("bind tray left-click to toggle", []string{"tray", "on-left-click", string(TrayActionToggleVisibility)}, false, nil)
		if osName == "darwin" {
			plan.Warnings = append(plan.Warnings, "iconAsTemplate true on macOS")
		}
		if osName == "windows" {
			plan.Warnings = append(plan.Warnings, "requires Windows notification area; tooltip limited to 127 chars")
		}
	default:
		plan.Add("create tray icon (generic)", []string{"tray", "create", cfg.Icon}, false, nil)
	}
	return plan, nil
}

// RenderTrayMenu generates a description of menu items for snapshot tests.
func RenderTrayMenu(items []TrayMenuItem) string {
	var b strings.Builder
	for i, it := range items {
		if i > 0 {
			b.WriteString("|")
		}
		switch it.Kind {
		case TrayMenuSeparator:
			b.WriteString("---")
		case TrayMenuQuit:
			b.WriteString("Quit:" + it.Text)
		case TrayMenuShow:
			b.WriteString("Show:" + it.Text)
		default:
			b.WriteString(string(it.Kind) + ":" + it.Text)
		}
	}
	return b.String()
}

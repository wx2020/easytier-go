// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"errors"
	"fmt"
	"strings"
)

// ElevatedCommand wraps a program invocation that may require privilege
// escalation. It mirrors Rust's elevate::Command.
type ElevatedCommand struct {
	Program string
	Args    []string
	Env     map[string]string
	Icon    []byte
	Name    string
	WorkDir string
}

// Validate checks that the command can be executed.
func (c *ElevatedCommand) Validate() error {
	if strings.TrimSpace(c.Program) == "" {
		return errors.New("program is required")
	}
	if strings.Contains(c.Program, "\x00") {
		return errors.New("program contains NUL")
	}
	for _, a := range c.Args {
		if strings.Contains(a, "\x00") {
			return errors.New("argument contains NUL")
		}
	}
	return nil
}

// IsElevated reports whether the current process has elevated privileges.
// It delegates to the platform isPrivileged helper and mirrors the Rust
// Command::is_elevated checks.
func IsElevated() bool { return isPrivileged() }

// PlanElevated returns a dry-run Plan describing how the command would be
// executed with elevation on the given OS. It never executes the command.
func (c *ElevatedCommand) Plan(osName string) (Plan, error) {
	if err := c.Validate(); err != nil {
		return Plan{}, err
	}
	if strings.TrimSpace(osName) == "" {
		osName = "linux"
	}
	switch osName {
	case "linux":
		return planElevatedLinux(c)
	case "darwin":
		return planElevatedDarwin(c)
	case "windows":
		return planElevatedWindows(c)
	case "android", "ios":
		plan := newPlan(osName)
		plan.Warnings = append(plan.Warnings, "elevation not applicable on mobile")
		plan.Add("run without elevation", append([]string{c.Program}, c.Args...), false, nil)
		return plan, nil
	default:
		plan := newPlan(osName)
		plan.Add("run elevated (generic)", append([]string{c.Program}, c.Args...), true, nil)
		return plan, nil
	}
}

func planElevatedLinux(c *ElevatedCommand) (Plan, error) {
	plan := newPlan("linux")
	// Mirrors elevate/linux.rs: pkexec --disable-internal-agent [env ...] program args
	cmd := []string{"pkexec", "--disable-internal-agent"}
	// Forward DISPLAY/XAUTHORITY/HOME or explicit env like Rust does.
	needsEnv := false
	if c.Env != nil {
		for _, v := range c.Env {
			if v != "" {
				needsEnv = true
				break
			}
		}
	}
	// We always include env handling via `env VAR=val` prefix if any env present.
	if len(c.Env) > 0 {
		needsEnv = true
	}
	if needsEnv {
		cmd = append(cmd, "env")
		for k, v := range c.Env {
			// Validate key/value do not contain invalid XML/control chars
			if strings.Contains(k, "=") || strings.Contains(k, "\x00") || strings.Contains(v, "\x00") {
				return Plan{}, fmt.Errorf("%w: invalid env %q", ErrInvalidConfig, k)
			}
			if strings.TrimSpace(k) == "" {
				continue
			}
			cmd = append(cmd, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd = append(cmd, c.Program)
	cmd = append(cmd, c.Args...)
	plan.Add("execute with pkexec", cmd, true, nil)
	plan.Warnings = append(plan.Warnings, "requires polkit pkexec; DISPLAY/XAUTHORITY/HOME forwarded when present")
	return plan, nil
}

func planElevatedDarwin(c *ElevatedCommand) (Plan, error) {
	plan := newPlan("darwin")
	// Mirrors elevate/macos.rs: AuthorizationExecuteWithPrivileges via osascript prompt
	// Dry-run: describe as osascript admin execution.
	cmd := []string{"osascript", "-e", fmt.Sprintf("do shell script \"%s %s\" with administrator privileges", c.Program, strings.Join(c.Args, " "))}
	// Alternative description: AuthorizationCreate + AuthorizationExecuteWithPrivileges
	plan.Add("execute with AuthorizationExecuteWithPrivileges", cmd, true, nil)
	if c.Name != "" {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("dialog name %q", c.Name))
	}
	plan.Warnings = append(plan.Warnings, "uses Authorization Services; stdin closed, stdout drained to avoid pipe block")
	return plan, nil
}

func planElevatedWindows(c *ElevatedCommand) (Plan, error) {
	plan := newPlan("windows")
	// Mirrors elevate/windows.rs: ShellExecuteW with "runas"
	// Dry-run: powershell Start-Process -Verb RunAs
	argStr := strings.Join(c.Args, " ")
	cmd := []string{"powershell", "-Command", fmt.Sprintf("Start-Process -FilePath \"%s\" -ArgumentList \"%s\" -Verb RunAs -WindowStyle Hidden", c.Program, argStr)}
	plan.Add("execute with ShellExecuteW runas", cmd, true, nil)
	plan.Warnings = append(plan.Warnings, "working directory becomes %SystemRoot%\\System32; env not forwarded")
	return plan, nil
}

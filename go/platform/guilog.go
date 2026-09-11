// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"path/filepath"
	"strings"
)

// GUILogLevel enumerates file logger levels.
type GUILogLevel string

const (
	GUILogOff   GUILogLevel = "off"
	GUILogTrace GUILogLevel = "trace"
	GUILogDebug GUILogLevel = "debug"
	GUILogInfo  GUILogLevel = "info"
	GUILogWarn  GUILogLevel = "warn"
	GUILogError GUILogLevel = "error"
)

// Valid reports whether level is allowed.
func (l GUILogLevel) Valid() bool {
	switch GUILogLevel(strings.ToLower(string(l))) {
	case GUILogOff, GUILogTrace, GUILogDebug, GUILogInfo, GUILogWarn, GUILogError:
		return true
	default:
		return false
	}
}

// ParseGUILogLevel normalizes a string to a GUILogLevel, defaulting to off for empty.
func ParseGUILogLevel(s string) (GUILogLevel, error) {
	ls := strings.ToLower(strings.TrimSpace(s))
	if ls == "" {
		return GUILogOff, nil
	}
	lvl := GUILogLevel(ls)
	if !lvl.Valid() {
		return "", fmt.Errorf("%w: invalid log level %q", ErrInvalidConfig, s)
	}
	return lvl, nil
}

// GUILogOptions describes GUI file logger configuration.
type GUILogOptions struct {
	Dir    string
	Level  GUILogLevel
	File   string
	SizeMB *int // nil means default 100
	Count  *int // nil means default 10
}

// Validate checks log options.
func (o GUILogOptions) Validate() error {
	if !o.Level.Valid() {
		return fmt.Errorf("%w: invalid log level %q", ErrInvalidConfig, o.Level)
	}
	if strings.Contains(o.Dir, "\x00") || strings.Contains(o.File, "\x00") {
		return fmt.Errorf("%w: log path contains NUL", ErrInvalidConfig)
	}
	if o.SizeMB != nil && *o.SizeMB <= 0 {
		return fmt.Errorf("%w: log size must be positive", ErrInvalidConfig)
	}
	if o.Count != nil && *o.Count < 0 {
		return fmt.Errorf("%w: log count cannot be negative", ErrInvalidConfig)
	}
	return nil
}

// EffectiveFile returns the file name, defaulting to easytier.log.
func (o GUILogOptions) EffectiveFile() string {
	if strings.TrimSpace(o.File) == "" {
		return "easytier.log"
	}
	return o.File
}

// EffectiveDir returns the directory, defaulting to ".".
func (o GUILogOptions) EffectiveDir() string {
	if strings.TrimSpace(o.Dir) == "" {
		return "."
	}
	return o.Dir
}

// LogFilePath returns the full log file path.
func (o GUILogOptions) LogFilePath() string {
	return filepath.Join(o.EffectiveDir(), o.EffectiveFile())
}

// ResolveGUILogDir returns the default log directory for the given OS.
// Mirrors Rust get_log_dir: android uses cacheDir/logs, otherwise appLogDir.
func ResolveGUILogDir(osName, appLogDir, cacheDir string) string {
	switch osName {
	case "android":
		base := strings.TrimSpace(cacheDir)
		if base == "" {
			base = "."
		}
		return filepath.Join(base, "logs")
	default:
		if strings.TrimSpace(appLogDir) != "" {
			return appLogDir
		}
		switch osName {
		case "windows":
			return filepath.Join(".", "logs")
		case "darwin":
			return filepath.Join(".", "logs")
		default:
			return filepath.Join(".", "logs")
		}
	}
}

// RenderGUILogConfig returns a TOML snippet for file logger, for snapshot tests.
func RenderGUILogConfig(o GUILogOptions) (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("[file_logger]\n")
	b.WriteString("dir = \"")
	b.WriteString(o.EffectiveDir())
	b.WriteString("\"\n")
	b.WriteString("level = \"")
	b.WriteString(string(o.Level))
	b.WriteString("\"\n")
	b.WriteString("file = \"")
	b.WriteString(o.EffectiveFile())
	b.WriteString("\"\n")
	if o.SizeMB != nil {
		fmt.Fprintf(&b, "size_mb = %d\n", *o.SizeMB)
	}
	if o.Count != nil {
		fmt.Fprintf(&b, "count = %d\n", *o.Count)
	}
	return b.String(), nil
}

// PlanGUILog returns a dry-run Plan for configuring GUI logging.
func PlanGUILog(osName string, opts GUILogOptions) (Plan, error) {
	if err := opts.Validate(); err != nil {
		return Plan{}, err
	}
	if strings.TrimSpace(osName) == "" {
		osName = "linux"
	}
	plan := newPlan(osName)
	level := opts.Level
	if level == "" {
		level = GUILogOff
	}
	switch level {
	case GUILogOff:
		plan.Add("disable file logging", []string{"log", "set-level", "off"}, false, nil)
		plan.Warnings = append(plan.Warnings, "file logger disabled; only console output")
	default:
		plan.Add("configure file logger", []string{"log", "set-level", string(level), "dir", opts.EffectiveDir(), "file", opts.EffectiveFile()}, false, []string{"log", "disable"})
		if opts.SizeMB != nil {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("max size %d MB", *opts.SizeMB))
		}
		if opts.Count != nil {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("retain %d files", *opts.Count))
		}
		plan.Warnings = append(plan.Warnings, "reuses RollingFileWriter; level reload via channel")
	}
	// Validate path creation
	plan.Add("ensure log directory", []string{"mkdir", "-p", opts.EffectiveDir()}, false, nil)
	return plan, nil
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package upgrade implements the version-gated configuration migration plan
// that carries an EasyTier node from a Rust-produced persisted config to the Go
// core and back. It holds no state: the caller supplies the LoadedConfig that
// config.Load produced and receives a deterministic plan.
package upgrade

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

// ReleaseVersion pins the release candidate the upgrade tests validate against
// (TestReleaseCandidateVersionIs264 also asserts the web Version constant).
const ReleaseVersion = "2.6.4"

// MinSupportedVersion is the oldest Rust configuration format the Go core can
// re-persist without loss and subsequently roll back to.
const MinSupportedVersion = "2.6.0"

// Version is a dotted major.minor.patch component identifier.
type Version struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion parses "N.N.N". Any other shape, including a trailing "v"
// prefix or a non-numeric component, is rejected so an unknown schema never
// slips through the compatibility gate.
func ParseVersion(raw string) (Version, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Version{}, fmt.Errorf("version string is empty")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version %q is not major.minor.patch", raw)
	}
	values := [3]int{-1, -1, -1}
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			return Version{}, fmt.Errorf("version component %d %q: %w", i, part, err)
		}
		if value < 0 {
			return Version{}, fmt.Errorf("version component %d %q is negative", i, part)
		}
		values[i] = value
	}
	return Version{Major: values[0], Minor: values[1], Patch: values[2]}, nil
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Less reports whether v sorts strictly before other.
func (v Version) Less(other Version) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor < other.Minor
	}
	return v.Patch < other.Patch
}

// Equal reports whether v equals other.
func (v Version) Equal(other Version) bool {
	return v.Major == other.Major && v.Minor == other.Minor && v.Patch == other.Patch
}

// Outcome classifies what an upgrade run must do.
type Outcome int

const (
	// OutcomeCurrent means the deployed schema already satisfies the persistence
	// contract; no migration is needed.
	OutcomeCurrent Outcome = iota
	// OutcomeMigrate means the loaded config came from a foreign core and the
	// node may rewrite it with the Go loader.
	OutcomeMigrate
	// OutcomeUnsupported means the version is older than MinSupported; the node
	// must refuse to start rather than risk silent data loss.
	OutcomeUnsupported
)

// Plan is the deterministic result of staging one upgrade.
type Plan struct {
	CurrentVersion Version
	MinSupported   Version
	Outcome        Outcome
	// NeedsPersist is true when the loaded file is writable and must be
	// rewritten by the Go loader.
	NeedsPersist bool
	// RollbackSafe is true when a Go re-persist stays parseable by the legacy
	// Rust-compatible loader (the control is deletable so a legacy copy can be
	// restored).
	RollbackSafe bool
	// IsStatic marks configuration delivered over stdin (STATIC_CONFIG), which
	// can never be persisted or rolled back.
	IsStatic bool
}

// MakePlan stages the config.ConfigFileControl produced by config.Load against
// MinSupportedVersion. The load outcome is fully determined by the control
// flags, so two runs over the same file produce an identical plan.
func MakePlan(loaded config.LoadedConfig) (Plan, error) {
	return MakePlanForVersion(loaded, MinSupportedVersion)
}

// MakePlanForVersion is MakePlan with an explicit minimum-version string, kept
// for tests and forward-compatible upgrades.
func MakePlanForVersion(loaded config.LoadedConfig, minRaw string) (Plan, error) {
	minVersion, err := ParseVersion(minRaw)
	if err != nil {
		return Plan{}, fmt.Errorf("parse minimum supported version: %w", err)
	}
	currentVersion, err := ParseVersion(ReleaseVersion)
	if err != nil {
		return Plan{}, fmt.Errorf("parse release version: %w", err)
	}

	plan := Plan{
		CurrentVersion: currentVersion,
		MinSupported:   minVersion,
		IsStatic:       loaded.Control == config.StaticConfigControl,
		NeedsPersist:   !loaded.Control.IsReadOnly(),
		RollbackSafe:   loaded.Control.IsDeletable(),
	}
	switch {
	case currentVersion.Less(minVersion):
		plan.Outcome = OutcomeUnsupported
	case plan.NeedsPersist:
		plan.Outcome = OutcomeMigrate
	default:
		plan.Outcome = OutcomeCurrent
	}
	return plan, nil
}

// MigrationCommand renders the audit-visible step list of a plan. The sequence
// is stable and append-only so log scrapers can rely on the strings.
func MigrationCommand(plan Plan) []string {
	switch plan.Outcome {
	case OutcomeUnsupported:
		return []string{
			"refuse start: persisted schema requires " + plan.MinSupported.String(),
			"minimum compatible release is " + plan.CurrentVersion.String(),
		}
	case OutcomeMigrate:
		steps := []string{"re-persist configuration through the Go loader"}
		if plan.RollbackSafe {
			steps = append(steps, "keep the legacy-parseable copy for rollback")
		} else {
			steps = append(steps, "rollback unavailable: config control is not deletable")
		}
		return steps
	default:
		return []string{"no migration required"}
	}
}
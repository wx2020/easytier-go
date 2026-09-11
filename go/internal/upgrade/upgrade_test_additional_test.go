// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package upgrade

import (
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

func TestParseVersionAndCompare(t *testing.T) {
	version, err := ParseVersion("2.6.4")
	if err != nil {
		t.Fatalf("parse 2.6.4: %v", err)
	}
	if version.Major != 2 || version.Minor != 6 || version.Patch != 4 {
		t.Fatalf("components = %d.%d.%d, want 2.6.4", version.Major, version.Minor, version.Patch)
	}
	older := Version{Major: 2, Minor: 6, Patch: 0}
	if !older.Less(version) {
		t.Fatalf("2.6.0 must sort before 2.6.4")
	}
	if version.Less(older) {
		t.Fatalf("2.6.4 must not sort before 2.6.0")
	}
	if !(Version{Major: 2, Minor: 6, Patch: 4}).Equal(version) {
		t.Fatalf("2.6.4 must equal 2.6.4")
	}
	if _, err := ParseVersion("2.6"); err == nil {
		t.Fatal("two-part version must be rejected")
	}
	if _, err := ParseVersion("alpha"); err == nil {
		t.Fatal("non-numeric version must be rejected")
	}
	if _, err := ParseVersion("2.-6.4"); err == nil {
		t.Fatal("negative component must be rejected")
	}
}

func TestMakePlanOutcomes(t *testing.T) {
	// Static stdin config: read-only and no-delete, never persisted.
	static := config.LoadedConfig{Control: config.StaticConfigControl}
	plan, err := MakePlan(static)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcome != OutcomeCurrent {
		t.Fatalf("static outcome = %v, want current", plan.Outcome)
	}
	if plan.NeedsPersist {
		t.Fatalf("static config must not be persisted")
	}
	if plan.RollbackSafe {
		t.Fatalf("static stdin config can never be rolled back")
	}
	if !plan.IsStatic {
		t.Fatalf("plan must mark the static control")
	}

	// A foreign persisted file with the default (read-write) control can be
	// re-persisted by Go and rolled back to a legacy copy.
	migratable := config.LoadedConfig{Control: config.ConfigFileControl{}}
	plan, err = MakePlan(migratable)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcome != OutcomeMigrate {
		t.Fatalf("writable file outcome = %v, want migrate", plan.Outcome)
	}
	if !plan.NeedsPersist {
		t.Fatalf("writable file must be re-persisted")
	}
	if !plan.RollbackSafe {
		t.Fatalf("writable file stays rollback-safe")
	}
	if plan.IsStatic {
		t.Fatalf("file control is not static")
	}

	// A read-only-but-deletable persisted file is not migrated (read-only),
	// but a legacy copy can still be restored.
	readOnly := config.LoadedConfig{Control: config.ConfigFileControl{Permission: config.PermissionReadOnly}}
	plan, err = MakePlan(readOnly)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcome != OutcomeCurrent {
		t.Fatalf("read-only outcome = %v, want current", plan.Outcome)
	}
	if plan.NeedsPersist {
		t.Fatalf("read-only file must not be persisted")
	}
	if !plan.RollbackSafe {
		t.Fatalf("deletable read-only file remains rollback-safe")
	}
}

func TestMakePlanUnsupportedVersion(t *testing.T) {
	plan, err := MakePlanForVersion(config.LoadedConfig{Control: config.ConfigFileControl{}}, "2.7.0")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcome != OutcomeUnsupported {
		t.Fatalf("2.6.4 under min 2.7.0 must be unsupported, got %v", plan.Outcome)
	}
}

func TestMigrationCommandStable(t *testing.T) {
	plan, err := MakePlan(config.LoadedConfig{Control: config.ConfigFileControl{}})
	if err != nil {
		t.Fatal(err)
	}
	commands := MigrationCommand(plan)
	if len(commands) != 2 {
		t.Fatalf("migrate commands = %d, want 2", len(commands))
	}
	// Deterministic across repeated staging.
	repeat, _ := MakePlan(config.LoadedConfig{Control: config.ConfigFileControl{}})
	if MigrationCommand(repeat)[0] != commands[0] {
		t.Fatalf("migration command is not deterministic")
	}
}

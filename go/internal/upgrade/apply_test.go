// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package upgrade

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

func testApplyConfig() config.Config {
	return config.Config{
		InstanceName: "apply-test",
		InstanceID:   "22222222-2222-2222-2222-222222222222",
		IPv4:         "10.20.0.1/24",
		NetworkIdentity: config.NetworkIdentity{
			NetworkName:   "apply-net",
			NetworkSecret: "s3cret",
		},
		Listeners: []string{"tcp://0.0.0.0:11010"},
	}
}

func writeRawConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyMigratesAndVerifies(t *testing.T) {
	cfg := testApplyConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	dump, err := cfg.Dump()
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a Rust-written file (extra whitespace/comments are fine).
	path := writeRawConfig(t, "# rust-written\n"+dump)
	loaded := config.LoadedConfig{
		Path:   path,
		Config: cfg,
		Control: config.ConfigFileControl{
			Path:       path,
			Permission: 0,
		},
	}
	result, err := Apply(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Persisted || !result.Verified {
		t.Fatalf("result = %+v, want persisted+verified", result)
	}
	if result.BackupPath == "" {
		t.Fatal("deletable config must produce a rollback backup")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}
	backup, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) == "" {
		t.Fatal("backup must preserve the pre-upgrade bytes")
	}
}

func TestApplyCurrentIsNoop(t *testing.T) {
	loaded := config.LoadedConfig{
		Config:  testApplyConfig(),
		Control: config.StaticConfigControl,
	}
	result, err := Apply(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if result.Persisted || result.BackupPath != "" {
		t.Fatalf("static config must not persist: %+v", result)
	}
}

func TestApplyRefusesUnsupported(t *testing.T) {
	loaded := config.LoadedConfig{
		Path:   filepath.Join(t.TempDir(), "config.toml"),
		Config: testApplyConfig(),
		Control: config.ConfigFileControl{
			Permission: 0,
		},
	}
	plan, err := MakePlanForVersion(loaded, "99.99.99")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Outcome != OutcomeUnsupported {
		t.Fatalf("outcome = %d, want unsupported", int(plan.Outcome))
	}
}

func TestRollbackRestoresBackup(t *testing.T) {
	cfg := testApplyConfig()
	dump, err := cfg.Dump()
	if err != nil {
		t.Fatal(err)
	}
	path := writeRawConfig(t, dump)
	loaded := config.LoadedConfig{
		Path:   path,
		Config: cfg,
		Control: config.ConfigFileControl{
			Path:       path,
			Permission: 0,
		},
	}
	result, err := Apply(loaded)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the live file, then roll back.
	if err := os.WriteFile(path, []byte("instance_name = \"corrupt\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(result.BackupPath, path); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(backup) {
		t.Fatal("rollback must restore the exact backup bytes")
	}
	if err := Rollback("", path); err == nil {
		t.Fatal("rollback without backup path must fail")
	}
}

func TestMigrationJournalIsAppendOnlyAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	applied, err := AppendMigration(path, "001-init", "initial schema")
	if err != nil || !applied {
		t.Fatalf("first append = %v, %v; want true, nil", applied, err)
	}
	applied, err = AppendMigration(path, "001-init", "initial schema")
	if err != nil || applied {
		t.Fatalf("second append = %v, %v; want false, nil", applied, err)
	}
	applied, err = AppendMigration(path, "002-add-index", "")
	if err != nil || !applied {
		t.Fatalf("third append = %v, %v; want true, nil", applied, err)
	}
	entries, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].ID != "001-init" || entries[1].ID != "002-add-index" {
		t.Fatalf("journal = %+v", entries)
	}
	if _, err := AppendMigration(path, "", "empty"); err == nil {
		t.Fatal("empty migration id must fail")
	}
	if entries, err := LoadJournal(filepath.Join(t.TempDir(), "missing.jsonl")); err != nil || len(entries) != 0 {
		t.Fatalf("missing journal = %v, %v; want empty, nil", entries, err)
	}
}

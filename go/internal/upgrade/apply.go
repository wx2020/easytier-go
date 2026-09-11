// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package upgrade

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

// configFileMode mirrors the Rust launcher's persisted-config permissions.
const configFileMode = 0o600

// ApplyResult reports what Apply did.
type ApplyResult struct {
	Plan       Plan
	Persisted  bool
	BackupPath string
	Verified   bool
}

// Apply executes a migration plan against loaded: it re-persists the config
// through the Go loader (deterministic Dump, mode 0600, atomic rename),
// keeps a rollback backup when the control is deletable, and verifies the
// result by reloading. OutcomeCurrent plans are no-ops; OutcomeUnsupported
// plans are refused with an error; static (stdin) configs are never
// persisted.
func Apply(loaded config.LoadedConfig) (ApplyResult, error) {
	plan, err := MakePlan(loaded)
	if err != nil {
		return ApplyResult{}, err
	}
	result := ApplyResult{Plan: plan}
	switch plan.Outcome {
	case OutcomeUnsupported:
		return result, fmt.Errorf("refuse upgrade: persisted schema requires %s", plan.MinSupported.String())
	case OutcomeCurrent:
		return result, nil
	case OutcomeMigrate:
		// Proceed below.
	default:
		return result, fmt.Errorf("unknown upgrade outcome %d", int(plan.Outcome))
	}
	if loaded.Path == "" {
		return result, errors.New("upgrade needs a config file path, got empty")
	}
	dump, err := loaded.Config.Dump()
	if err != nil {
		return result, fmt.Errorf("dump config for upgrade: %w", err)
	}
	original, err := os.ReadFile(loaded.Path)
	if err != nil {
		return result, fmt.Errorf("read config for backup: %w", err)
	}
	if plan.RollbackSafe {
		backupPath := loaded.Path + ".pre-go"
		if err := writeFileAtomic(backupPath, original, configFileMode); err != nil {
			return result, fmt.Errorf("write rollback backup: %w", err)
		}
		result.BackupPath = backupPath
	}
	if err := writeFileAtomic(loaded.Path, []byte(dump), configFileMode); err != nil {
		return result, fmt.Errorf("persist upgraded config: %w", err)
	}
	result.Persisted = true
	reloaded, _, err := config.Load(loaded.Path, true)
	if err != nil {
		return result, fmt.Errorf("verify upgraded config: %w", err)
	}
	redump, err := reloaded.Dump()
	if err != nil {
		return result, fmt.Errorf("verify upgraded dump: %w", err)
	}
	if redump != dump {
		return result, errors.New("upgrade verification failed: reloaded dump differs")
	}
	result.Verified = true
	return result, nil
}

// Rollback restores targetPath from a backup written by Apply (mode 0600,
// atomic rename) and verifies the restored file loads.
func Rollback(backupPath, targetPath string) error {
	if backupPath == "" || targetPath == "" {
		return errors.New("rollback requires backup and target paths")
	}
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read rollback backup: %w", err)
	}
	if err := writeFileAtomic(targetPath, backup, configFileMode); err != nil {
		return fmt.Errorf("restore rollback backup: %w", err)
	}
	if _, _, err := config.Load(targetPath, true); err != nil {
		return fmt.Errorf("verify rolled back config: %w", err)
	}
	return nil
}

// writeFileAtomic writes data with mode via temp file + rename so readers
// never observe a half-written config.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".upgrade-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Migration is one append-only journal entry tracking executed upgrades
// (schema or data migrations). Re-applying a recorded ID is a no-op, which
// keeps migration runs idempotent across restarts.
type Migration struct {
	ID        string    `json:"id"`
	AppliedAt time.Time `json:"applied_at"`
	Note      string    `json:"note,omitempty"`
}

// LoadJournal reads the JSON-lines journal at path. A missing file yields
// an empty journal.
func LoadJournal(path string) ([]Migration, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read migration journal: %w", err)
	}
	var out []Migration
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry Migration
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("decode migration journal: %w", err)
		}
		out = append(out, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan migration journal: %w", err)
	}
	return out, nil
}

// AppendMigration records id in the journal at path (created with mode
// 0600). It reports whether the entry was newly applied; known IDs are
// skipped so reruns are idempotent.
func AppendMigration(path, id, note string) (bool, error) {
	if id == "" {
		return false, errors.New("migration id is required")
	}
	entries, err := LoadJournal(path)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.ID == id {
			return false, nil
		}
	}
	record, err := json.Marshal(Migration{ID: id, AppliedAt: time.Now().UTC(), Note: note})
	if err != nil {
		return false, fmt.Errorf("encode migration: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, configFileMode)
	if err != nil {
		return false, fmt.Errorf("open migration journal: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(record, '\n')); err != nil {
		return false, fmt.Errorf("append migration journal: %w", err)
	}
	return true, nil
}

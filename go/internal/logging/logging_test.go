// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package logging

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLoggerFiltersLevels(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, LevelInfo)

	if err := logger.Debug("hidden", nil); err != nil {
		t.Fatal(err)
	}
	if err := logger.Info("shown", nil); err != nil {
		t.Fatal(err)
	}
	if err := logger.Error("also shown", nil); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("record count = %d, want 2", len(lines))
	}
	var records []Record
	for _, line := range lines {
		var record Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if records[0].Level != LevelInfo || records[1].Level != LevelError {
		t.Fatalf("levels = %q, %q", records[0].Level, records[1].Level)
	}
}

func TestLoggerJSONFieldsAndEscaping(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, LevelTrace)
	fields := Fields{
		`quote"newline`: "value\nwith\"escaping",
		"nested":        map[string]any{"ok": true},
	}
	if err := logger.Warn("message\nwith\"escaping", fields); err != nil {
		t.Fatal(err)
	}

	var record Record
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record.Message != "message\nwith\"escaping" {
		t.Fatalf("message = %q", record.Message)
	}
	if record.Fields[`quote"newline`] != "value\nwith\"escaping" {
		t.Fatalf("fields = %#v", record.Fields)
	}
	if record.Fields["nested"].(map[string]any)["ok"] != true {
		t.Fatalf("nested fields = %#v", record.Fields["nested"])
	}
}

func TestRollingFileWriterRotatesAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path+".3", []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writer, err := NewRollingFileWriter(path, 10, 2)
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range []string{"one\n", "two\n", "three\n", "four\n"} {
		if _, err := writer.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("file count = %d, want active plus 2 backups", len(entries))
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("unexpected third backup, stat error = %v", err)
	}
	active, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(active) != "four\n" {
		t.Fatalf("active log = %q", active)
	}
}

func TestRollingFileWriterConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.log")
	writer, err := NewRollingFileWriter(path, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	const (
		workers = 8
		writes  = 100
	)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for write := 0; write < writes; write++ {
				if _, err := writer.Write([]byte("record\n")); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}(worker)
	}
	group.Wait()

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		if scanner.Text() != "record" {
			t.Fatalf("corrupt record %q", scanner.Text())
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != workers*writes {
		t.Fatalf("record count = %d, want %d", count, workers*writes)
	}
}

func TestRollingFileWriterRotatesAtExactBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundary.log")
	writer, err := NewRollingFileWriter(path, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := writer.Write([]byte("12345")); err != nil || n != 5 {
		t.Fatalf("first Write() = %d, %v", n, err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	active, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(active) != "x" {
		t.Fatalf("active log = %q, want %q", active, "x")
	}
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if string(rotated) != "12345" {
		t.Fatalf("rotated log = %q, want %q", rotated, "12345")
	}
}

func TestRollingFileWriterZeroRetainedFilesTruncatesAtBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "truncate.log")
	writer, err := NewRollingFileWriter(path, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("d")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	active, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(active) != "d" {
		t.Fatalf("active log = %q, want %q", active, "d")
	}
}

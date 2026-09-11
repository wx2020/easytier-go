// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package logging provides small structured logging primitives for the Go
// implementation.
package logging

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level is the severity of a log record.
type Level string

const (
	LevelTrace Level = "trace"
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Valid reports whether level is supported by the logger.
func (level Level) Valid() bool {
	switch level {
	case LevelTrace, LevelDebug, LevelInfo, LevelWarn, LevelError:
		return true
	default:
		return false
	}
}

func (level Level) rank() int32 {
	switch level {
	case LevelTrace:
		return 0
	case LevelDebug:
		return 1
	case LevelInfo:
		return 2
	case LevelWarn:
		return 3
	case LevelError:
		return 4
	default:
		return -1
	}
}

// Fields are key/value pairs attached to a record.
type Fields = map[string]any

// Record is the JSON representation emitted by Logger.
type Record struct {
	Time    time.Time `json:"time"`
	Level   Level     `json:"level"`
	Message string    `json:"message"`
	Fields  Fields    `json:"fields,omitempty"`
}

// Logger writes one JSON record per line to an io.Writer.
type Logger struct {
	out   io.Writer
	level atomic.Int32
	mu    sync.Mutex
}

// New creates a logger. An invalid level uses info, matching the management
// service's default level.
func New(out io.Writer, level Level) *Logger {
	logger := &Logger{out: out}
	if !level.Valid() {
		level = LevelInfo
	}
	logger.level.Store(level.rank())
	return logger
}

// NewLogger is an explicit alias for New.
func NewLogger(out io.Writer, level Level) *Logger {
	return New(out, level)
}

// Level returns the current minimum level.
func (logger *Logger) Level() Level {
	if logger == nil {
		return LevelInfo
	}
	return levelAtRank(logger.level.Load())
}

// SetLevel changes the minimum level for future records.
func (logger *Logger) SetLevel(level Level) error {
	if logger == nil {
		return errors.New("logger is nil")
	}
	if !level.Valid() {
		return fmt.Errorf("invalid log level %q", level)
	}
	logger.level.Store(level.rank())
	return nil
}

// Enabled reports whether records at level would be written.
func (logger *Logger) Enabled(level Level) bool {
	return logger != nil && level.Valid() && level.rank() >= logger.level.Load()
}

// Log writes a structured record unless it is below the configured level.
func (logger *Logger) Log(level Level, message string, fields Fields) error {
	if logger == nil {
		return errors.New("logger is nil")
	}
	if !level.Valid() {
		return fmt.Errorf("invalid log level %q", level)
	}
	if !logger.Enabled(level) {
		return nil
	}
	if logger.out == nil {
		return errors.New("logger writer is nil")
	}

	record, err := json.Marshal(Record{
		Time:    time.Now().UTC(),
		Level:   level,
		Message: message,
		Fields:  fields,
	})
	if err != nil {
		return fmt.Errorf("marshal log record: %w", err)
	}
	record = append(record, '\n')

	logger.mu.Lock()
	defer logger.mu.Unlock()
	if n, err := logger.out.Write(record); err != nil {
		return err
	} else if n != len(record) {
		return io.ErrShortWrite
	}
	return nil
}

// Trace writes a trace-level record.
func (logger *Logger) Trace(message string, fields Fields) error {
	return logger.Log(LevelTrace, message, fields)
}

// Debug writes a debug-level record.
func (logger *Logger) Debug(message string, fields Fields) error {
	return logger.Log(LevelDebug, message, fields)
}

// Info writes an info-level record.
func (logger *Logger) Info(message string, fields Fields) error {
	return logger.Log(LevelInfo, message, fields)
}

// Warn writes a warn-level record.
func (logger *Logger) Warn(message string, fields Fields) error {
	return logger.Log(LevelWarn, message, fields)
}

// Error writes an error-level record.
func (logger *Logger) Error(message string, fields Fields) error {
	return logger.Log(LevelError, message, fields)
}

func levelAtRank(rank int32) Level {
	switch rank {
	case 0:
		return LevelTrace
	case 1:
		return LevelDebug
	case 2:
		return LevelInfo
	case 3:
		return LevelWarn
	case 4:
		return LevelError
	default:
		return LevelInfo
	}
}

// RollingFileWriter writes to path and rotates it when it exceeds maxSize.
// The active file is path; rotated files are path.1 through path.maxFiles.
// maxFiles counts retained rotated files and may be zero.
type RollingFileWriter struct {
	path     string
	maxSize  int64
	maxFiles int

	mu     sync.Mutex
	file   *os.File
	size   int64
	closed bool
}

// NewRollingFileWriter opens path and creates a size-based rolling writer.
func NewRollingFileWriter(path string, maxSize int64, maxFiles int) (*RollingFileWriter, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("rolling log path is empty")
	}
	if maxSize <= 0 {
		return nil, errors.New("rolling log size must be positive")
	}
	if maxFiles < 0 {
		return nil, errors.New("retained log file count cannot be negative")
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open rolling log: %w", err)
	}
	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat rolling log: %w", err)
	}
	writer := &RollingFileWriter{
		path:     path,
		maxSize:  maxSize,
		maxFiles: maxFiles,
		file:     file,
		size:     stat.Size(),
	}
	if err := writer.cleanup(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return writer, nil
}

// Write appends p atomically with respect to other writes and rotates before
// a write that would exceed the configured size.
func (writer *RollingFileWriter) Write(p []byte) (int, error) {
	if writer == nil {
		return 0, errors.New("rolling log writer is nil")
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return 0, errors.New("rolling log writer is closed")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if writer.size > 0 && (writer.size >= writer.maxSize || int64(len(p)) > writer.maxSize-writer.size) {
		if err := writer.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := writer.file.Write(p)
	writer.size += int64(n)
	if err == nil && n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, err
}

// Close closes the active log file. It is safe to call once; later calls
// return an error.
func (writer *RollingFileWriter) Close() error {
	if writer == nil {
		return errors.New("rolling log writer is nil")
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return errors.New("rolling log writer is closed")
	}
	writer.closed = true
	return writer.file.Close()
}

func (writer *RollingFileWriter) rotate() error {
	if err := writer.file.Close(); err != nil {
		return fmt.Errorf("close log before rotation: %w", err)
	}
	if writer.maxFiles == 0 {
		if err := os.Truncate(writer.path, 0); err != nil {
			return fmt.Errorf("truncate log during rotation: %w", err)
		}
	} else {
		for index := writer.maxFiles; index >= 1; index-- {
			oldPath := writer.rotatedPath(index)
			if index == writer.maxFiles {
				if err := os.Remove(oldPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("remove old log %q: %w", oldPath, err)
				}
				continue
			}
			if err := os.Rename(oldPath, writer.rotatedPath(index+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("rotate log %q: %w", oldPath, err)
			}
		}
		if err := os.Rename(writer.path, writer.rotatedPath(1)); err != nil {
			return fmt.Errorf("rotate log: %w", err)
		}
	}

	file, err := os.OpenFile(writer.path, os.O_CREATE|os.O_TRUNC|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open new rolling log: %w", err)
	}
	writer.file = file
	writer.size = 0
	return nil
}

func (writer *RollingFileWriter) rotatedPath(index int) string {
	return writer.path + "." + strconv.Itoa(index)
}

func (writer *RollingFileWriter) cleanup() error {
	matches, err := filepath.Glob(writer.path + ".*")
	if err != nil {
		return fmt.Errorf("find rotated logs: %w", err)
	}
	for _, path := range matches {
		suffix := strings.TrimPrefix(path, writer.path+".")
		index, err := strconv.Atoi(suffix)
		if err != nil || index <= writer.maxFiles {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale log %q: %w", path, err)
		}
	}
	return nil
}

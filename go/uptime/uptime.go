// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package uptime ports the uptime monitor (UPT-01).
//
// It corresponds to the Rust crate `easytier-contrib/easytier-uptime`
// (monitor API, database, scheduler, dashboard integration). This
// placeholder provides the module version and minimal types so that
// `go build ./...` succeeds and module boundaries remain cycle-free.
package uptime

import "net/http"

const (
	ModuleName = "github.com/EasyTier/EasyTier/go/uptime"
	Version    = "2.6.4"
)

// Config holds uptime monitor configuration.
// DBPath and Interval are preserved for compatibility with the placeholder.
type Config struct {
	DBPath   string `json:"db_path"`
	Interval int    `json:"interval"` // seconds, health-check interval

	// Extended fields mirroring Rust AppConfig
	ListenAddr         string `json:"listen_addr"`
	AdminPassword      string `json:"admin_password"`
	JWTSecret          string `json:"jwt_secret"`
	HealthCheckTimeout int    `json:"health_check_timeout"` // seconds
	MaxRetries         int    `json:"max_retries"`

	CleanupRetentionDays    int `json:"cleanup_retention_days"`
	MaxHealthRecordsPerNode int `json:"max_health_records_per_node"`
	CleanupIntervalSec      int `json:"cleanup_interval_sec"`
}

// DefaultConfig returns a config with Rust-compatible defaults.
func DefaultConfig() Config {
	return Config{
		DBPath:                  "uptime.db",
		Interval:                30,
		ListenAddr:              "127.0.0.1:8080",
		AdminPassword:           "admin123",
		JWTSecret:               "default-jwt-secret",
		HealthCheckTimeout:      10,
		MaxRetries:              3,
		CleanupRetentionDays:    30,
		MaxHealthRecordsPerNode: 70000,
		CleanupIntervalSec:      1200,
	}
}

// Monitor is a placeholder uptime monitor (kept for compatibility).
// New code should use Server.
type Monitor struct {
	cfg Config
	srv *Server
}

// New creates a Monitor. It initialises a Server but does not start it.
func New(cfg Config) *Monitor {
	srv, _ := NewServer(cfg)
	return &Monitor{cfg: cfg, srv: srv}
}

// NewWithDB creates a Monitor with an existing DB (for tests).
func NewWithDB(cfg Config, db *DB) *Monitor {
	srv, _ := NewServerWithDB(cfg, db)
	return &Monitor{cfg: cfg, srv: srv}
}

// Version returns the module version.
func (m *Monitor) Version() string { return Version }

// Server returns the underlying Server.
func (m *Monitor) Server() *Server { return m.srv }

// Handler returns the HTTP handler.
func (m *Monitor) Handler() http.Handler {
	if m.srv != nil {
		return m.srv.Handler()
	}
	return nil
}

// DB returns the database handle.
func (m *Monitor) DB() *DB {
	if m.srv != nil {
		return m.srv.DB()
	}
	return nil
}

// Close releases resources.
func (m *Monitor) Close() error {
	if m.srv != nil {
		return m.srv.Close()
	}
	return nil
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package web implements the Go web control-plane service (WEB-03/WEB-04).
//
// It corresponds to the Rust crate `easytier-web` and the frontends
// `easytier-web/frontend` and `easytier-web/frontend-lib`.
//
// Responsibilities:
//   - WEB-01: config-server listeners and client session lifecycle over TCP/UDP/WS
//   - WEB-03: REST API, auth, RBAC, SQLite migrations (port of easytier-web)
//   - WEB-04: Vue console placeholder
package web

import (
	"net"
	"net/http"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/webclient"
)

const (
	ModuleName = "github.com/EasyTier/EasyTier/go/web"
	Version    = "2.6.4"
	APIVersion = "v1"
)

// Config holds web service configuration (WEB-01 / WEB-03).
// ListenAddr is the HTTP API listen address (e.g. "127.0.0.1:8080").
// DataDir is used for SQLite file and optional GeoIP DB.
// For in-memory fallback, DataDir may be empty, and DBPath may be ":memory:".
type Config struct {
	ListenAddr            string
	DataDir               string
	DBPath                string
	InternalAuthToken     string
	WebhookURL            string
	WebhookSecret         string
	WebInstanceID         string
	WebInstanceAPIBaseURL string
	GeoIPDB               string
	DisableRegistration   bool
	AllowAutoCreateUser   bool
	// OIDC (stub – WEB-03)
	OIDCIssuerURL       string
	OIDCClientID        string
	OIDCClientSecret    string
	OIDCRedirectURL     string
	OIDCUsernameClaim   string
	OIDCFrontendBaseURL string
	// WEB-02: optional Noise upgrade (required or downgraded)
	RequireSecureTransport bool
	DisableNoise           bool
	// WEB-04: versioned API
	WebAPIVersion string
}

// Server is the web control-plane server (config-server + REST API).
// It is created with New and started with Listen/ListenUDP/ListenWS + Serve.
type Server struct {
	cfg Config

	mu sync.Mutex

	store *store

	// WEB-01 config server
	configSrv *webclient.Server

	// WEB-03 REST API
	apiListener net.Listener
	httpSrv     *http.Server
	handler     http.Handler

	// lifecycle
	closed   bool
	closeErr error
}

// New creates a Server; it does not start listeners.
func New(cfg Config) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:8080"
	}
	if cfg.WebAPIVersion == "" {
		cfg.WebAPIVersion = APIVersion
	}
	s := &Server{cfg: cfg}
	s.store = newStore(cfg)
	// initialize config server (WEB-01 / WEB-02)
	cs, _ := webclient.NewServer(webclient.ServerConfig{
		RequireSecure: cfg.RequireSecureTransport,
		DisableNoise:  cfg.DisableNoise,
	})
	s.configSrv = cs
	s.handler = s.buildHandler()
	s.httpSrv = &http.Server{Handler: s.handler}
	return s
}

// Version returns the module version.
func (s *Server) Version() string { return Version }

// APIVersion returns the API version string.
func (s *Server) APIVersion() string { return APIVersion }

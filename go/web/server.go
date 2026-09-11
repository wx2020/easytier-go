// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/transport"
	"github.com/EasyTier/EasyTier/go/internal/webclient"
)

// Listen binds the config server to a TCP address. May be called once before Serve.
func (s *Server) Listen(address string) error {
	if s == nil {
		return errors.New("web server is nil")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.mu.Unlock()
	return s.configSrv.Listen(address)
}

// ListenUDP binds a UDP config-server listener.
func (s *Server) ListenUDP(address string) error {
	if s == nil {
		return errors.New("web server is nil")
	}
	return s.configSrv.ListenUDP(address)
}

// ListenWebSocket binds a WebSocket config-server listener.
func (s *Server) ListenWebSocket(address string, opts ...transport.WebSocketOptions) error {
	if s == nil {
		return errors.New("web server is nil")
	}
	return s.configSrv.ListenWebSocket(address, opts...)
}

// ListenWS is an alias for ListenWebSocket.
func (s *Server) ListenWS(address string, opts ...transport.WebSocketOptions) error {
	return s.ListenWebSocket(address, opts...)
}

// ListenAPI binds the HTTP REST API to an address.
func (s *Server) ListenAPI(address string) error {
	if s == nil {
		return errors.New("web server is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.apiListener != nil {
		return errors.New("web API server is already listening")
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen web API on %q: %w", address, err)
	}
	s.apiListener = ln
	return nil
}

// Addr returns the config server address (TCP) or nil.
func (s *Server) Addr() net.Addr {
	if s == nil {
		return nil
	}
	return s.configSrv.Addr()
}

// APIAddr returns the HTTP API listener address.
func (s *Server) APIAddr() net.Addr {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.apiListener == nil {
		return nil
	}
	return s.apiListener.Addr()
}

// Handler returns the HTTP handler (for tests without listening).
func (s *Server) Handler() http.Handler {
	if s == nil {
		return http.NotFoundHandler()
	}
	return s.handler
}

// Sessions returns all config-server sessions (WEB-01).
func (s *Server) Sessions() []webclient.Session {
	if s == nil || s.configSrv == nil {
		return nil
	}
	return s.configSrv.Sessions()
}

// Session returns a machine record by ID.
func (s *Server) Session(machineID string) (webclient.Session, bool) {
	if s == nil || s.configSrv == nil {
		return webclient.Session{}, false
	}
	return s.configSrv.Session(machineID)
}

// SendConfigUpdate sends a configuration update to one connected machine.
func (s *Server) SendConfigUpdate(ctx context.Context, machineID string, update webclient.ConfigUpdate) error {
	if s == nil || s.configSrv == nil {
		return errors.New("config server not initialized")
	}
	return s.configSrv.SendConfigUpdate(ctx, machineID, update)
}

// BroadcastConfigUpdate sends one update to every currently connected machine.
func (s *Server) BroadcastConfigUpdate(ctx context.Context, update webclient.ConfigUpdate) error {
	if s == nil || s.configSrv == nil {
		return errors.New("config server not initialized")
	}
	return s.configSrv.BroadcastConfigUpdate(ctx, update)
}

// Serve accepts config sessions and serves HTTP API until ctx is canceled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	if s == nil {
		return errors.New("web server is nil")
	}
	if ctx == nil {
		return errors.New("web server context is nil")
	}
	s.mu.Lock()
	apiListener := s.apiListener
	httpSrv := s.httpSrv
	s.mu.Unlock()

	// ensure we have at least one listener
	if apiListener == nil {
		// auto-listen on cfg.ListenAddr if not already
		if err := s.ListenAPI(s.cfg.ListenAddr); err != nil {
			return err
		}
		s.mu.Lock()
		apiListener = s.apiListener
		httpSrv = s.httpSrv
		s.mu.Unlock()
	}

	// start config server
	configErr := make(chan error, 1)
	go func() {
		err := s.configSrv.Serve(ctx)
		configErr <- err
	}()

	// start HTTP API
	apiErr := make(chan error, 1)
	go func() {
		// httpSrv.Serve will block; we use apiListener
		err := httpSrv.Serve(apiListener)
		if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
			apiErr <- nil
			return
		}
		apiErr <- err
	}()

	// Close handling
	stopClose := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stopClose()

	select {
	case err := <-configErr:
		_ = s.Close()
		// wait for api to finish
		<-apiErr
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
		return nil
	case err := <-apiErr:
		_ = s.Close()
		<-configErr
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		_ = s.Close()
		<-configErr
		<-apiErr
		return nil
	}
}

// Close stops accepting connections and closes active sessions. Idempotent.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		err := s.closeErr
		s.mu.Unlock()
		return err
	}
	s.closed = true
	s.mu.Unlock()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	addErr := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := s.configSrv.Close(); err != nil {
			addErr(err)
		}
	}()
	go func() {
		defer wg.Done()
		s.mu.Lock()
		ln := s.apiListener
		srv := s.httpSrv
		s.mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
		if srv != nil {
			if err := srv.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				addErr(err)
			}
		}
	}()
	wg.Wait()
	s.mu.Lock()
	s.closeErr = firstErr
	s.mu.Unlock()
	return firstErr
}

// Store returns in-memory store for inspection (migrations / tests).
func (s *Server) Store() interface{} { return s.store }

// Migrations returns the SQL migrations applied (for inspection).
func (s *Server) Migrations() []string { return migrationsSQL }

// ApplyMigrations executes the SQL migrations (in-memory; no-op for real DB).
func (s *Server) ApplyMigrations() error { return s.store.migrate() }

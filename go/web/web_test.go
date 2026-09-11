// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/webclient"
)

func TestPlaceholderVersion(t *testing.T) {
	srv := New(Config{})
	if srv.Version() != Version {
		t.Fatalf("Version = %q, want %q", srv.Version(), Version)
	}
	if srv.APIVersion() != APIVersion {
		t.Fatalf("APIVersion = %q, want %q", srv.APIVersion(), APIVersion)
	}
}

func TestMigrations(t *testing.T) {
	srv := New(Config{})
	if len(srv.Migrations()) != 3 {
		t.Fatalf("migrations count = %d, want 3", len(srv.Migrations()))
	}
	if err := srv.ApplyMigrations(); err != nil {
		t.Fatalf("ApplyMigrations error = %v", err)
	}
	// Ensure default users exist
	if _, ok := srv.store.getUserByUsername("user"); !ok {
		t.Fatal("user not found after migration")
	}
	if _, ok := srv.store.getUserByUsername("admin"); !ok {
		t.Fatal("admin not found after migration")
	}
}

func TestWEB01_TCP_RegistrationHeartbeatAndConfigUpdate(t *testing.T) {
	srv := New(Config{ListenAddr: "127.0.0.1:0"})
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(50 * time.Millisecond)
	addr := srv.Addr().String()
	if addr == "" {
		t.Fatal("Addr is empty")
	}
	updates := make(chan webclient.ConfigUpdate, 1)
	client, err := webclient.NewClient(webclient.ClientConfig{
		Address:             addr,
		MachineID:           "machine-tcp-01",
		MachineName:         "test-tcp",
		HeartbeatInterval:   10 * time.Millisecond,
		ReconnectMinBackoff: 5 * time.Millisecond,
		ReconnectMaxBackoff: 20 * time.Millisecond,
		OnConfigUpdate:      func(u webclient.ConfigUpdate) { updates <- u },
	})
	if err != nil {
		t.Fatal(err)
	}
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	go func() { _ = client.Run(cctx) }()

	// wait for connected
	waitFor(t, func() bool {
		s, ok := srv.Session("machine-tcp-01")
		return ok && s.Connected
	})
	first, _ := srv.Session("machine-tcp-01")
	waitFor(t, func() bool {
		cur, ok := srv.Session("machine-tcp-01")
		return ok && cur.LastSeen.After(first.LastSeen)
	})
	if err := srv.SendConfigUpdate(context.Background(), "machine-tcp-01", webclient.ConfigUpdate{
		Version: "2",
		Config:  json.RawMessage(`{"network":"mesh"}`),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case u := <-updates:
		if u.Version != "2" || string(u.Config) != `{"network":"mesh"}` {
			t.Fatalf("config update = %#v", u)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for config update")
	}
}

func TestWEB01_UDPAndWS(t *testing.T) {
	tests := []struct {
		name   string
		listen func(*Server) error
		scheme string
	}{
		{
			name:   "udp",
			listen: func(s *Server) error { return s.ListenUDP("127.0.0.1:0") },
			scheme: "udp",
		},
		{
			name:   "websocket",
			listen: func(s *Server) error { return s.ListenWS("127.0.0.1:0") },
			scheme: "ws",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := New(Config{ListenAddr: "127.0.0.1:0"})
			if err := tc.listen(srv); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = srv.Serve(ctx) }()
			time.Sleep(50 * time.Millisecond)
			addr := srv.Addr().String()
			if addr == "" {
				t.Fatal("Addr empty")
			}
			clientAddr := addr
			if tc.scheme != "tcp" {
				clientAddr = tc.scheme + "://" + addr
			}
			updates := make(chan webclient.ConfigUpdate, 1)
			client, err := webclient.NewClient(webclient.ClientConfig{
				Address:             clientAddr,
				MachineID:           "machine-" + tc.name,
				HeartbeatInterval:   10 * time.Millisecond,
				ReconnectMinBackoff: 5 * time.Millisecond,
				ReconnectMaxBackoff: 20 * time.Millisecond,
				OnConfigUpdate:      func(u webclient.ConfigUpdate) { updates <- u },
			})
			if err != nil {
				t.Fatal(err)
			}
			cctx, ccancel := context.WithCancel(context.Background())
			defer ccancel()
			go func() { _ = client.Run(cctx) }()
			waitFor(t, func() bool {
				s, ok := srv.Session("machine-" + tc.name)
				return ok && s.Connected
			})
			if err := srv.SendConfigUpdate(context.Background(), "machine-"+tc.name, webclient.ConfigUpdate{Config: json.RawMessage(`{"mode":"loopback"}`)}); err != nil {
				t.Fatal(err)
			}
			select {
			case u := <-updates:
				if string(u.Config) != `{"mode":"loopback"}` {
					t.Fatalf("config update = %#v", u)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out")
			}
		})
	}
}

func TestWEB03_AuthAndRBAC(t *testing.T) {
	srv := New(Config{ListenAddr: "127.0.0.1:0"})
	h := srv.Handler()

	// login as user (password is md5("user"))
	body, _ := json.Marshal(map[string]string{"username": "user", "password": "ee11cbb19052e40b07aac0ca060c23ee"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status %d body %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie")
	}

	// check login status
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/check_login_status", nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("check_login_status %d body %s", rec2.Code, rec2.Body.String())
	}

	// sessions requires auth
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("sessions without auth %d want 401", rec3.Code)
	}
	req3c := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	for _, c := range cookies {
		req3c.AddCookie(c)
	}
	rec3c := httptest.NewRecorder()
	h.ServeHTTP(rec3c, req3c)
	if rec3c.Code != http.StatusOK {
		t.Fatalf("sessions with auth %d body %s", rec3c.Code, rec3c.Body.String())
	}

	// summary
	req4 := httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil)
	for _, c := range cookies {
		req4.AddCookie(c)
	}
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Fatalf("summary %d body %s", rec4.Code, rec4.Body.String())
	}
	var summary map[string]any
	if err := json.Unmarshal(rec4.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if _, ok := summary["device_count"]; !ok {
		t.Fatalf("summary missing device_count: %v", summary)
	}

	// machines
	req5 := httptest.NewRequest(http.MethodGet, "/api/v1/machines", nil)
	for _, c := range cookies {
		req5.AddCookie(c)
	}
	rec5 := httptest.NewRecorder()
	h.ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusOK {
		t.Fatalf("machines %d body %s", rec5.Code, rec5.Body.String())
	}

	// OIDC config (disabled)
	req6 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/config", nil)
	rec6 := httptest.NewRecorder()
	h.ServeHTTP(rec6, req6)
	if rec6.Code != http.StatusOK {
		t.Fatalf("oidc config %d", rec6.Code)
	}
	var oidc map[string]any
	if err := json.Unmarshal(rec6.Body.Bytes(), &oidc); err != nil {
		t.Fatal(err)
	}
	if oidc["enabled"] != false {
		t.Fatalf("oidc enabled = %v want false", oidc["enabled"])
	}

	// generate-config (public)
	req7 := httptest.NewRequest(http.MethodPost, "/api/v1/generate-config", bytes.NewReader([]byte(`{"config":{"network_name":"test"}}`)))
	req7.Header.Set("Content-Type", "application/json")
	rec7 := httptest.NewRecorder()
	h.ServeHTTP(rec7, req7)
	if rec7.Code != http.StatusOK {
		t.Fatalf("generate-config %d body %s", rec7.Code, rec7.Body.String())
	}

	// captcha
	req8 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/captcha", nil)
	rec8 := httptest.NewRecorder()
	h.ServeHTTP(rec8, req8)
	if rec8.Code != http.StatusOK {
		t.Fatalf("captcha %d", rec8.Code)
	}
	if ct := rec8.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("captcha content-type %q", ct)
	}
}

func TestWEB03_InternalToken(t *testing.T) {
	srv := New(Config{ListenAddr: "127.0.0.1:0", InternalAuthToken: "secret123"})
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/internal/sessions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("internal without token %d want 401", rec.Code)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/api/internal/sessions", nil)
	req2.Header.Set("X-Internal-Auth", "secret123")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("internal with token %d body %s", rec2.Code, rec2.Body.String())
	}
}

func TestWEB03_CaptchaAndRegistration(t *testing.T) {
	srv := New(Config{ListenAddr: "127.0.0.1:0"})
	h := srv.Handler()
	// get captcha
	reqCap := httptest.NewRequest(http.MethodGet, "/api/v1/auth/captcha", nil)
	recCap := httptest.NewRecorder()
	h.ServeHTTP(recCap, reqCap)
	if recCap.Code != http.StatusOK {
		t.Fatalf("captcha %d", recCap.Code)
	}
	cookies := recCap.Result().Cookies()
	var sid string
	for _, c := range cookies {
		if c.Name == "easytier_session" {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no captcha session")
	}
	// peek captcha from store
	captcha, ok := srv.store.captchas[sid]
	if !ok {
		t.Fatal("captcha not stored")
	}
	// register with correct captcha
	body, _ := json.Marshal(map[string]any{
		"credentials": map[string]string{"username": "newuser", "password": "5f4dcc3b5aa765d61d8327deb882cf99"},
		"captcha":     captcha,
	})
	reqReg := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	reqReg.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		reqReg.AddCookie(c)
	}
	recReg := httptest.NewRecorder()
	h.ServeHTTP(recReg, reqReg)
	if recReg.Code != http.StatusOK {
		t.Fatalf("register %d body %s", recReg.Code, recReg.Body.String())
	}
	// login as newuser
	body2, _ := json.Marshal(map[string]string{"username": "newuser", "password": "5f4dcc3b5aa765d61d8327deb882cf99"})
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body2))
	reqLogin.Header.Set("Content-Type", "application/json")
	recLogin := httptest.NewRecorder()
	h.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusOK {
		t.Fatalf("login newuser %d body %s", recLogin.Code, recLogin.Body.String())
	}
}

func TestWEB03_DisableRegistration(t *testing.T) {
	srv := New(Config{ListenAddr: "127.0.0.1:0", DisableRegistration: true})
	h := srv.Handler()
	reqCap := httptest.NewRequest(http.MethodGet, "/api/v1/auth/captcha", nil)
	recCap := httptest.NewRecorder()
	h.ServeHTTP(recCap, reqCap)
	cookies := recCap.Result().Cookies()
	body, _ := json.Marshal(map[string]any{
		"credentials": map[string]string{"username": "shouldfail", "password": "5f4dcc3b5aa765d61d8327deb882cf99"},
		"captcha":     "abcd",
	})
	reqReg := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	reqReg.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		reqReg.AddCookie(c)
	}
	recReg := httptest.NewRecorder()
	h.ServeHTTP(recReg, reqReg)
	if recReg.Code != http.StatusForbidden {
		t.Fatalf("register disabled status %d want 403", recReg.Code)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

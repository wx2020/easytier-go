// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/acl"
	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/credential"
	"github.com/EasyTier/EasyTier/go/internal/dns"
	"github.com/EasyTier/EasyTier/go/internal/management"
	"github.com/EasyTier/EasyTier/go/internal/route"
	"github.com/EasyTier/EasyTier/go/internal/stats"
)

func TestAPIAuthWhitelistAndMethods(t *testing.T) {
	service := management.NewService(management.NodeInfo{ID: "node-1"}, nil, nil)
	server, err := NewServer(service, Config{
		Token:     "test-token",
		Whitelist: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	for _, test := range []struct {
		name          string
		remoteAddr    string
		authorization string
		method        string
		path          string
		wantStatus    int
	}{
		{name: "missing auth", remoteAddr: "127.0.0.1:1", method: http.MethodGet, path: "/api/v1/node", wantStatus: http.StatusUnauthorized},
		{name: "wrong auth", remoteAddr: "127.0.0.1:1", authorization: "Bearer wrong", method: http.MethodGet, path: "/api/v1/node", wantStatus: http.StatusUnauthorized},
		{name: "denied source", remoteAddr: "192.0.2.1:1", authorization: "Bearer test-token", method: http.MethodGet, path: "/api/v1/node", wantStatus: http.StatusForbidden},
		{name: "wrong method", remoteAddr: "127.0.0.1:1", authorization: "Bearer test-token", method: http.MethodPost, path: "/api/v1/node", wantStatus: http.StatusMethodNotAllowed},
		{name: "unknown endpoint", remoteAddr: "127.0.0.1:1", authorization: "Bearer test-token", method: http.MethodGet, path: "/api/v1/unknown", wantStatus: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			request.RemoteAddr = test.remoteAddr
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.wantStatus, response.Body)
			}
			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("error response is not JSON: %v", err)
			}
			if body["error"] == "" {
				t.Fatalf("error response = %v", body)
			}
		})
	}
}

func TestAPIEndpointsUseManagementService(t *testing.T) {
	counters := stats.New()
	counters.Add("easytier_test_total", 2)
	service := management.NewService(management.NodeInfo{ID: "node-1", Name: "test", Version: "v1"}, counters, nil)
	server, err := NewServer(service, Config{Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodGet, path: "/api/v1/node"},
		{method: http.MethodGet, path: "/api/v1/stats"},
		{method: http.MethodGet, path: "/api/v1/logger"},
		{method: http.MethodGet, path: "/api/v1/instances"},
	} {
		request := httptest.NewRequest(test.method, test.path, nil)
		request.RemoteAddr = "127.0.0.1:1"
		request.Header.Set("Authorization", "Bearer test-token")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s %s status = %d, body = %s", test.method, test.path, response.Code, response.Body)
		}
		if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
			t.Fatalf("%s %s Content-Type = %q", test.method, test.path, contentType)
		}
	}

	request := httptest.NewRequest(http.MethodPut, "/api/v1/logger", bytes.NewBufferString(`{"level":"debug"}`))
	request.RemoteAddr = "127.0.0.1:1"
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.LoggerLevel() != management.LoggerLevelDebug {
		t.Fatalf("logger PUT status = %d, level = %q", response.Code, service.LoggerLevel())
	}
	request = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.RemoteAddr = "127.0.0.1:1"
	request.Header.Set("Authorization", "Bearer test-token")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || !bytes.Contains(response.Body.Bytes(), []byte("easytier_test_total 2")) {
		t.Fatalf("metrics response = status %d, type %q, body %q", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
}

func TestAPIRequestLimit(t *testing.T) {
	service := management.NewService(management.NodeInfo{}, nil, nil)
	server, err := NewServer(service, Config{Token: "test-token", MaxRequestBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/logger", bytes.NewBufferString(`{"level":"debug"}`))
	request.RemoteAddr = "127.0.0.1:1"
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusRequestEntityTooLarge, response.Body)
	}
}

func TestServerCloseStopsServe(t *testing.T) {
	service := management.NewService(management.NodeInfo{}, nil, nil)
	server, err := NewServer(service, Config{Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(context.Background()) }()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after Close")
	}
}

func TestNewServerValidation(t *testing.T) {
	service := management.NewService(management.NodeInfo{}, nil, nil)
	for _, test := range []struct {
		name   string
		config Config
	}{
		{name: "missing token"},
		{name: "negative limit", config: Config{Token: "token", MaxRequestBytes: -1}},
		{name: "invalid whitelist", config: Config{Token: "token", Whitelist: []netip.Prefix{{}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewServer(service, test.config); err == nil {
				t.Fatal("NewServer succeeded")
			}
		})
	}
}

func TestAPIRuntimeManagementEndpoints(t *testing.T) {
	cfg := config.Config{NetworkIdentity: config.NetworkIdentity{NetworkName: "web"}}
	routes := route.NewEngine(1)
	routes.AddLink(1, 2, 5)
	policy, err := acl.NewPolicy(acl.ActionDrop, nil)
	if err != nil {
		t.Fatal(err)
	}
	dnsServer, err := dns.NewServer(dns.Config{Address: "127.0.0.1:0", Zone: "web"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dnsServer.Close() })
	service := management.NewServiceWithOptions(management.ServiceOptions{
		NodeInfo: management.NodeInfo{ID: "node"}, Counters: stats.New(), Config: &cfg,
		Routes: routes, ACL: policy, Credentials: &credential.Manager{}, DNS: dnsServer,
	})
	server, err := NewServer(service, Config{Token: "token"})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		request.RemoteAddr = "127.0.0.1:1"
		request.Header.Set("Authorization", "Bearer token")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	for _, path := range []string{"/api/v1/config", "/api/v1/routes", "/api/v1/acl", "/api/v1/acl/stats", "/api/v1/credentials", "/api/v1/dns", "/api/v1/dns/status"} {
		response := call(http.MethodGet, path, "")
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, body = %s", path, response.Code, response.Body)
		}
	}
	if response := call(http.MethodPut, "/api/v1/dns", `{"name":"node.web","addresses":["10.0.0.2"]}`); response.Code != http.StatusOK {
		t.Fatalf("DNS PUT status = %d, body = %s", response.Code, response.Body)
	}
	if response := call(http.MethodGet, "/api/v1/dns", ""); !bytes.Contains(response.Body.Bytes(), []byte(`"node.web"`)) {
		t.Fatalf("DNS GET body = %s", response.Body)
	}
	if response := call(http.MethodGet, "/api/v1/peers", ""); response.Code != http.StatusNotImplemented {
		t.Fatalf("missing peer manager status = %d", response.Code)
	}
	for _, path := range []string{"/api/v1/vpn-portal", "/api/v1/proxy", "/api/v1/peer-center"} {
		if response := call(http.MethodGet, path, ""); response.Code != http.StatusOK {
			t.Fatalf("endpoint %s status = %d, want %d; body = %s", path, response.Code, http.StatusOK, response.Body)
		}
	}
}

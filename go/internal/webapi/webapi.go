// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package webapi exposes the management service over a versioned HTTP JSON API.
package webapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/forward"
	"github.com/EasyTier/EasyTier/go/internal/management"
)

const DefaultMaxRequestBytes int64 = 1 << 20

// Config controls access to a management HTTP server.
type Config struct {
	// Whitelist contains source CIDRs allowed to call the API. When empty, only
	// IPv4 and IPv6 loopback addresses are allowed.
	Whitelist []netip.Prefix
	// Token is required as a Bearer token in the Authorization header.
	Token string
	// MaxRequestBytes limits an HTTP request body. Zero uses the default limit.
	MaxRequestBytes int64
}

// Server serves a management service over HTTP.
type Server struct {
	mu        sync.Mutex
	listener  net.Listener
	closed    bool
	closeErr  error
	closeDone chan struct{}

	httpServer *http.Server
}

type configRequest struct {
	TOML   string         `json:"toml"`
	Config *config.Config `json:"config"`
}

type forwardJSONRequest struct {
	Rule forward.Rule `json:"rule"`
}

type credentialJSONRequest struct {
	ID           string   `json:"id"`
	Groups       []string `json:"groups"`
	RelayAllowed bool     `json:"relay_allowed"`
	ProxyCIDRs   []string `json:"proxy_cidrs"`
	TTLSeconds   int64    `json:"ttl_seconds"`
	Reusable     *bool    `json:"reusable"`
}

type idJSONRequest struct {
	ID string `json:"id"`
}

type dnsJSONRequest struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// NewServer creates an HTTP management server using service directly.
func NewServer(service *management.Service, config Config) (*Server, error) {
	if service == nil {
		return nil, fmt.Errorf("management service is nil")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("management API token must be supplied")
	}
	if config.MaxRequestBytes < 0 {
		return nil, fmt.Errorf("management API request limit must not be negative")
	}

	whitelist := config.Whitelist
	if len(whitelist) == 0 {
		whitelist = []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
		}
	}
	prefixes := make([]netip.Prefix, len(whitelist))
	for i, prefix := range whitelist {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("management API whitelist entry %d is invalid", i)
		}
		prefixes[i] = prefix.Masked()
	}
	maxRequestBytes := config.MaxRequestBytes
	if maxRequestBytes == 0 {
		maxRequestBytes = DefaultMaxRequestBytes
	}

	server := &Server{}
	server.httpServer = &http.Server{
		Handler: server.handler(service, prefixes, config.Token, maxRequestBytes),
	}
	return server, nil
}

// Handler returns the server's authenticated management handler.
func (s *Server) Handler() http.Handler {
	if s == nil || s.httpServer == nil {
		return http.NotFoundHandler()
	}
	return s.httpServer.Handler
}

// Listen binds the server to a TCP address. It may be called once.
func (s *Server) Listen(address string) error {
	if s == nil {
		return fmt.Errorf("management API server is nil")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen management API on %q: %w", address, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = listener.Close()
		return net.ErrClosed
	}
	if s.listener != nil {
		_ = listener.Close()
		return fmt.Errorf("management API server is already listening")
	}
	s.listener = listener
	return nil
}

// Addr returns the bound listener address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve accepts HTTP requests until ctx is canceled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("management API server is nil")
	}
	if ctx == nil {
		return fmt.Errorf("management API serve context is nil")
	}
	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()
	if listener == nil {
		return fmt.Errorf("management API server is not listening")
	}

	stopClose := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stopClose()
	err := s.httpServer.Serve(listener)
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) || s.isClosed() {
		return nil
	}
	return fmt.Errorf("serve management API: %w", err)
}

// Close gracefully stops the server and is idempotent.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		s.mu.Lock()
		err := s.closeErr
		s.mu.Unlock()
		return err
	}
	s.closed = true
	s.closeDone = make(chan struct{})
	done := s.closeDone
	listener := s.listener
	s.mu.Unlock()

	var err error
	if listener != nil {
		err = listener.Close()
	}
	if shutdownErr := s.httpServer.Shutdown(context.Background()); err == nil {
		err = shutdownErr
	}
	s.mu.Lock()
	s.closeErr = err
	close(done)
	s.mu.Unlock()
	return err
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) handler(service *management.Service, whitelist []netip.Prefix, token string, maxRequestBytes int64) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !allowedSource(request.RemoteAddr, whitelist) {
			writeError(writer, http.StatusForbidden, "source address is not allowed")
			return
		}
		if !authorized(request, token) {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="management"`)
			writeError(writer, http.StatusUnauthorized, "authentication required")
			return
		}
		if request.ContentLength > maxRequestBytes {
			writeError(writer, http.StatusRequestEntityTooLarge, "request body is too large")
			return
		}

		request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
		switch request.URL.Path {
		case "/metrics", "/api/v1/stats/prometheus":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			text, err := service.StatsPrometheus()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeText(writer, http.StatusOK, text)
		case "/api/v1/node":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Node management.NodeInfo `json:"node"`
			}{Node: service.NodeInfo()})
		case "/api/v1/stats":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			text, err := service.StatsPrometheus()
			if err != nil {
				writeError(writer, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Text string `json:"text"`
			}{Text: text})
		case "/api/v1/logger":
			switch request.Method {
			case http.MethodGet:
				writeJSON(writer, http.StatusOK, struct {
					Level management.LoggerLevel `json:"level"`
				}{Level: service.LoggerLevel()})
			case http.MethodPut:
				level, err := decodeLoggerLevel(request)
				if err != nil {
					writeRequestError(writer, err)
					return
				}
				if err := service.SetLoggerLevel(level); err != nil {
					writeError(writer, http.StatusBadRequest, err.Error())
					return
				}
				writeJSON(writer, http.StatusOK, struct {
					Level management.LoggerLevel `json:"level"`
				}{Level: level})
			default:
				methodNotAllowed(writer, http.MethodGet+", "+http.MethodPut)
			}
		case "/api/v1/instances":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Instances []management.InstanceInfo `json:"instances"`
			}{Instances: service.InstanceList()})
		case "/api/v1/instances/start":
			if request.Method != http.MethodPost {
				methodNotAllowed(writer, http.MethodPost)
				return
			}
			var body struct {
				Name string `json:"name"`
			}
			if err := decodeJSON(request, &body); err != nil {
				writeRequestError(writer, err)
				return
			}
			status, err := service.InstanceStart(request.Context(), body.Name)
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, status)
		case "/api/v1/instances/stop":
			if request.Method != http.MethodPost {
				methodNotAllowed(writer, http.MethodPost)
				return
			}
			var body struct {
				Name string `json:"name"`
			}
			if err := decodeJSON(request, &body); err != nil {
				writeRequestError(writer, err)
				return
			}
			if err := service.InstanceStop(body.Name); err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Stopped bool `json:"stopped"`
			}{Stopped: true})
		case "/api/v1/instances/status":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Instances []management.InstanceStatus `json:"instances"`
			}{Instances: service.InstanceStatuses()})
		case "/api/v1/stats/snapshot":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Metrics []management.StatsInfo `json:"metrics"`
			}{Metrics: service.StatsSnapshot()})
		case "/api/v1/config":
			switch request.Method {
			case http.MethodGet:
				value, err := service.ConfigGet()
				if err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusOK, value)
			case http.MethodPut:
				var body configRequest
				if err := decodeJSON(request, &body); err != nil {
					writeRequestError(writer, err)
					return
				}
				value, err := service.ConfigSet(request.Context(), body.TOML, body.Config)
				if err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusOK, value)
			default:
				methodNotAllowed(writer, http.MethodGet+", "+http.MethodPut)
			}
		case "/api/v1/peers":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			peers, err := service.PeerList()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Peers []management.PeerInfo `json:"peers"`
			}{Peers: peers})
		case "/api/v1/routes":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			routes, err := service.RouteList()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Routes any `json:"routes"`
			}{Routes: routes})
		case "/api/v1/connectors":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			connectors, err := service.ConnectorList()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Connectors []management.ConnectorInfo `json:"connectors"`
			}{Connectors: connectors})
		case "/api/v1/acl":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			aclInfo, err := service.ACLGet()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, aclInfo)
		case "/api/v1/acl/stats":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			aclStats, err := service.ACLStats()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, aclStats)
		case "/api/v1/port-forwards":
			switch request.Method {
			case http.MethodGet:
				rules, err := service.ForwardList()
				if err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusOK, struct {
					Rules []forward.Rule `json:"rules"`
				}{Rules: rules})
			case http.MethodPost:
				var body forwardJSONRequest
				if err := decodeJSON(request, &body); err != nil {
					writeRequestError(writer, err)
					return
				}
				if err := service.ForwardAdd(body.Rule); err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusCreated, struct {
					Rule forward.Rule `json:"rule"`
				}{Rule: body.Rule})
			case http.MethodDelete:
				var body forwardJSONRequest
				if err := decodeJSON(request, &body); err != nil {
					writeRequestError(writer, err)
					return
				}
				if err := service.ForwardRemove(body.Rule); err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusOK, struct {
					Removed bool `json:"removed"`
				}{Removed: true})
			default:
				methodNotAllowed(writer, http.MethodGet+", "+http.MethodPost+", "+http.MethodDelete)
			}
		case "/api/v1/port-forwards/status":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			forwards, err := service.ForwardStatusList()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Forwards []management.ForwardStatus `json:"forwards"`
			}{Forwards: forwards})
		case "/api/v1/credentials":
			switch request.Method {
			case http.MethodGet:
				credentials, err := service.CredentialList()
				if err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusOK, struct {
					Credentials []management.CredentialInfo `json:"credentials"`
				}{Credentials: credentials})
			case http.MethodPost:
				var body credentialJSONRequest
				if err := decodeJSON(request, &body); err != nil {
					writeRequestError(writer, err)
					return
				}
				value, err := service.CredentialGenerate(management.CredentialGenerateRequest{ID: body.ID, Groups: body.Groups, RelayAllowed: body.RelayAllowed, ProxyCIDRs: body.ProxyCIDRs, TTLSeconds: body.TTLSeconds, Reusable: body.Reusable})
				if err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusCreated, value)
			case http.MethodDelete:
				var body idJSONRequest
				if err := decodeJSON(request, &body); err != nil {
					writeRequestError(writer, err)
					return
				}
				if err := service.CredentialRevoke(body.ID); err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusOK, struct {
					Success bool `json:"success"`
				}{Success: true})
			default:
				methodNotAllowed(writer, http.MethodGet+", "+http.MethodPost+", "+http.MethodDelete)
			}
		case "/api/v1/dns/status":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			status, err := service.DNSStatus()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, status)
		case "/api/v1/dns":
			switch request.Method {
			case http.MethodGet:
				records, err := service.DNSList()
				if err != nil {
					writeManagementError(writer, err)
					return
				}
				status, err := service.DNSStatus()
				if err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusOK, struct {
					Zone    string                     `json:"zone"`
					Records []management.DNSRecordInfo `json:"records"`
					Status  management.DNSStatus       `json:"status"`
				}{Zone: service.DNSZone(), Records: records, Status: status})
			case http.MethodPut:
				var body dnsJSONRequest
				if err := decodeJSON(request, &body); err != nil {
					writeRequestError(writer, err)
					return
				}
				if err := service.DNSSet(body.Name, body.Addresses); err != nil {
					writeManagementError(writer, err)
					return
				}
				records, err := service.DNSList()
				if err != nil {
					writeManagementError(writer, err)
					return
				}
				var record management.DNSRecordInfo
				for _, item := range records {
					if item.Name == strings.TrimSuffix(strings.ToLower(body.Name), ".") {
						record = item
						break
					}
				}
				writeJSON(writer, http.StatusOK, struct {
					Record management.DNSRecordInfo `json:"record"`
				}{Record: record})
			case http.MethodDelete:
				var body dnsJSONRequest
				if err := decodeJSON(request, &body); err != nil {
					writeRequestError(writer, err)
					return
				}
				if err := service.DNSDelete(body.Name); err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusOK, struct {
					Removed bool `json:"removed"`
				}{Removed: true})
			default:
				methodNotAllowed(writer, http.MethodGet+", "+http.MethodPut+", "+http.MethodDelete)
			}
		case "/api/v1/mapped-listeners":
			switch request.Method {
			case http.MethodGet:
				listeners, err := service.MappedListenerList()
				if err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusOK, struct {
					Listeners []management.MappedListenerStatus `json:"mapped_listeners"`
				}{Listeners: listeners})
			case http.MethodPost:
				var body struct {
					URL string `json:"url"`
				}
				if err := decodeJSON(request, &body); err != nil {
					writeRequestError(writer, err)
					return
				}
				if err := service.MappedListenerAdd(body.URL); err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusCreated, struct {
					URL string `json:"url"`
				}{URL: body.URL})
			case http.MethodDelete:
				var body struct {
					URL string `json:"url"`
				}
				if err := decodeJSON(request, &body); err != nil {
					writeRequestError(writer, err)
					return
				}
				if err := service.MappedListenerRemove(body.URL); err != nil {
					writeManagementError(writer, err)
					return
				}
				writeJSON(writer, http.StatusOK, struct {
					Removed bool `json:"removed"`
				}{Removed: true})
			default:
				methodNotAllowed(writer, http.MethodGet+", "+http.MethodPost+", "+http.MethodDelete)
			}
		case "/api/v1/vpn-portal":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			info, err := service.VPNPortalInfo()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, info)
		case "/api/v1/proxy":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			proxyInfo, err := service.ProxyList()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, proxyInfo)
		case "/api/v1/peer-center":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			peerCenterInfo, err := service.PeerCenterInfo()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, peerCenterInfo)
		case "/api/v1/web/sessions":
			if request.Method != http.MethodGet {
				methodNotAllowed(writer, http.MethodGet)
				return
			}
			sessions, err := service.WebSessions()
			if err != nil {
				writeManagementError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, struct {
				Sessions any `json:"sessions"`
			}{Sessions: sessions})
		default:
			writeError(writer, http.StatusNotFound, "endpoint not found")
		}
	})
}

func allowedSource(remote string, whitelist []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	address = address.Unmap()
	for _, prefix := range whitelist {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func authorized(request *http.Request, token string) bool {
	const prefix = "Bearer "
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	provided := value[len(prefix):]
	return len(provided) == len(token) && subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

type loggerLevelRequest struct {
	Level management.LoggerLevel `json:"level"`
}

func decodeLoggerLevel(request *http.Request) (management.LoggerLevel, error) {
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body loggerLevelRequest
	if err := decoder.Decode(&body); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return "", err
		}
		return "", fmt.Errorf("invalid JSON request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return "", fmt.Errorf("invalid JSON request: multiple values")
		}
		return "", fmt.Errorf("invalid JSON request: %w", err)
	}
	if !body.Level.Valid() {
		return "", fmt.Errorf("invalid logger level %q", body.Level)
	}
	return body.Level, nil
}

func decodeJSON(request *http.Request, value any) error {
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("invalid JSON request: multiple values")
		}
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	return nil
}

func writeRequestError(writer http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeError(writer, http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}
	writeError(writer, http.StatusBadRequest, err.Error())
}

func writeManagementError(writer http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, management.ErrUnsupported) {
		status = http.StatusNotImplemented
	} else if errors.Is(err, net.ErrClosed) {
		status = http.StatusConflict
	}
	writeError(writer, status, err.Error())
}

func methodNotAllowed(writer http.ResponseWriter, allow string) {
	writer.Header().Set("Allow", allow)
	writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeText(writer http.ResponseWriter, status int, value string) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, value)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, struct {
		Error string `json:"error"`
	}{Error: message})
}

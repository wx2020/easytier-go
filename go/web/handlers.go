// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// buildHandler creates the HTTP mux with all routes.
func (s *Server) buildHandler() http.Handler {
	mux := http.NewServeMux()
	apiPrefix := "/api/" + s.cfg.WebAPIVersion
	if s.cfg.WebAPIVersion == "" {
		apiPrefix = "/api/" + APIVersion
	}

	// Public routes
	mux.HandleFunc("POST "+apiPrefix+"/auth/login", s.handleLogin)
	mux.HandleFunc("GET "+apiPrefix+"/auth/logout", s.handleLogout)
	mux.HandleFunc("GET "+apiPrefix+"/auth/captcha", s.handleGetCaptcha)
	mux.HandleFunc("POST "+apiPrefix+"/auth/register", s.handleRegister)
	mux.HandleFunc("GET "+apiPrefix+"/auth/oidc/config", s.handleOIDCConfig)
	mux.HandleFunc("GET "+apiPrefix+"/auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("GET "+apiPrefix+"/auth/oidc/callback", s.handleOIDCCallback)

	// Protected routes (require auth)
	mux.HandleFunc("PUT "+apiPrefix+"/auth/password", s.authRequired(s.handleChangePassword))
	mux.HandleFunc("GET "+apiPrefix+"/auth/check_login_status", s.authRequired(s.handleCheckLoginStatus))
	mux.HandleFunc("GET "+apiPrefix+"/sessions", s.authRequired(s.handleListSessions))
	mux.HandleFunc("GET "+apiPrefix+"/summary", s.authRequired(s.handleGetSummary))
	mux.HandleFunc("GET "+apiPrefix+"/machines", s.authRequired(s.handleListMachines))

	mux.HandleFunc("POST "+apiPrefix+"/machines/{machine_id}/validate-config", s.authRequired(s.handleValidateConfig))
	mux.HandleFunc("POST "+apiPrefix+"/machines/{machine_id}/networks", s.authRequired(s.handleRunNetwork))
	mux.HandleFunc("GET "+apiPrefix+"/machines/{machine_id}/networks", s.authRequired(s.handleListNetworks))

	mux.HandleFunc("DELETE "+apiPrefix+"/machines/{machine_id}/networks/{inst_id}", s.authRequired(s.handleRemoveNetwork))
	mux.HandleFunc("PUT "+apiPrefix+"/machines/{machine_id}/networks/{inst_id}", s.authRequired(s.handleUpdateNetworkState))
	mux.HandleFunc("GET "+apiPrefix+"/machines/{machine_id}/networks/info", s.authRequired(s.handleCollectNetworkInfo))
	mux.HandleFunc("GET "+apiPrefix+"/machines/{machine_id}/networks/info/{inst_id}", s.authRequired(s.handleCollectOneNetworkInfo))
	mux.HandleFunc("GET "+apiPrefix+"/machines/{machine_id}/networks/config/{inst_id}", s.authRequired(s.handleGetNetworkConfig))
	mux.HandleFunc("PUT "+apiPrefix+"/machines/{machine_id}/networks/config/{inst_id}", s.authRequired(s.handleSaveNetworkConfig))
	mux.HandleFunc("POST "+apiPrefix+"/machines/{machine_id}/networks/metas", s.authRequired(s.handleGetNetworkMetas))
	mux.HandleFunc("POST "+apiPrefix+"/machines/{machine_id}/proxy-rpc", s.authRequired(s.handleProxyRPC))

	// Open config helpers (public for frontend)
	mux.HandleFunc("POST "+apiPrefix+"/generate-config", s.handleGenerateConfig)
	mux.HandleFunc("POST "+apiPrefix+"/parse-config", s.handleParseConfig)

	// Versioned alias for compatibility if custom version != v1
	if apiPrefix != "/api/v1" {
		mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
		mux.HandleFunc("GET /api/v1/auth/logout", s.handleLogout)
		mux.HandleFunc("GET /api/v1/auth/captcha", s.handleGetCaptcha)
		mux.HandleFunc("POST /api/v1/auth/register", s.handleRegister)
	}

	// Internal token routes
	mux.HandleFunc("GET /api/internal/sessions", s.internalAuth(s.handleListSessionsInternal))
	mux.HandleFunc("DELETE /api/internal/users/{user_id}/sessions/{machine_id}", s.internalAuth(s.handleDisconnectSessionInternal))
	mux.HandleFunc("POST /api/internal/users/{user_id}/machines/{machine_id}/networks", s.internalAuth(s.handleRunNetworkInternal))
	mux.HandleFunc("GET /api/internal/users/{user_id}/machines/{machine_id}/networks", s.internalAuth(s.handleListNetworksInternal))
	mux.HandleFunc("DELETE /api/internal/users/{user_id}/machines/{machine_id}/networks/{inst_id}", s.internalAuth(s.handleRemoveNetworkInternal))
	mux.HandleFunc("GET /api/internal/users/{user_id}/machines/{machine_id}/networks/info", s.internalAuth(s.handleCollectNetworkInfoInternal))
	mux.HandleFunc("POST /api/internal/users/{user_id}/machines/{machine_id}/proxy-rpc", s.internalAuth(s.handleProxyRPCInternal))

	// WEB-04: versioned API meta and frontend static
	mux.HandleFunc("GET /api_meta.js", s.handleAPIMeta)
	mux.HandleFunc("GET /api/"+APIVersion+"/version", s.handleVersion)
	mux.HandleFunc("GET /api/"+APIVersion+"/health", s.handleHealth)

	// Frontend static (WEB-04): serve built Vue console if present
	frontendHandler := s.frontendHandler()

	// Fallback / health
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, http.StatusNotFound, "endpoint not found")
			return
		}
		if frontendHandler != nil {
			frontendHandler.ServeHTTP(w, r)
			return
		}
		// Serve placeholder frontend (WEB-04)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>EasyTier Web</title></head><body><h1>EasyTier Web Console (placeholder)</h1><p>API at /api/v1</p></body></html>`))
	})

	return corsMiddleware(mux)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Internal-Auth")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) getSessionID(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("easytier_session")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func (s *Server) getOrCreateSessionID(w http.ResponseWriter, r *http.Request) string {
	if sid, ok := s.getSessionID(r); ok {
		return sid
	}
	sid := generateSessionID()
	http.SetCookie(w, &http.Cookie{
		Name:     "easytier_session",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return sid
}

func (s *Server) getUserFromRequest(r *http.Request) (*userModel, bool) {
	sid, ok := s.getSessionID(r)
	if !ok {
		return nil, false
	}
	return s.store.getUserBySession(sid)
}

func (s *Server) authRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.InternalAuthToken != "" {
			if tok := r.Header.Get("X-Internal-Auth"); tok != "" && tok == s.cfg.InternalAuthToken {
				next(w, r)
				return
			}
		}
		if _, ok := s.getUserFromRequest(r); !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r)
	}
}

func (s *Server) internalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.InternalAuthToken == "" {
			writeError(w, http.StatusUnauthorized, "internal auth not configured")
			return
		}
		if tok := r.Header.Get("X-Internal-Auth"); tok != s.cfg.InternalAuthToken {
			writeError(w, http.StatusUnauthorized, "unauthorized: invalid or missing X-Internal-Auth header")
			return
		}
		next(w, r)
	}
}

// --- auth handlers ---

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type registerRequest struct {
	Credentials credentials `json:"credentials"`
	Captcha     string      `json:"captcha"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds credentials
	if err := decodeJSON(r, &creds); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if creds.Username == "" || creds.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password required")
		return
	}
	user, ok := s.store.authenticate(creds.Username, creds.Password)
	if !ok {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	sid := s.store.createSession(user.ID)
	http.SetCookie(w, &http.Cookie{
		Name:     "easytier_session",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sid, ok := s.getSessionID(r); ok {
		s.store.deleteSession(sid)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "easytier_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DisableRegistration {
		writeError(w, http.StatusForbidden, "Registration is disabled")
		return
	}
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sid, _ := s.getSessionID(r)
	if sid == "" {
		// try to get session from cookie without creating new
		writeError(w, http.StatusBadRequest, fmt.Sprintf("captcha verify error, input: %s", req.Captcha))
		return
	}
	if !s.store.verifyCaptcha(sid, req.Captcha) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("captcha verify error, input: %s", req.Captcha))
		return
	}
	if req.Credentials.Username == "" || req.Credentials.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password required")
		return
	}
	if _, err := s.store.createUser(req.Credentials.Username, req.Credentials.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := s.getUserFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "No such user")
		return
	}
	var body struct {
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "new_password required")
		return
	}
	if err := s.store.changePassword(user.ID, body.NewPassword); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sid, ok := s.getSessionID(r); ok {
		s.store.deleteSession(sid)
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleCheckLoginStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getUserFromRequest(r); !ok {
		writeError(w, http.StatusUnauthorized, "Not logged in")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleOIDCConfig(w http.ResponseWriter, r *http.Request) {
	enabled := s.cfg.OIDCIssuerURL != "" && s.cfg.OIDCClientID != ""
	writeJSON(w, http.StatusOK, map[string]any{"enabled": enabled})
}

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusBadRequest, "OIDC is not enabled")
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusBadRequest, "OIDC is not enabled")
}

// --- sessions / summary ---

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions := s.Sessions()
	// Return as tokens similar to Rust StorageToken
	// For minimal, return machine IDs
	type token struct {
		MachineID string `json:"machine_id"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Connected bool   `json:"connected"`
	}
	var out []token
	for _, sess := range sessions {
		out = append(out, token{
			MachineID: sess.MachineID,
			Name:      sess.Name,
			Version:   sess.Version,
			Connected: sess.Connected,
		})
	}
	if out == nil {
		out = []token{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListSessionsInternal(w http.ResponseWriter, r *http.Request) {
	s.handleListSessions(w, r)
}

func (s *Server) handleDisconnectSessionInternal(w http.ResponseWriter, r *http.Request) {
	// Stub: not implemented fully, return 404 or 204
	userIDStr := r.PathValue("user_id")
	machineID := r.PathValue("machine_id")
	_, _ = strconv.Atoi(userIDStr)
	_ = machineID
	writeError(w, http.StatusNotFound, "session not found")
}

func (s *Server) handleGetSummary(w http.ResponseWriter, r *http.Request) {
	// device_count = number of machines for user
	user, _ := s.getUserFromRequest(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "No such user")
		return
	}
	// Count sessions for demonstration: all connected sessions count as devices
	// In real Rust, it lists machines by user_id via storage; here we just count config sessions
	count := 0
	for _, sess := range s.Sessions() {
		if sess.Connected {
			count++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_count": count})
}

// --- machines ---

func (s *Server) handleListMachines(w http.ResponseWriter, r *http.Request) {
	// Return machines from config server sessions grouped by user? For now return all sessions
	// Each machine corresponds to a connected client; we don't have user-scoped storage yet
	// So return all
	type item struct {
		ClientURL interface{} `json:"client_url"`
		Info      interface{} `json:"info"`
		Location  interface{} `json:"location"`
	}
	sessions := s.Sessions()
	var machines []item
	for _, sess := range sessions {
		info := map[string]any{
			"machine_id": sess.MachineID,
			"hostname":   sess.Name,
			"version":    sess.Version,
		}
		loc := lookupLocation(s.cfg.GeoIPDB, sess.MachineID)
		machines = append(machines, item{ClientURL: nil, Info: info, Location: loc})
	}
	if machines == nil {
		machines = []item{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"machines": machines})
}

func lookupLocation(geoipDB, machineID string) map[string]any {
	// Stub GeoIP: if geoipDB path provided, try to use; else return local network for loopback, overseas otherwise
	// Since we don't have real IP, return fixed location.
	// This mimics client_manager lookup_location logic for private IPs.
	return map[string]any{"country": "本地网络", "city": nil, "region": nil}
}

// --- network ---

func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	machineID := r.PathValue("machine_id")
	_ = machineID
	var body struct {
		Config json.RawMessage `json:"config"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Stub validation: always ok
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleRunNetwork(w http.ResponseWriter, r *http.Request) {
	user, _ := s.getUserFromRequest(r)
	machineID := r.PathValue("machine_id")
	var body struct {
		Config json.RawMessage `json:"config"`
		Save   bool            `json:"save"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Extract instance_id from config if present
	instID := extractInstanceID(body.Config)
	if instID == "" {
		instID = machineID // fallback
	}
	s.store.upsertNetworkConfig(user.ID, machineID, instID, string(body.Config), "user")
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	user, _ := s.getUserFromRequest(r)
	machineID := r.PathValue("machine_id")
	configs := s.store.listNetworkConfigs(user.ID, machineID)
	var running []string
	var disabled []string
	for _, c := range configs {
		if c.Disabled {
			disabled = append(disabled, c.NetworkInstanceID)
		} else {
			running = append(running, c.NetworkInstanceID)
		}
	}
	if running == nil {
		running = []string{}
	}
	if disabled == nil {
		disabled = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"running_inst_ids":  running,
		"disabled_inst_ids": disabled,
	})
}

func (s *Server) handleRemoveNetwork(w http.ResponseWriter, r *http.Request) {
	user, _ := s.getUserFromRequest(r)
	machineID := r.PathValue("machine_id")
	instID := r.PathValue("inst_id")
	s.store.deleteNetworkConfigs(user.ID, machineID, []string{instID})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleUpdateNetworkState(w http.ResponseWriter, r *http.Request) {
	user, _ := s.getUserFromRequest(r)
	machineID := r.PathValue("machine_id")
	instID := r.PathValue("inst_id")
	var body struct {
		Disabled bool `json:"disabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if instID == "" {
		writeError(w, http.StatusNotImplemented, "Not implemented")
		return
	}
	if !s.store.setNetworkDisabled(user.ID, machineID, instID, body.Disabled) {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCollectNetworkInfo(w http.ResponseWriter, r *http.Request) {
	machineID := r.PathValue("machine_id")
	_ = machineID
	// Expect body with inst_ids
	var body struct {
		InstIDs *[]string `json:"inst_ids"`
	}
	_ = decodeJSON(r, &body)
	// Return empty map
	writeJSON(w, http.StatusOK, map[string]any{"info": map[string]any{}})
}

func (s *Server) handleCollectOneNetworkInfo(w http.ResponseWriter, r *http.Request) {
	// /info/{inst_id}
	writeJSON(w, http.StatusOK, map[string]any{"info": map[string]any{}})
}

func (s *Server) handleGetNetworkConfig(w http.ResponseWriter, r *http.Request) {
	user, _ := s.getUserFromRequest(r)
	machineID := r.PathValue("machine_id")
	instID := r.PathValue("inst_id")
	if m, ok := s.store.getNetworkConfig(user.ID, machineID, instID); ok {
		// Return stored JSON
		var cfg json.RawMessage = json.RawMessage(m.NetworkConfig)
		writeJSON(w, http.StatusOK, cfg)
		return
	}
	writeError(w, http.StatusNotFound, "network config not found")
}

func (s *Server) handleSaveNetworkConfig(w http.ResponseWriter, r *http.Request) {
	user, _ := s.getUserFromRequest(r)
	machineID := r.PathValue("machine_id")
	instID := r.PathValue("inst_id")
	var body struct {
		Config json.RawMessage `json:"config"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if extractInstanceID(body.Config) != "" && extractInstanceID(body.Config) != instID {
		writeError(w, http.StatusBadRequest, "Instance ID mismatch")
		return
	}
	s.store.upsertNetworkConfig(user.ID, machineID, instID, string(body.Config), "user")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetNetworkMetas(w http.ResponseWriter, r *http.Request) {
	// body: {"instance_ids": [...]}
	var body struct {
		InstanceIDs []string `json:"instance_ids"`
	}
	_ = decodeJSON(r, &body)
	writeJSON(w, http.StatusOK, map[string]any{"metas": []any{}})
}

func (s *Server) handleProxyRPC(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "proxy-rpc not implemented in Go stub")
}

// internal variants

func (s *Server) handleRunNetworkInternal(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.PathValue("user_id")
	machineID := r.PathValue("machine_id")
	uid, _ := strconv.Atoi(userIDStr)
	var body struct {
		Config json.RawMessage `json:"config"`
		Save   bool            `json:"save"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	instID := extractInstanceID(body.Config)
	if instID == "" {
		instID = machineID
	}
	s.store.upsertNetworkConfig(uid, machineID, instID, string(body.Config), "user")
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleListNetworksInternal(w http.ResponseWriter, r *http.Request) {
	uidStr := r.PathValue("user_id")
	machineID := r.PathValue("machine_id")
	uid, _ := strconv.Atoi(uidStr)
	configs := s.store.listNetworkConfigs(uid, machineID)
	var running []string
	var disabled []string
	for _, c := range configs {
		if c.Disabled {
			disabled = append(disabled, c.NetworkInstanceID)
		} else {
			running = append(running, c.NetworkInstanceID)
		}
	}
	if running == nil {
		running = []string{}
	}
	if disabled == nil {
		disabled = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"running_inst_ids":  running,
		"disabled_inst_ids": disabled,
	})
}

func (s *Server) handleRemoveNetworkInternal(w http.ResponseWriter, r *http.Request) {
	uidStr := r.PathValue("user_id")
	machineID := r.PathValue("machine_id")
	instID := r.PathValue("inst_id")
	uid, _ := strconv.Atoi(uidStr)
	s.store.deleteNetworkConfigs(uid, machineID, []string{instID})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCollectNetworkInfoInternal(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"info": map[string]any{}})
}

func (s *Server) handleProxyRPCInternal(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "proxy-rpc not implemented")
}

// --- generate / parse config ---

func (s *Server) handleGenerateConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config json.RawMessage `json:"config"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Stub: return empty toml
	writeJSON(w, http.StatusOK, map[string]any{"error": nil, "toml_config": ""})
}

func (s *Server) handleParseConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TomlConfig string `json:"toml_config"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Stub parse: return empty config
	writeJSON(w, http.StatusOK, map[string]any{"error": nil, "config": map[string]any{}})
}

// --- helpers ---

func extractInstanceID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	// Try instance_id or instanceId or network_name fallback
	for _, key := range []string{"instance_id", "instanceId", "instance_ID"} {
		if v, ok := m[key]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil {
				return s
			}
		}
	}
	// Also try nested
	return ""
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	// ensure single value
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid JSON request: multiple values")
		}
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"error":   msg,
		"message": msg,
	})
}

func (s *Server) handleAPIMeta(w http.ResponseWriter, r *http.Request) {
	apiHost := s.cfg.WebInstanceAPIBaseURL
	if apiHost == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		apiHost = fmt.Sprintf("%s://%s", scheme, r.Host)
		if r.Host == "" {
			apiHost = "http://localhost:11211"
		}
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	payload, _ := json.Marshal(map[string]string{"api_host": apiHost})
	_, _ = w.Write([]byte("window.apiMeta = " + string(payload)))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":     Version,
		"api_version": s.cfg.WebAPIVersion,
		"module":      ModuleName,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": Version})
}

func (s *Server) frontendHandler() http.Handler {
	candidates := []string{
		"easytier-web/frontend/dist",
		"../easytier-web/frontend/dist",
		"../../easytier-web/frontend/dist",
		"./dist",
	}
	// Also try relative to current binary's working dir
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(p)
			return http.FileServer(http.Dir(abs))
		}
	}
	// Try absolute project root via checking ENV or PWD
	if pwd, err := os.Getwd(); err == nil {
		for _, rel := range []string{"easytier-web/frontend/dist", "frontend/dist"} {
			joined := filepath.Join(pwd, rel)
			if info, err := os.Stat(joined); err == nil && info.IsDir() {
				return http.FileServer(http.Dir(joined))
			}
		}
	}
	return nil
}

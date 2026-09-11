// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package uptime

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Server implements HTTP API.
type Server struct {
	cfg       Config
	db        *DB
	scheduler *Scheduler
	handler   http.Handler
}

// NewServer creates Server with DB at cfg.DBPath.
func NewServer(cfg Config) (*Server, error) {
	if cfg.DBPath == "" {
		cfg.DBPath = DefaultConfig().DBPath
	}
	if cfg.Interval == 0 {
		cfg.Interval = DefaultConfig().Interval
	}
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = DefaultConfig().JWTSecret
	}
	if cfg.AdminPassword == "" {
		cfg.AdminPassword = DefaultConfig().AdminPassword
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultConfig().ListenAddr
	}
	if cfg.HealthCheckTimeout == 0 {
		cfg.HealthCheckTimeout = DefaultConfig().HealthCheckTimeout
	}
	db, err := NewDB(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	return NewServerWithDB(cfg, db)
}

// NewServerWithDB uses existing DB.
func NewServerWithDB(cfg Config, db *DB) (*Server, error) {
	if cfg.Interval == 0 {
		cfg.Interval = 30
	}
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = "default-jwt-secret"
	}
	if cfg.AdminPassword == "" {
		cfg.AdminPassword = "admin123"
	}
	sched := NewScheduler(db, time.Duration(cfg.Interval)*time.Second, time.Duration(cfg.HealthCheckTimeout)*time.Second, nil)
	sched.LoadFromDB()
	s := &Server{cfg: cfg, db: db, scheduler: sched}
	s.handler = s.buildHandler()
	return s, nil
}

// Handler returns http.Handler.
func (s *Server) Handler() http.Handler { return s.handler }

// DB returns DB.
func (s *Server) DB() *DB { return s.db }

// Scheduler returns scheduler.
func (s *Server) Scheduler() *Scheduler { return s.scheduler }

// Config returns config.
func (s *Server) Config() Config { return s.cfg }

// Start starts scheduler and optionally HTTP server (not needed for tests).
func (s *Server) Start() { s.scheduler.Start() }

// Stop stops scheduler.
func (s *Server) Stop() { s.scheduler.Stop() }

// Close releases.
func (s *Server) Close() error {
	s.scheduler.Stop()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Version compatibility.
func (s *Server) Version() string { return Version }

// Migrations returns migration SQL.
func (s *Server) Migrations() []string { return s.db.Migrations() }

// Build handler
func (s *Server) buildHandler() http.Handler {
	mux := http.NewServeMux()
	// public
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /api/nodes", s.handleGetNodes)
	mux.HandleFunc("POST /api/nodes", s.handleCreateNode)
	mux.HandleFunc("POST /api/test_connection", s.handleTestConnection)
	mux.HandleFunc("GET /api/nodes/{id}", s.handleGetNode)
	mux.HandleFunc("GET /api/nodes/{id}/health", s.handleGetNodeHealth)
	mux.HandleFunc("GET /api/nodes/{id}/health/stats", s.handleGetNodeHealthStats)
	mux.HandleFunc("GET /api/tags", s.handleGetAllTags)
	mux.HandleFunc("GET /node/{id}", s.handleGetNodeConnectURL)

	// admin
	mux.HandleFunc("POST /api/admin/login", s.handleAdminLogin)
	mux.HandleFunc("GET /api/admin/verify", s.handleAdminVerify)
	mux.HandleFunc("GET /api/admin/nodes", s.handleAdminGetNodes)
	mux.HandleFunc("PUT /api/admin/nodes/{id}/approve", s.handleAdminApprove)
	mux.HandleFunc("PUT /api/admin/nodes/{id}/revoke", s.handleAdminRevoke)
	mux.HandleFunc("PUT /api/admin/nodes/{id}", s.handleAdminUpdateNode)
	mux.HandleFunc("DELETE /api/admin/nodes/{id}", s.handleAdminDeleteNode)

	// fallback for frontend
	frontend := s.frontendHandler()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/health") || strings.HasPrefix(r.URL.Path, "/node/") {
			http.NotFound(w, r)
			return
		}
		if frontend != nil {
			frontend.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>EasyTier Uptime</title></head><body><h1>EasyTier Uptime (Go)</h1><p>API at /api/nodes</p></body></html>`))
	})
	return corsMiddleware(mux)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, err error) {
	if ae, ok := err.(*apiError); ok {
		code := ae.status
		msg := ae.msg
		// Rust returns {"error":{"code":...,"message":...}} via ApiError, but frontend expects ApiResponse success=false
		// We support both: send ApiResponse error for direct handlers, and error object for middleware.
		// For consistency with Rust error.rs, send {"error":{"code":..., "message":...}}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": code, "message": msg},
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"code": 500, "message": err.Error()},
	})
}

func parsePagination(r *http.Request) (page, perPage int) {
	q := r.URL.Query()
	page = 1
	perPage = 20
	if v := q.Get("page"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			page = i
		}
	}
	if v := q.Get("per_page"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			perPage = i
		}
	} else if v := q.Get("perPage"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			perPage = i
		}
	}
	return
}

func (s *Server) requireAdmin(r *http.Request) error {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		// also allow lowercase
		auth = r.Header.Get("authorization")
	}
	if auth == "" {
		return errUnauthorized("Missing authorization header")
	}
	if err := VerifyAdminToken(auth, s.cfg.JWTSecret); err != nil {
		return errUnauthorized("Invalid token: " + err.Error())
	}
	return nil
}

// Handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, ApiResponse[string]{Success: true, Message: strPtr("Service is healthy")})
}

func strPtr(s string) *string { return &s }

func (s *Server) handleGetNodes(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r)
	q := r.URL.Query()
	var isActive *bool
	if v := q.Get("is_active"); v != "" {
		b := v == "true" || v == "1"
		isActive = &b
	}
	var protocol *string
	if v := q.Get("protocol"); v != "" {
		protocol = &v
	}
	var search *string
	if v := q.Get("search"); v != "" {
		search = &v
	}
	tags := q["tags"]
	if len(tags) == 0 {
		// also support comma-separated?
		if v := q.Get("tag"); v != "" {
			tags = []string{v}
		}
	}
	var tagIDs []int
	if len(tags) > 0 {
		ids, err := s.db.FilterNodeIDsByTagsAny(tags)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		if len(ids) == 0 {
			writeJSON(w, 200, SuccessResponse(PaginatedResponse[NodeResponse]{Items: []NodeResponse{}, Total: 0, Page: page, PerPage: perPage, TotalPages: 0}))
			return
		}
		tagIDs = ids
	}
	nodes, total, err := s.db.ListNodesFiltered(true, isActive, protocol, search, tagIDs, page, perPage)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	// Map to responses
	items := make([]NodeResponse, 0, len(nodes))
	ids := make([]int, 0, len(nodes))
	for _, n := range nodes {
		items = append(items, nodeToResponse(n))
		ids = append(ids, n.ID)
	}
	tagsMap, _ := s.db.GetNodesTagsMap(ids)
	for i := range items {
		if t, ok := tagsMap[items[i].ID]; ok {
			items[i].Tags = t
		} else {
			items[i].Tags = []string{}
		}
		// Health enrichment
		if rec := s.scheduler.GetNodeMemoryRecord(items[i].ID); rec != nil {
			status := string(rec.CurrentHealthStatus)
			items[i].CurrentHealthStatus = &status
			t := rec.LastCheckTime
			items[i].LastCheckTime = &t
			items[i].LastResponseTime = rec.LastResponseTime
			if stats := rec.GetHealthStats(24); stats != nil {
				items[i].HealthPercentage24h = &stats.HealthPercentage
			}
			tot, healthy := rec.GetCounterRing()
			items[i].HealthRecordTotalCounterRing = tot
			items[i].HealthRecordHealthyCounterRing = healthy
			items[i].RingGranularity = rec.GetRingGranularity()
		}
		// Hide sensitive as Rust does
		items[i].NetworkName = nil
		items[i].NetworkSecret = nil
		// Round current_connections to percentage
		if items[i].MaxConnections != 0 {
			items[i].CurrentConnections = int(float64(items[i].CurrentConnections) / float64(items[i].MaxConnections) * 100)
			items[i].MaxConnections = 100
		} else {
			items[i].CurrentConnections = 0
			items[i].MaxConnections = 0
		}
		items[i].QQNumber = nil
		items[i].Wechat = nil
		items[i].Mail = nil
	}
	totalPages := int((total + int64(perPage) - 1) / int64(perPage))
	if totalPages < 0 {
		totalPages = 0
	}
	writeJSON(w, 200, SuccessResponse(PaginatedResponse[NodeResponse]{Items: items, Total: total, Page: page, PerPage: perPage, TotalPages: totalPages}))
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var req CreateNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, errBadRequest("invalid JSON: "+err.Error()))
		return
	}
	if err := req.Validate(); err != nil {
		writeAPIError(w, err)
		return
	}
	if exists, err := s.db.NodeExists(req.Host, req.Port, req.Protocol); err != nil {
		writeAPIError(w, err)
		return
	} else if exists {
		writeAPIError(w, errBadRequest("node with host/port/protocol already exists"))
		return
	}
	node, err := s.db.CreateNode(req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	resp := nodeToResponse(node)
	resp.Tags = []string{}
	writeJSON(w, 200, SuccessResponse(resp))
}

func (s *Server) handleTestConnection(w http.ResponseWriter, r *http.Request) {
	var req CreateNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, errBadRequest("invalid JSON"))
		return
	}
	// Create temporary node model (not persisted)
	tmp := &SharedNode{
		Host: req.Host, Port: req.Port, Protocol: req.Protocol,
		NetworkName: req.NetworkName,
	}
	if req.NetworkSecret != nil {
		tmp.NetworkSecret = *req.NetworkSecret
	}
	if err := s.scheduler.TestConnection(tmp, 5*time.Second); err != nil {
		writeAPIError(w, err)
		return
	}
	// Return success with temporary response
	resp := nodeToResponse(&SharedNode{ID: 0, Name: req.Name, Host: req.Host, Port: req.Port, Protocol: req.Protocol})
	writeJSON(w, 200, SuccessResponse(resp))
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeAPIError(w, errBadRequest("invalid id"))
		return
	}
	node, err := s.db.GetNodeByID(id)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if node == nil {
		writeAPIError(w, errNotFound("Node not found"))
		return
	}
	resp := nodeToResponse(node)
	tags, _ := s.db.GetNodeTags(id)
	resp.Tags = tags
	writeJSON(w, 200, SuccessResponse(resp))
}

func (s *Server) handleGetNodeHealth(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	nodeID, err := strconv.Atoi(idStr)
	if err != nil {
		writeAPIError(w, errBadRequest("invalid id"))
		return
	}
	page, perPage := parsePagination(r)
	q := r.URL.Query()
	var statusFilter *string
	if v := q.Get("status"); v != "" {
		statusFilter = &v
	}
	var since *time.Time
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = &t
		} else if t, err := time.Parse("2006-01-02T15:04:05", v); err == nil {
			since = &t
		}
	}
	// Also support ?hours param? Rust doesn't but we handle limit
	records, total, err := s.db.GetNodeHealthRecords(nodeID, since, &perPage, statusFilter)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	// Pagination: we fetched limit but need offset
	// GetNodeHealthRecords currently applies LIMIT but not OFFSET; we implement offset manually by re-query with offset?
	// Instead fetch all and slice: simpler to re-implement with offset logic.
	// For now, handle pagination correctly: do offset via query.
	offset := (page - 1) * perPage
	// Re-query with offset if needed
	if offset > 0 || true {
		// manual offset: we need to redo query with offset. Instead fetch with offset via raw SQL.
		// Fallback: if records length == perPage and offset>0, we missed offset. Let's query properly.
		// Build query manually for offset case.
		q2 := `SELECT id, node_id, status, response_time, error_message, checked_at FROM health_records WHERE node_id = ?`
		args := []any{nodeID}
		if since != nil {
			q2 += ` AND checked_at >= ?`
			args = append(args, *since)
		}
		if statusFilter != nil {
			q2 += ` AND status = ?`
			args = append(args, *statusFilter)
		}
		q2 += ` ORDER BY checked_at DESC LIMIT ? OFFSET ?`
		args = append(args, perPage, offset)
		rows, err2 := s.db.sqlDB.Query(q2, args...)
		if err2 == nil {
			defer rows.Close()
			var out []*HealthRecord
			for rows.Next() {
				var rec HealthRecord
				var rt sqlNullInt
				var em sqlNullString
				var checked sqlNullTime
				var status string
				_ = rows.Scan(&rec.ID, &rec.NodeID, &status, &rt, &em, &checked)
				rec.Status = status
				if rt.Valid {
					rec.ResponseTime = int(rt.Int64)
				}
				if em.Valid {
					rec.ErrorMessage = em.String
				}
				if checked.Valid {
					rec.CheckedAt = checked.Time.UTC()
				}
				out = append(out, &rec)
			}
			records = out
		}
	}
	items := make([]HealthRecordResponse, 0, len(records))
	for _, rec := range records {
		items = append(items, recordToResponse(rec))
	}
	totalPages := int((total + int64(perPage) - 1) / int64(perPage))
	writeJSON(w, 200, SuccessResponse(PaginatedResponse[HealthRecordResponse]{Items: items, Total: total, Page: page, PerPage: perPage, TotalPages: totalPages}))
}

// helper sql null types for manual query above
type sqlNullInt struct {
	Int64 int64
	Valid bool
}

func (n *sqlNullInt) Scan(value any) error {
	if value == nil {
		n.Valid = false
		return nil
	}
	switch v := value.(type) {
	case int64:
		n.Int64 = v
		n.Valid = true
	case int:
		n.Int64 = int64(v)
		n.Valid = true
	case float64:
		n.Int64 = int64(v)
		n.Valid = true
	default:
		n.Valid = false
	}
	return nil
}

type sqlNullString struct {
	String string
	Valid  bool
}

func (n *sqlNullString) Scan(value any) error {
	if value == nil {
		n.Valid = false
		return nil
	}
	if s, ok := value.(string); ok {
		n.String = s
		n.Valid = true
	} else if b, ok := value.([]byte); ok {
		n.String = string(b)
		n.Valid = true
	}
	return nil
}

type sqlNullTime struct {
	Time  time.Time
	Valid bool
}

func (n *sqlNullTime) Scan(value any) error {
	if value == nil {
		n.Valid = false
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		n.Time = v
		n.Valid = true
	case string:
		// try parse
		if t, err := time.Parse("2006-01-02 15:04:05", v); err == nil {
			n.Time = t
			n.Valid = true
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			n.Time = t
			n.Valid = true
		}
	case []byte:
		s := string(v)
		if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
			n.Time = t
			n.Valid = true
		} else if t, err := time.Parse(time.RFC3339, s); err == nil {
			n.Time = t
			n.Valid = true
		}
	}
	return nil
}

func (s *Server) handleGetNodeHealthStats(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	nodeID, err := strconv.Atoi(idStr)
	if err != nil {
		writeAPIError(w, errBadRequest("invalid id"))
		return
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			hours = i
		}
	}
	stats, err := s.db.GetHealthStats(nodeID, hours)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, 200, SuccessResponse(*stats))
}

func (s *Server) handleGetAllTags(w http.ResponseWriter, r *http.Request) {
	tags, err := s.db.GetAllTags()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, 200, SuccessResponse(tags))
}

func (s *Server) handleGetNodeConnectURL(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeAPIError(w, errBadRequest("invalid id"))
		return
	}
	node, err := s.db.GetNodeByID(id)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if node == nil {
		writeAPIError(w, errNotFound("Node not found"))
		return
	}
	url := node.Protocol + "://" + node.Host + ":" + formatInt(node.Port)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(url))
}

// Admin handlers

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req AdminLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, errBadRequest("invalid JSON"))
		return
	}
	if req.Password != s.cfg.AdminPassword {
		writeAPIError(w, errUnauthorized("Invalid password"))
		return
	}
	exp := time.Now().Add(24 * time.Hour)
	token, err := GenerateAdminToken(s.cfg.JWTSecret, exp)
	if err != nil {
		writeAPIError(w, errInternal("Token generation failed"))
		return
	}
	writeJSON(w, 200, SuccessResponse(AdminLoginResponse{Token: token, ExpiresAt: exp}))
}

func (s *Server) handleAdminVerify(w http.ResponseWriter, r *http.Request) {
	if err := s.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, 200, ApiResponse[string]{Success: true, Message: strPtr("Token is valid")})
}

func (s *Server) handleAdminGetNodes(w http.ResponseWriter, r *http.Request) {
	if err := s.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	page, perPage := parsePagination(r)
	if perPage == 20 {
		// admin default is 200 per Rust
		if r.URL.Query().Get("per_page") == "" && r.URL.Query().Get("perPage") == "" {
			perPage = 200
		}
	}
	q := r.URL.Query()
	var isActive, isApproved *bool
	if v := q.Get("is_active"); v != "" {
		b := v == "true" || v == "1"
		isActive = &b
	}
	if v := q.Get("is_approved"); v != "" {
		b := v == "true" || v == "1"
		isApproved = &b
	}
	var protocol *string
	if v := q.Get("protocol"); v != "" {
		protocol = &v
	}
	var search *string
	if v := q.Get("search"); v != "" {
		search = &v
	}
	tags := []string{}
	if v := q.Get("tag"); v != "" {
		tags = append(tags, v)
	}
	tags = append(tags, q["tags"]...)
	// also handle tags as comma separated?
	var tagIDs []int
	if len(tags) > 0 {
		ids, err := s.db.FilterNodeIDsByTagsAny(tags)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		if len(ids) == 0 {
			writeJSON(w, 200, SuccessResponse(PaginatedResponse[NodeResponse]{Items: []NodeResponse{}, Total: 0, Page: page, PerPage: perPage, TotalPages: 0}))
			return
		}
		tagIDs = ids
	}
	nodes, total, err := s.db.ListAdminNodes(isActive, isApproved, protocol, search, tagIDs, page, perPage)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	items := make([]NodeResponse, 0, len(nodes))
	ids := []int{}
	for _, n := range nodes {
		items = append(items, nodeToResponse(n))
		ids = append(ids, n.ID)
	}
	tagsMap, _ := s.db.GetNodesTagsMap(ids)
	for i := range items {
		if t, ok := tagsMap[items[i].ID]; ok {
			items[i].Tags = t
		} else {
			items[i].Tags = []string{}
		}
	}
	totalPages := int((total + int64(perPage) - 1) / int64(perPage))
	writeJSON(w, 200, SuccessResponse(PaginatedResponse[NodeResponse]{Items: items, Total: total, Page: page, PerPage: perPage, TotalPages: totalPages}))
}

func (s *Server) handleAdminApprove(w http.ResponseWriter, r *http.Request) {
	if err := s.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	idStr := r.PathValue("id")
	id, _ := strconv.Atoi(idStr)
	node, err := s.db.ApproveNode(id, true)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if node == nil {
		writeAPIError(w, errNotFound("Node not found"))
		return
	}
	resp := nodeToResponse(node)
	tags, _ := s.db.GetNodeTags(id)
	resp.Tags = tags
	writeJSON(w, 200, SuccessResponse(resp))
}

func (s *Server) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if err := s.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	idStr := r.PathValue("id")
	id, _ := strconv.Atoi(idStr)
	node, err := s.db.ApproveNode(id, false)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if node == nil {
		writeAPIError(w, errNotFound("Node not found"))
		return
	}
	resp := nodeToResponse(node)
	tags, _ := s.db.GetNodeTags(id)
	resp.Tags = tags
	writeJSON(w, 200, SuccessResponse(resp))
}

func (s *Server) handleAdminUpdateNode(w http.ResponseWriter, r *http.Request) {
	if err := s.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	idStr := r.PathValue("id")
	id, _ := strconv.Atoi(idStr)
	var req UpdateNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, errBadRequest("invalid JSON"))
		return
	}
	node, err := s.db.UpdateNode(id, req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if node == nil {
		writeAPIError(w, errNotFound("Node not found"))
		return
	}
	resp := nodeToResponse(node)
	tags, _ := s.db.GetNodeTags(id)
	resp.Tags = tags
	writeJSON(w, 200, SuccessResponse(resp))
}

func (s *Server) handleAdminDeleteNode(w http.ResponseWriter, r *http.Request) {
	if err := s.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	idStr := r.PathValue("id")
	id, _ := strconv.Atoi(idStr)
	_, err := s.db.DeleteNode(id)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, 200, ApiResponse[string]{Success: true, Message: strPtr("Node deleted successfully")})
}

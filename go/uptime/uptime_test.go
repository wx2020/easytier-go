// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package uptime

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVersion(t *testing.T) {
	if Version == "" {
		t.Fatal("Version empty")
	}
	mon := New(Config{DBPath: ":memory:"})
	if mon.Version() != Version {
		t.Fatalf("Version mismatch")
	}
	_ = mon.Close()
	srv, err := NewServer(Config{DBPath: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if srv.Version() != Version {
		t.Fatal("server version mismatch")
	}
}

func TestMigrations(t *testing.T) {
	srv, err := NewServer(Config{DBPath: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if len(srv.Migrations()) != len(migrations) {
		t.Fatalf("migrations count %d want %d", len(srv.Migrations()), len(migrations))
	}
	stats, err := srv.DB().GetDatabaseStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalNodes != 0 {
		t.Fatalf("total nodes %d want 0", stats.TotalNodes)
	}
}

func TestNodeCRUDAndApproval(t *testing.T) {
	srv, err := NewServer(Config{DBPath: ":memory:", AdminPassword: "testpass", JWTSecret: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	h := srv.Handler()

	// Create node (pending approval)
	createReq := CreateNodeRequest{
		Name: "Test Node", Host: "127.0.0.1", Port: 11010, Protocol: "tcp",
		MaxConnections: 100, AllowRelay: false, NetworkName: "test-net",
		QQNumber: testStrPtr("123456"),
	}
	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("create status %d body %s", rec.Code, rec.Body.String())
	}
	var resp ApiResponse[NodeResponse]
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data == nil {
		t.Fatal("no data")
	}
	id := resp.Data.ID

	// Public list should be empty (not approved)
	req2 := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("list status %d", rec2.Code)
	}
	var listResp ApiResponse[PaginatedResponse[NodeResponse]]
	if err := json.Unmarshal(rec2.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	if listResp.Data == nil || listResp.Data.Total != 0 {
		t.Fatalf("expected 0 approved nodes, got %+v", listResp.Data)
	}

	// Admin login
	loginBody, _ := json.Marshal(map[string]string{"password": "testpass"})
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	recLogin := httptest.NewRecorder()
	h.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != 200 {
		t.Fatalf("login status %d body %s", recLogin.Code, recLogin.Body.String())
	}
	var loginResp ApiResponse[AdminLoginResponse]
	if err := json.Unmarshal(recLogin.Body.Bytes(), &loginResp); err != nil {
		t.Fatal(err)
	}
	if loginResp.Data == nil || loginResp.Data.Token == "" {
		t.Fatal("no token")
	}
	token := loginResp.Data.Token

	// Admin list should see pending
	reqAdmin := httptest.NewRequest(http.MethodGet, "/api/admin/nodes", nil)
	reqAdmin.Header.Set("Authorization", "Bearer "+token)
	recAdmin := httptest.NewRecorder()
	h.ServeHTTP(recAdmin, reqAdmin)
	if recAdmin.Code != 200 {
		t.Fatalf("admin list %d body %s", recAdmin.Code, recAdmin.Body.String())
	}
	var adminList ApiResponse[PaginatedResponse[NodeResponse]]
	if err := json.Unmarshal(recAdmin.Body.Bytes(), &adminList); err != nil {
		t.Fatal(err)
	}
	if adminList.Data.Total != 1 {
		t.Fatalf("admin list total %d want 1", adminList.Data.Total)
	}

	// Approve
	reqApprove := httptest.NewRequest(http.MethodPut, "/api/admin/nodes/"+formatInt(id)+"/approve", nil)
	reqApprove.Header.Set("Authorization", "Bearer "+token)
	recApprove := httptest.NewRecorder()
	h.ServeHTTP(recApprove, reqApprove)
	if recApprove.Code != 200 {
		t.Fatalf("approve %d body %s", recApprove.Code, recApprove.Body.String())
	}

	// Public list should now have 1
	req2b := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	rec2b := httptest.NewRecorder()
	h.ServeHTTP(rec2b, req2b)
	var listResp2 ApiResponse[PaginatedResponse[NodeResponse]]
	_ = json.Unmarshal(rec2b.Body.Bytes(), &listResp2)
	if listResp2.Data.Total != 1 {
		t.Fatalf("after approve total %d want 1", listResp2.Data.Total)
	}

	// Get node by id
	reqGet := httptest.NewRequest(http.MethodGet, "/api/nodes/"+formatInt(id), nil)
	recGet := httptest.NewRecorder()
	h.ServeHTTP(recGet, reqGet)
	if recGet.Code != 200 {
		t.Fatalf("get node %d", recGet.Code)
	}
}

func TestHealthHistoryAPI(t *testing.T) {
	srv, err := NewServer(Config{DBPath: ":memory:", AdminPassword: "admin123", JWTSecret: "default-jwt-secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	h := srv.Handler()

	// Create and approve node
	createReq := CreateNodeRequest{Name: "HN", Host: "127.0.0.1", Port: 22000, Protocol: "tcp", MaxConnections: 100, NetworkName: "net", QQNumber: testStrPtr("111")}
	body, _ := json.Marshal(createReq)
	req := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var cr ApiResponse[NodeResponse]
	_ = json.Unmarshal(rec.Body.Bytes(), &cr)
	id := cr.Data.ID

	// approve
	loginBody, _ := json.Marshal(map[string]string{"password": "admin123"})
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	recLogin := httptest.NewRecorder()
	h.ServeHTTP(recLogin, reqLogin)
	var lr ApiResponse[AdminLoginResponse]
	_ = json.Unmarshal(recLogin.Body.Bytes(), &lr)
	token := lr.Data.Token
	reqApp := httptest.NewRequest(http.MethodPut, "/api/admin/nodes/"+formatInt(id)+"/approve", nil)
	reqApp.Header.Set("Authorization", "Bearer "+token)
	recApp := httptest.NewRecorder()
	h.ServeHTTP(recApp, reqApp)

	// Insert health records directly via DB
	for i := 0; i < 5; i++ {
		status := HealthHealthy
		rt := 100 + i*10
		if i == 2 {
			status = HealthUnhealthy
		}
		_, _ = srv.DB().CreateHealthRecord(id, status, &rt, nil)
		time.Sleep(5 * time.Millisecond)
	}

	// Get health history
	reqHealth := httptest.NewRequest(http.MethodGet, "/api/nodes/"+formatInt(id)+"/health?page=1&per_page=10", nil)
	recHealth := httptest.NewRecorder()
	h.ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != 200 {
		t.Fatalf("health history %d body %s", recHealth.Code, recHealth.Body.String())
	}
	var hr ApiResponse[PaginatedResponse[HealthRecordResponse]]
	if err := json.Unmarshal(recHealth.Body.Bytes(), &hr); err != nil {
		t.Fatal(err)
	}
	if hr.Data.Total != 5 {
		t.Fatalf("total health %d want 5", hr.Data.Total)
	}
	if len(hr.Data.Items) != 5 {
		t.Fatalf("items %d want 5", len(hr.Data.Items))
	}

	// Get stats
	reqStats := httptest.NewRequest(http.MethodGet, "/api/nodes/"+formatInt(id)+"/health/stats?hours=24", nil)
	recStats := httptest.NewRecorder()
	h.ServeHTTP(recStats, reqStats)
	if recStats.Code != 200 {
		t.Fatalf("stats %d body %s", recStats.Code, recStats.Body.String())
	}
	var sr ApiResponse[HealthStats]
	if err := json.Unmarshal(recStats.Body.Bytes(), &sr); err != nil {
		t.Fatal(err)
	}
	if sr.Data == nil {
		t.Fatal("no stats")
	}
	if sr.Data.TotalChecks != 5 {
		t.Fatalf("stats total %d want 5", sr.Data.TotalChecks)
	}
	if sr.Data.HealthyCount != 4 {
		t.Fatalf("healthy %d want 4", sr.Data.HealthyCount)
	}
}

func TestScheduler(t *testing.T) {
	// Scheduler uses TCP dial; create node with unreachable port should be unhealthy, reachable should be healthy
	// Start a dummy TCP listener
	ln, err := newTestListener()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	srv, err := NewServer(Config{DBPath: ":memory:", Interval: 1, HealthCheckTimeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	// create node pointing to dummy listener
	createReq := CreateNodeRequest{Name: "Sched", Host: "127.0.0.1", Port: port, Protocol: "tcp", MaxConnections: 100, NetworkName: "net", QQNumber: testStrPtr("123")}
	body, _ := json.Marshal(createReq)
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var cr ApiResponse[NodeResponse]
	_ = json.Unmarshal(rec.Body.Bytes(), &cr)
	id := cr.Data.ID

	// Run scheduler once
	_ = srv.Scheduler().CheckOnce(nil)
	// Check health record created
	records, total, err := srv.DB().GetNodeHealthRecords(id, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 {
		t.Fatal("no health records after scheduler")
	}
	_ = records
	_ = total
	// Verify DB stats
	stats, _ := srv.DB().GetDatabaseStats()
	if stats.TotalHealthRecords == 0 {
		t.Fatal("no health records in stats")
	}
}

func TestTags(t *testing.T) {
	srv, _ := NewServer(Config{DBPath: ":memory:", AdminPassword: "admin123"})
	defer srv.Close()
	h := srv.Handler()
	// Create node
	reqBody, _ := json.Marshal(CreateNodeRequest{Name: "TagNode", Host: "10.0.0.1", Port: 1000, Protocol: "tcp", MaxConnections: 100, NetworkName: "net", QQNumber: testStrPtr("1")})
	req := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var cr ApiResponse[NodeResponse]
	_ = json.Unmarshal(rec.Body.Bytes(), &cr)
	id := cr.Data.ID

	// Approve
	loginBody, _ := json.Marshal(map[string]string{"password": "admin123"})
	rl := httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewReader(loginBody))
	rl.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, rl)
	var lr ApiResponse[AdminLoginResponse]
	_ = json.Unmarshal(rr.Body.Bytes(), &lr)
	token := lr.Data.Token

	// Approve node first
	approveReq := httptest.NewRequest(http.MethodPut, "/api/admin/nodes/"+formatInt(id)+"/approve", nil)
	approveReq.Header.Set("Authorization", "Bearer "+token)
	approveRec := httptest.NewRecorder()
	h.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != 200 {
		t.Fatalf("approve %d body %s", approveRec.Code, approveRec.Body.String())
	}

	// Update tags via admin
	tags := []string{"prod", "east"}
	updateBody, _ := json.Marshal(UpdateNodeRequest{Tags: &tags})
	updReq := httptest.NewRequest(http.MethodPut, "/api/admin/nodes/"+formatInt(id), bytes.NewReader(updateBody))
	updReq.Header.Set("Content-Type", "application/json")
	updReq.Header.Set("Authorization", "Bearer "+token)
	updRec := httptest.NewRecorder()
	h.ServeHTTP(updRec, updReq)
	if updRec.Code != 200 {
		t.Fatalf("update tags %d body %s", updRec.Code, updRec.Body.String())
	}

	// Get all tags
	reqTags := httptest.NewRequest(http.MethodGet, "/api/tags", nil)
	recTags := httptest.NewRecorder()
	h.ServeHTTP(recTags, reqTags)
	var tr ApiResponse[[]string]
	_ = json.Unmarshal(recTags.Body.Bytes(), &tr)
	if tr.Data == nil || len(*tr.Data) == 0 {
		t.Fatal("no tags")
	}

	// Filter by tag
	reqFilter := httptest.NewRequest(http.MethodGet, "/api/nodes?tags=prod", nil)
	recFilter := httptest.NewRecorder()
	h.ServeHTTP(recFilter, reqFilter)
	var fr ApiResponse[PaginatedResponse[NodeResponse]]
	_ = json.Unmarshal(recFilter.Body.Bytes(), &fr)
	if fr.Data.Total != 1 {
		t.Fatalf("filter total %d want 1", fr.Data.Total)
	}
}

// helpers

func testStrPtr(s string) *string { return &s }

func newTestListener() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

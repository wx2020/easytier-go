// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package uptime

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// migrations mirrors Rust m20250101_000001_create_tables and m20250101_000002_create_node_tags.
var migrations = []string{
	// 001 shared_nodes + health_records
	`CREATE TABLE IF NOT EXISTS shared_nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL DEFAULT 'tcp',
		version TEXT,
		allow_relay BOOLEAN DEFAULT 0,
		network_name TEXT,
		network_secret TEXT,
		description TEXT,
		max_connections INTEGER DEFAULT 100,
		current_connections INTEGER DEFAULT 0,
		is_active BOOLEAN DEFAULT 1,
		is_approved BOOLEAN DEFAULT 0,
		qq_number TEXT,
		wechat TEXT,
		mail TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_shared_nodes_host_port_protocol ON shared_nodes(host, port, protocol);`,
	`CREATE TABLE IF NOT EXISTS health_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id INTEGER NOT NULL,
		status TEXT NOT NULL,
		response_time INTEGER,
		error_message TEXT,
		checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(node_id) REFERENCES shared_nodes(id) ON DELETE CASCADE ON UPDATE CASCADE
	);`,
	`CREATE INDEX IF NOT EXISTS idx_health_records_node_id ON health_records(node_id);`,
	`CREATE INDEX IF NOT EXISTS idx_health_records_checked_at ON health_records(checked_at);`,
	`CREATE INDEX IF NOT EXISTS idx_health_records_node_time ON health_records(node_id, checked_at);`,
	`CREATE INDEX IF NOT EXISTS idx_health_records_status ON health_records(status);`,
	// 002 node_tags
	`CREATE TABLE IF NOT EXISTS node_tags (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id INTEGER NOT NULL,
		tag TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(node_id) REFERENCES shared_nodes(id) ON DELETE CASCADE ON UPDATE CASCADE
	);`,
	`CREATE INDEX IF NOT EXISTS idx_node_tags_node ON node_tags(node_id);`,
	`CREATE INDEX IF NOT EXISTS idx_node_tags_tag ON node_tags(tag);`,
	`CREATE UNIQUE INDEX IF NOT EXISTS uniq_node_tag_per_node ON node_tags(node_id, tag);`,
}

// DB wraps sql.DB and provides uptime operations.
type DB struct {
	sqlDB  *sql.DB
	dbPath string
}

// NewDB opens SQLite at path and runs migrations.
func NewDB(path string) (*DB, error) {
	if path == "" {
		path = ":memory:"
	}
	// Normalize :memory: for sqlite driver
	dsn := path
	if path == ":memory:" {
		dsn = "file::memory:?cache=shared"
	}
	// Ensure foreign_keys and WAL for file DBs
	if !strings.Contains(dsn, "?") && dsn != "file::memory:?cache=shared" {
		dsn = dsn + "?_journal_mode=WAL&_foreign_keys=on"
	} else if strings.HasPrefix(dsn, "file:") && !strings.Contains(dsn, "_foreign_keys") {
		if strings.Contains(dsn, "?") {
			dsn += "&_foreign_keys=on"
		} else {
			dsn += "?_foreign_keys=on"
		}
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db %q: %w", path, err)
	}
	// Optimize for :memory:
	if path == ":memory:" || strings.Contains(path, ":memory:") {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	} else {
		db.SetMaxOpenConns(10)
	}
	// Pragmas
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = 10000",
		"PRAGMA temp_store = memory",
		"PRAGMA mmap_size = 268435456",
		"PRAGMA foreign_keys = ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}
	d := &DB{sqlDB: db, dbPath: path}
	if err := d.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return d, nil
}

// NewMemoryDB creates an in-memory DB for tests.
func NewMemoryDB() (*DB, error) {
	return NewDB(":memory:")
}

// Close closes the DB.
func (d *DB) Close() error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	return d.sqlDB.Close()
}

// SQLDB returns underlying *sql.DB.
func (d *DB) SQLDB() *sql.DB { return d.sqlDB }

// Path returns DB path.
func (d *DB) Path() string { return d.dbPath }

// migrate runs migrations.
func (d *DB) migrate() error {
	for i, m := range migrations {
		if _, err := d.sqlDB.Exec(m); err != nil {
			return fmt.Errorf("migration %d: %w", i, err)
		}
	}
	return nil
}

// Migrations returns migration SQL (for inspection).
func (d *DB) Migrations() []string { return migrations }

// --- models ---

// SharedNode corresponds to shared_nodes table.
type SharedNode struct {
	ID                int       `json:"id"`
	Name              string    `json:"name"`
	Host              string    `json:"host"`
	Port              int       `json:"port"`
	Protocol          string    `json:"protocol"`
	Version           string    `json:"version"`
	AllowRelay        bool      `json:"allow_relay"`
	NetworkName       string    `json:"network_name"`
	NetworkSecret     string    `json:"network_secret"`
	Description       string    `json:"description"`
	MaxConnections    int       `json:"max_connections"`
	CurrentConnections int      `json:"current_connections"`
	IsActive          bool      `json:"is_active"`
	IsApproved        bool      `json:"is_approved"`
	QQNumber          string    `json:"qq_number"`
	Wechat            string    `json:"wechat"`
	Mail              string    `json:"mail"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// HealthRecord corresponds to health_records.
type HealthRecord struct {
	ID           int       `json:"id"`
	NodeID       int       `json:"node_id"`
	Status       string    `json:"status"`
	ResponseTime int       `json:"response_time"`
	ErrorMessage string    `json:"error_message"`
	CheckedAt    time.Time `json:"checked_at"`
}

// HealthStatus enum.
type HealthStatus string

const (
	HealthHealthy         HealthStatus = "healthy"
	HealthUnhealthy       HealthStatus = "unhealthy"
	HealthTimeout         HealthStatus = "timeout"
	HealthConnectionError HealthStatus = "connection_error"
	HealthUnknown         HealthStatus = "unknown"
)

func (h HealthStatus) String() string { return string(h) }

// ParseHealthStatus parses string.
func ParseHealthStatus(s string) HealthStatus {
	switch strings.ToLower(s) {
	case "healthy":
		return HealthHealthy
	case "unhealthy":
		return HealthUnhealthy
	case "timeout":
		return HealthTimeout
	case "connection_error":
		return HealthConnectionError
	default:
		return HealthUnknown
	}
}

func (r HealthRecord) IsHealthy() bool { return ParseHealthStatus(r.Status) == HealthHealthy }

// HealthStats mirrors Rust HealthStats.
type HealthStats struct {
	TotalChecks         uint64      `json:"total_checks"`
	HealthyCount        uint64      `json:"healthy_count"`
	UnhealthyCount      uint64      `json:"unhealthy_count"`
	HealthPercentage    float64     `json:"health_percentage"`
	AverageResponseTime *float64    `json:"average_response_time"`
	UptimePercentage    float64     `json:"uptime_percentage"`
	LastCheckTime       *time.Time  `json:"last_check_time"`
	LastStatus          *string     `json:"last_status"`
}

// DatabaseStats mirrors Rust DatabaseStats.
type DatabaseStats struct {
	TotalNodes         uint64 `json:"total_nodes"`
	ActiveNodes        uint64 `json:"active_nodes"`
	TotalHealthRecords uint64 `json:"total_health_records"`
}

// --- helpers ---

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func intToBool(i int) bool { return i != 0 }

// flexBool handles SQLite bool that may be int or bool
type flexBool struct {
	Bool  bool
	Valid bool
}

func (f *flexBool) Scan(src any) error {
	if src == nil {
		f.Valid = false
		return nil
	}
	f.Valid = true
	switch v := src.(type) {
	case bool:
		f.Bool = v
	case int64:
		f.Bool = v != 0
	case int:
		f.Bool = v != 0
	case int32:
		f.Bool = v != 0
	case float64:
		f.Bool = v != 0
	case []byte:
		s := string(v)
		f.Bool = s == "1" || s == "true" || s == "TRUE"
	case string:
		f.Bool = v == "1" || v == "true" || v == "TRUE"
	default:
		f.Bool = false
	}
	return nil
}

func scanNode(rows *sql.Rows) (*SharedNode, error) {
	var n SharedNode
	var version, networkName, networkSecret, description, qq, wechat, mail sql.NullString
	var allowRelay, isActive, isApproved flexBool
	var maxConn, curConn sql.NullInt64
	var created, updated sql.NullTime
	var port sql.NullInt64
	// name, host, protocol are NOT NULL but scan as string directly
	var name, host, protocol string
	var id int
	err := rows.Scan(&id, &name, &host, &port, &protocol, &version, &allowRelay, &networkName, &networkSecret, &description, &maxConn, &curConn, &isActive, &isApproved, &qq, &wechat, &mail, &created, &updated)
	if err != nil {
		return nil, err
	}
	n.ID = id
	n.Name = name
	n.Host = host
	if port.Valid {
		n.Port = int(port.Int64)
	}
	n.Protocol = protocol
	if version.Valid {
		n.Version = version.String
	}
	if allowRelay.Valid {
		n.AllowRelay = allowRelay.Bool
	}
	if networkName.Valid {
		n.NetworkName = networkName.String
	}
	if networkSecret.Valid {
		n.NetworkSecret = networkSecret.String
	}
	if description.Valid {
		n.Description = description.String
	}
	if maxConn.Valid {
		n.MaxConnections = int(maxConn.Int64)
	}
	if curConn.Valid {
		n.CurrentConnections = int(curConn.Int64)
	}
	if isActive.Valid {
		n.IsActive = isActive.Bool
	}
	if isApproved.Valid {
		n.IsApproved = isApproved.Bool
	}
	if qq.Valid {
		n.QQNumber = qq.String
	}
	if wechat.Valid {
		n.Wechat = wechat.String
	}
	if mail.Valid {
		n.Mail = mail.String
	}
	if created.Valid {
		n.CreatedAt = created.Time.UTC()
	}
	if updated.Valid {
		n.UpdatedAt = updated.Time.UTC()
	}
	return &n, nil
}

func scanNodeRow(row *sql.Row) (*SharedNode, error) {
	var n SharedNode
	var version, networkName, networkSecret, description, qq, wechat, mail sql.NullString
	var allowRelay, isActive, isApproved flexBool
	var maxConn, curConn sql.NullInt64
	var created, updated sql.NullTime
	var name, host, protocol string
	var id int
	var port sql.NullInt64
	err := row.Scan(&id, &name, &host, &port, &protocol, &version, &allowRelay, &networkName, &networkSecret, &description, &maxConn, &curConn, &isActive, &isApproved, &qq, &wechat, &mail, &created, &updated)
	if err != nil {
		return nil, err
	}
	n.ID = id
	n.Name = name
	n.Host = host
	if port.Valid {
		n.Port = int(port.Int64)
	}
	n.Protocol = protocol
	if version.Valid {
		n.Version = version.String
	}
	if allowRelay.Valid {
		n.AllowRelay = allowRelay.Bool
	}
	if networkName.Valid {
		n.NetworkName = networkName.String
	}
	if networkSecret.Valid {
		n.NetworkSecret = networkSecret.String
	}
	if description.Valid {
		n.Description = description.String
	}
	if maxConn.Valid {
		n.MaxConnections = int(maxConn.Int64)
	}
	if curConn.Valid {
		n.CurrentConnections = int(curConn.Int64)
	}
	if isActive.Valid {
		n.IsActive = isActive.Bool
	}
	if isApproved.Valid {
		n.IsApproved = isApproved.Bool
	}
	if qq.Valid {
		n.QQNumber = qq.String
	}
	if wechat.Valid {
		n.Wechat = wechat.String
	}
	if mail.Valid {
		n.Mail = mail.String
	}
	if created.Valid {
		n.CreatedAt = created.Time.UTC()
	}
	if updated.Valid {
		n.UpdatedAt = updated.Time.UTC()
	}
	return &n, nil
}

// --- Node operations ---

// CreateNode inserts a node (is_active false pending, is_approved false).
func (d *DB) CreateNode(req CreateNodeRequest) (*SharedNode, error) {
	now := time.Now().UTC()
	res, err := d.sqlDB.Exec(`INSERT INTO shared_nodes (name, host, port, protocol, version, allow_relay, network_name, network_secret, description, max_connections, current_connections, is_active, is_approved, qq_number, wechat, mail, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?, ?, ?, ?)`,
		req.Name, req.Host, req.Port, req.Protocol, "", boolToInt(req.AllowRelay), req.NetworkName, stringOrEmpty(req.NetworkSecret), stringOrEmpty(req.Description), req.MaxConnections, stringOrEmpty(req.QQNumber), stringOrEmpty(req.Wechat), stringOrEmpty(req.Mail), now, now)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return d.GetNodeByID(int(id))
}

func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// GetNodeByID fetches by id.
func (d *DB) GetNodeByID(id int) (*SharedNode, error) {
	row := d.sqlDB.QueryRow(`SELECT id, name, host, port, protocol, version, allow_relay, network_name, network_secret, description, max_connections, current_connections, is_active, is_approved, qq_number, wechat, mail, created_at, updated_at FROM shared_nodes WHERE id = ?`, id)
	n, err := scanNodeRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return n, err
}

// GetAllNodes returns all nodes ordered by id.
func (d *DB) GetAllNodes() ([]*SharedNode, error) {
	rows, err := d.sqlDB.Query(`SELECT id, name, host, port, protocol, version, allow_relay, network_name, network_secret, description, max_connections, current_connections, is_active, is_approved, qq_number, wechat, mail, created_at, updated_at FROM shared_nodes ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SharedNode
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// DeleteNode deletes by id, returns rows affected.
func (d *DB) DeleteNode(id int) (int64, error) {
	res, err := d.sqlDB.Exec(`DELETE FROM shared_nodes WHERE id = ?`, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// UpdateNodeStatus updates is_active and current_connections.
func (d *DB) UpdateNodeStatus(id int, isActive bool, currentConnections *int) (*SharedNode, error) {
	now := time.Now().UTC()
	if currentConnections != nil {
		_, err := d.sqlDB.Exec(`UPDATE shared_nodes SET is_active = ?, current_connections = ?, updated_at = ? WHERE id = ?`, boolToInt(isActive), *currentConnections, now, id)
		if err != nil {
			return nil, err
		}
	} else {
		_, err := d.sqlDB.Exec(`UPDATE shared_nodes SET is_active = ?, updated_at = ? WHERE id = ?`, boolToInt(isActive), now, id)
		if err != nil {
			return nil, err
		}
	}
	return d.GetNodeByID(id)
}

// UpdateNodeVersion updates version.
func (d *DB) UpdateNodeVersion(id int, version string) (*SharedNode, error) {
	now := time.Now().UTC()
	_, err := d.sqlDB.Exec(`UPDATE shared_nodes SET version = ?, updated_at = ? WHERE id = ?`, version, now, id)
	if err != nil {
		return nil, err
	}
	return d.GetNodeByID(id)
}

// ApproveNode sets is_approved.
func (d *DB) ApproveNode(id int, approved bool) (*SharedNode, error) {
	now := time.Now().UTC()
	_, err := d.sqlDB.Exec(`UPDATE shared_nodes SET is_approved = ?, updated_at = ? WHERE id = ?`, boolToInt(approved), now, id)
	if err != nil {
		return nil, err
	}
	return d.GetNodeByID(id)
}

// NodeExists checks host/port/protocol.
func (d *DB) NodeExists(host string, port int, protocol string) (bool, error) {
	var cnt int
	err := d.sqlDB.QueryRow(`SELECT COUNT(*) FROM shared_nodes WHERE host = ? AND port = ? AND protocol = ?`, host, port, protocol).Scan(&cnt)
	return cnt > 0, err
}

// UpdateNode applies partial update from UpdateNodeRequest (admin).
func (d *DB) UpdateNode(id int, req UpdateNodeRequest) (*SharedNode, error) {
	n, err := d.GetNodeByID(id)
	if err != nil {
		return nil, err
	}
	if n == nil {
		return nil, sql.ErrNoRows
	}
	// Build dynamic update
	sets := []string{}
	args := []any{}
	if req.Name != nil {
		sets = append(sets, "name = ?")
		args = append(args, *req.Name)
	}
	if req.Host != nil {
		sets = append(sets, "host = ?")
		args = append(args, *req.Host)
	}
	if req.Port != nil {
		sets = append(sets, "port = ?")
		args = append(args, *req.Port)
	}
	if req.Protocol != nil {
		sets = append(sets, "protocol = ?")
		args = append(args, *req.Protocol)
	}
	if req.Description != nil {
		sets = append(sets, "description = ?")
		args = append(args, *req.Description)
	}
	if req.MaxConnections != nil {
		sets = append(sets, "max_connections = ?")
		args = append(args, *req.MaxConnections)
	}
	if req.IsActive != nil {
		sets = append(sets, "is_active = ?")
		args = append(args, boolToInt(*req.IsActive))
	}
	if req.AllowRelay != nil {
		sets = append(sets, "allow_relay = ?")
		args = append(args, boolToInt(*req.AllowRelay))
	}
	if req.NetworkName != nil {
		sets = append(sets, "network_name = ?")
		args = append(args, *req.NetworkName)
	}
	if req.NetworkSecret != nil {
		sets = append(sets, "network_secret = ?")
		args = append(args, *req.NetworkSecret)
	}
	if req.QQNumber != nil {
		sets = append(sets, "qq_number = ?")
		args = append(args, *req.QQNumber)
	}
	if req.Wechat != nil {
		sets = append(sets, "wechat = ?")
		args = append(args, *req.Wechat)
	}
	if req.Mail != nil {
		sets = append(sets, "mail = ?")
		args = append(args, *req.Mail)
	}
	if len(sets) == 0 && req.Tags == nil {
		return n, nil
	}
	if len(sets) > 0 {
		sets = append(sets, "updated_at = ?")
		args = append(args, time.Now().UTC())
		args = append(args, id)
		q := fmt.Sprintf("UPDATE shared_nodes SET %s WHERE id = ?", strings.Join(sets, ", "))
		if _, err := d.sqlDB.Exec(q, args...); err != nil {
			return nil, err
		}
	}
	if req.Tags != nil {
		if err := d.SetNodeTags(id, *req.Tags); err != nil {
			return nil, err
		}
	}
	return d.GetNodeByID(id)
}

// --- Tag operations ---

// GetNodeTags returns tags for node.
func (d *DB) GetNodeTags(nodeID int) ([]string, error) {
	rows, err := d.sqlDB.Query(`SELECT tag FROM node_tags WHERE node_id = ? ORDER BY tag ASC`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	if tags == nil {
		tags = []string{}
	}
	return tags, rows.Err()
}

// GetNodesTagsMap batch.
func (d *DB) GetNodesTagsMap(nodeIDs []int) (map[int][]string, error) {
	m := make(map[int][]string)
	if len(nodeIDs) == 0 {
		return m, nil
	}
	// Build IN clause
	q := `SELECT node_id, tag FROM node_tags WHERE node_id IN (`
	args := []any{}
	for i, id := range nodeIDs {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, id)
	}
	q += ") ORDER BY node_id ASC, tag ASC"
	rows, err := d.sqlDB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var nid int
		var tag string
		if err := rows.Scan(&nid, &tag); err != nil {
			return nil, err
		}
		m[nid] = append(m[nid], tag)
	}
	return m, rows.Err()
}

// FilterNodeIDsByTag single tag.
func (d *DB) FilterNodeIDsByTag(tag string) ([]int, error) {
	rows, err := d.sqlDB.Query(`SELECT node_id FROM node_tags WHERE tag = ?`, tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// FilterNodeIDsByTagsAny OR semantics.
func (d *DB) FilterNodeIDsByTagsAny(tags []string) ([]int, error) {
	if len(tags) == 0 {
		return []int{}, nil
	}
	q := `SELECT DISTINCT node_id FROM node_tags WHERE tag IN (`
	args := []any{}
	for i, t := range tags {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, t)
	}
	q += ")"
	rows, err := d.sqlDB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetAllTags returns all unique tags sorted.
func (d *DB) GetAllTags() ([]string, error) {
	rows, err := d.sqlDB.Query(`SELECT DISTINCT tag FROM node_tags ORDER BY tag ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	if tags == nil {
		tags = []string{}
	}
	return tags, rows.Err()
}

// SetNodeTags replaces tags.
func (d *DB) SetNodeTags(nodeID int, tags []string) error {
	// Deduplicate and trim
	seen := make(map[string]bool)
	clean := []string{}
	for _, t := range tags {
		trimmed := strings.TrimSpace(t)
		if trimmed == "" {
			continue
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			clean = append(clean, trimmed)
		}
	}
	tx, err := d.sqlDB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Existing tags
	rows, err := tx.Query(`SELECT tag FROM node_tags WHERE node_id = ?`, nodeID)
	if err != nil {
		return err
	}
	existing := make(map[string]bool)
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		existing[t] = true
	}
	rows.Close()
	// Delete removed
	for tag := range existing {
		if !seen[tag] {
			if _, err := tx.Exec(`DELETE FROM node_tags WHERE node_id = ? AND tag = ?`, nodeID, tag); err != nil {
				return err
			}
		}
	}
	// Insert new
	for _, tag := range clean {
		if !existing[tag] {
			if _, err := tx.Exec(`INSERT INTO node_tags (node_id, tag, created_at) VALUES (?, ?, ?)`, nodeID, tag, time.Now().UTC()); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// --- Health operations ---

// CreateHealthRecord inserts record.
func (d *DB) CreateHealthRecord(nodeID int, status HealthStatus, responseTime *int, errorMessage *string) (*HealthRecord, error) {
	now := time.Now().UTC()
	var rt sql.NullInt64
	if responseTime != nil {
		rt.Valid = true
		rt.Int64 = int64(*responseTime)
	} else {
		rt.Valid = false
	}
	var em sql.NullString
	if errorMessage != nil && *errorMessage != "" {
		em.Valid = true
		em.String = *errorMessage
	} else {
		em.Valid = false
		// Rust stores empty string, but allow null
		em.String = ""
	}
	// Use 0 for null response_time to match Rust default
	rtVal := 0
	if rt.Valid {
		rtVal = int(rt.Int64)
	}
	emVal := ""
	if em.Valid {
		emVal = em.String
	}
	res, err := d.sqlDB.Exec(`INSERT INTO health_records (node_id, status, response_time, error_message, checked_at) VALUES (?, ?, ?, ?, ?)`, nodeID, string(status), rtVal, emVal, now)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return d.GetHealthRecordByID(int(id))
}

func (d *DB) GetHealthRecordByID(id int) (*HealthRecord, error) {
	row := d.sqlDB.QueryRow(`SELECT id, node_id, status, response_time, error_message, checked_at FROM health_records WHERE id = ?`, id)
	var r HealthRecord
	var rt sql.NullInt64
	var em sql.NullString
	var checked sql.NullTime
	var status string
	err := row.Scan(&r.ID, &r.NodeID, &status, &rt, &em, &checked)
	if err != nil {
		return nil, err
	}
	r.Status = status
	if rt.Valid {
		r.ResponseTime = int(rt.Int64)
	}
	if em.Valid {
		r.ErrorMessage = em.String
	}
	if checked.Valid {
		r.CheckedAt = checked.Time.UTC()
	}
	return &r, nil
}

// GetNodeHealthRecords fetches with optional since and limit.
func (d *DB) GetNodeHealthRecords(nodeID int, since *time.Time, limit *int, statusFilter *string) ([]*HealthRecord, int64, error) {
	// Count first
	countQ := `SELECT COUNT(*) FROM health_records WHERE node_id = ?`
	countArgs := []any{nodeID}
	if since != nil {
		countQ += ` AND checked_at >= ?`
		countArgs = append(countArgs, *since)
	}
	if statusFilter != nil && *statusFilter != "" {
		countQ += ` AND status = ?`
		countArgs = append(countArgs, *statusFilter)
	}
	var total int64
	if err := d.sqlDB.QueryRow(countQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT id, node_id, status, response_time, error_message, checked_at FROM health_records WHERE node_id = ?`
	args := []any{nodeID}
	if since != nil {
		q += ` AND checked_at >= ?`
		args = append(args, *since)
	}
	if statusFilter != nil && *statusFilter != "" {
		q += ` AND status = ?`
		args = append(args, *statusFilter)
	}
	q += ` ORDER BY checked_at DESC`
	if limit != nil {
		q += ` LIMIT ?`
		args = append(args, *limit)
	}
	rows, err := d.sqlDB.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*HealthRecord
	for rows.Next() {
		var r HealthRecord
		var rt sql.NullInt64
		var em sql.NullString
		var checked sql.NullTime
		var status string
		if err := rows.Scan(&r.ID, &r.NodeID, &status, &rt, &em, &checked); err != nil {
			return nil, 0, err
		}
		r.Status = status
		if rt.Valid {
			r.ResponseTime = int(rt.Int64)
		}
		if em.Valid {
			r.ErrorMessage = em.String
		}
		if checked.Valid {
			r.CheckedAt = checked.Time.UTC()
		}
		out = append(out, &r)
	}
	return out, total, rows.Err()
}

// GetLatestHealthStatus.
func (d *DB) GetLatestHealthStatus(nodeID int) (*HealthRecord, error) {
	rows, _, err := d.GetNodeHealthRecords(nodeID, nil, intPtr(1), nil)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

func intPtr(i int) *int { return &i }

// GetHealthStats computes stats for last hours.
func (d *DB) GetHealthStats(nodeID int, hours int) (*HealthStats, error) {
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	rows, err := d.sqlDB.Query(`SELECT status, response_time, checked_at FROM health_records WHERE node_id = ? AND checked_at >= ? ORDER BY checked_at DESC`, nodeID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var total, healthy uint64
	var sum int64
	var cntHealthyWithRT int64
	var lastTime *time.Time
	var lastStatus *string
	first := true
	for rows.Next() {
		var status string
		var rt sql.NullInt64
		var checked sql.NullTime
		if err := rows.Scan(&status, &rt, &checked); err != nil {
			return nil, err
		}
		total++
		if ParseHealthStatus(status) == HealthHealthy {
			healthy++
			if rt.Valid && rt.Int64 > 0 {
				sum += rt.Int64
				cntHealthyWithRT++
			}
		}
		if first {
			if checked.Valid {
				t := checked.Time.UTC()
				lastTime = &t
			}
			s := status
			lastStatus = &s
			first = false
		}
	}
	stats := &HealthStats{
		TotalChecks:    total,
		HealthyCount:   healthy,
		UnhealthyCount: total - healthy,
		LastCheckTime:  lastTime,
		LastStatus:     lastStatus,
	}
	if total > 0 {
		stats.HealthPercentage = float64(healthy) / float64(total) * 100
		stats.UptimePercentage = stats.HealthPercentage
	}
	if cntHealthyWithRT > 0 {
		avg := float64(sum) / float64(cntHealthyWithRT)
		stats.AverageResponseTime = &avg
	}
	return stats, rows.Err()
}

// CleanupOldHealthRecords deletes older than days.
func (d *DB) CleanupOldHealthRecords(days int) (int64, error) {
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	res, err := d.sqlDB.Exec(`DELETE FROM health_records WHERE checked_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CleanupExcessHealthRecords keeps max per node.
func (d *DB) CleanupExcessHealthRecords(maxPerNode int) (int64, error) {
	// Get all node IDs
	rows, err := d.sqlDB.Query(`SELECT id FROM shared_nodes`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var totalRemoved int64
	for rows.Next() {
		var nid int
		if err := rows.Scan(&nid); err != nil {
			return totalRemoved, err
		}
		var cnt int64
		if err := d.sqlDB.QueryRow(`SELECT COUNT(*) FROM health_records WHERE node_id = ?`, nid).Scan(&cnt); err != nil {
			return totalRemoved, err
		}
		if cnt > int64(maxPerNode) {
			toRemove := cnt - int64(maxPerNode)
			// Delete oldest
			res, err := d.sqlDB.Exec(`DELETE FROM health_records WHERE id IN (SELECT id FROM health_records WHERE node_id = ? ORDER BY checked_at ASC LIMIT ?)`, nid, toRemove)
			if err != nil {
				return totalRemoved, err
			}
			ra, _ := res.RowsAffected()
			totalRemoved += ra
		}
	}
	return totalRemoved, rows.Err()
}

// GetDatabaseStats.
func (d *DB) GetDatabaseStats() (*DatabaseStats, error) {
	var total, active, hr int64
	if err := d.sqlDB.QueryRow(`SELECT COUNT(*) FROM shared_nodes`).Scan(&total); err != nil {
		return nil, err
	}
	if err := d.sqlDB.QueryRow(`SELECT COUNT(*) FROM shared_nodes WHERE is_active = 1`).Scan(&active); err != nil {
		return nil, err
	}
	if err := d.sqlDB.QueryRow(`SELECT COUNT(*) FROM health_records`).Scan(&hr); err != nil {
		return nil, err
	}
	return &DatabaseStats{
		TotalNodes:         uint64(total),
		ActiveNodes:        uint64(active),
		TotalHealthRecords: uint64(hr),
	}, nil
}

// ListNodesFiltered with pagination and filters (public approved only or admin).
func (d *DB) ListNodesFiltered(approvedOnly bool, isActive *bool, protocol *string, search *string, tagIDs []int, page, perPage int) ([]*SharedNode, int64, error) {
	where := []string{}
	args := []any{}
	if approvedOnly {
		where = append(where, "is_approved = 1")
	}
	if isActive != nil {
		where = append(where, "is_active = ?")
		args = append(args, boolToInt(*isActive))
	}
	if protocol != nil && *protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, *protocol)
	}
	if search != nil && *search != "" {
		where = append(where, "(name LIKE ? OR host LIKE ? OR description LIKE ?)")
		like := "%" + *search + "%"
		args = append(args, like, like, like)
	}
	if len(tagIDs) > 0 {
		// IDs already filtered
		placeholders := strings.Repeat("?,", len(tagIDs)-1) + "?"
		where = append(where, fmt.Sprintf("id IN (%s)", placeholders))
		for _, id := range tagIDs {
			args = append(args, id)
		}
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	cntQ := fmt.Sprintf("SELECT COUNT(*) FROM shared_nodes %s", whereSQL)
	if err := d.sqlDB.QueryRow(cntQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * perPage
	q := fmt.Sprintf("SELECT id, name, host, port, protocol, version, allow_relay, network_name, network_secret, description, max_connections, current_connections, is_active, is_approved, qq_number, wechat, mail, created_at, updated_at FROM shared_nodes %s ORDER BY id ASC LIMIT ? OFFSET ?", whereSQL)
	args2 := append([]any{}, args...)
	args2 = append(args2, perPage, offset)
	rows, err := d.sqlDB.Query(q, args2...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*SharedNode
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, n)
	}
	return out, total, rows.Err()
}

// ListAdminNodes similarly but without approvedOnly, with isApproved filter.
func (d *DB) ListAdminNodes(isActive *bool, isApproved *bool, protocol *string, search *string, tagIDs []int, page, perPage int) ([]*SharedNode, int64, error) {
	where := []string{}
	args := []any{}
	if isActive != nil {
		where = append(where, "is_active = ?")
		args = append(args, boolToInt(*isActive))
	}
	if isApproved != nil {
		where = append(where, "is_approved = ?")
		args = append(args, boolToInt(*isApproved))
	}
	if protocol != nil && *protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, *protocol)
	}
	if search != nil && *search != "" {
		where = append(where, "(name LIKE ? OR host LIKE ? OR description LIKE ?)")
		like := "%" + *search + "%"
		args = append(args, like, like, like)
	}
	if len(tagIDs) > 0 {
		placeholders := strings.Repeat("?,", len(tagIDs)-1) + "?"
		where = append(where, fmt.Sprintf("id IN (%s)", placeholders))
		for _, id := range tagIDs {
			args = append(args, id)
		}
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	cntQ := fmt.Sprintf("SELECT COUNT(*) FROM shared_nodes %s", whereSQL)
	if err := d.sqlDB.QueryRow(cntQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * perPage
	q := fmt.Sprintf("SELECT id, name, host, port, protocol, version, allow_relay, network_name, network_secret, description, max_connections, current_connections, is_active, is_approved, qq_number, wechat, mail, created_at, updated_at FROM shared_nodes %s ORDER BY created_at DESC LIMIT ? OFFSET ?", whereSQL)
	args2 := append([]any{}, args...)
	args2 = append(args2, perPage, offset)
	rows, err := d.sqlDB.Query(q, args2...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*SharedNode
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, n)
	}
	return out, total, rows.Err()
}

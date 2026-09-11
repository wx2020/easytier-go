// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package uptime

import "time"

// ApiResponse mirrors Rust ApiResponse.
type ApiResponse[T any] struct {
	Success bool    `json:"success"`
	Data    *T      `json:"data,omitempty"`
	Error   *string `json:"error,omitempty"`
	Message *string `json:"message,omitempty"`
}

func SuccessResponse[T any](data T) ApiResponse[T] {
	return ApiResponse[T]{Success: true, Data: &data}
}

func ErrorResponse[T any](msg string) ApiResponse[T] {
	return ApiResponse[T]{Success: false, Error: &msg}
}

func MessageResponse[T any](msg string) ApiResponse[T] {
	return ApiResponse[T]{Success: true, Message: &msg}
}

// PaginatedResponse mirrors Rust.
type PaginatedResponse[T any] struct {
	Items      []T   `json:"items"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	TotalPages int   `json:"total_pages"`
}

// PaginationParams
type PaginationParams struct {
	Page    *int `json:"page"`
	PerPage *int `json:"per_page"`
}

// CreateNodeRequest mirrors Rust validation.
type CreateNodeRequest struct {
	Name           string  `json:"name"`
	Host           string  `json:"host"`
	Port           int     `json:"port"`
	Protocol       string  `json:"protocol"`
	Description    *string `json:"description"`
	MaxConnections int     `json:"max_connections"`
	AllowRelay     bool    `json:"allow_relay"`
	NetworkName    string  `json:"network_name"`
	NetworkSecret  *string `json:"network_secret"`
	QQNumber       *string `json:"qq_number"`
	Wechat         *string `json:"wechat"`
	Mail           *string `json:"mail"`
}

// Validate minimal.
func (r CreateNodeRequest) Validate() error {
	if r.Name == "" || len(r.Name) > 100 {
		return errBadRequest("name must be 1-100 chars")
	}
	if r.Host == "" || len(r.Host) > 255 {
		return errBadRequest("host must be 1-255 chars")
	}
	if r.Port < 1 || r.Port > 65535 {
		return errBadRequest("port must be 1-65535")
	}
	if r.Protocol == "" || len(r.Protocol) > 20 {
		return errBadRequest("protocol must be 1-20 chars")
	}
	if r.NetworkName == "" || len(r.NetworkName) > 100 {
		return errBadRequest("network_name required 1-100")
	}
	if r.MaxConnections < 1 || r.MaxConnections > 10000 {
		return errBadRequest("max_connections 1-10000")
	}
	hasQQ := r.QQNumber != nil && *r.QQNumber != ""
	hasWechat := r.Wechat != nil && *r.Wechat != ""
	hasMail := r.Mail != nil && *r.Mail != ""
	if !hasQQ && !hasWechat && !hasMail {
		return errBadRequest("at least one contact method required (qq, wechat, mail)")
	}
	return nil
}

// UpdateNodeRequest for admin.
type UpdateNodeRequest struct {
	Name           *string  `json:"name"`
	Host           *string  `json:"host"`
	Port           *int     `json:"port"`
	Protocol       *string  `json:"protocol"`
	Description    *string  `json:"description"`
	MaxConnections *int     `json:"max_connections"`
	IsActive       *bool    `json:"is_active"`
	AllowRelay     *bool    `json:"allow_relay"`
	NetworkName    *string  `json:"network_name"`
	NetworkSecret  *string  `json:"network_secret"`
	QQNumber       *string  `json:"qq_number"`
	Wechat         *string  `json:"wechat"`
	Mail           *string  `json:"mail"`
	Tags           *[]string `json:"tags"`
}

// NodeResponse mirrors Rust NodeResponse with health ring.
type NodeResponse struct {
	ID               int       `json:"id"`
	Name             string    `json:"name"`
	Host             string    `json:"host"`
	Port             int       `json:"port"`
	Protocol         string    `json:"protocol"`
	Version          *string   `json:"version"`
	Description      *string   `json:"description"`
	MaxConnections   int       `json:"max_connections"`
	CurrentConnections int    `json:"current_connections"`
	IsActive         bool      `json:"is_active"`
	IsApproved       bool      `json:"is_approved"`
	AllowRelay       bool      `json:"allow_relay"`
	NetworkName      *string   `json:"network_name"`
	NetworkSecret    *string   `json:"network_secret"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Address          string    `json:"address"`
	UsagePercentage  float64   `json:"usage_percentage"`

	CurrentHealthStatus *string    `json:"current_health_status"`
	LastCheckTime       *time.Time `json:"last_check_time"`
	LastResponseTime    *int       `json:"last_response_time"`
	HealthPercentage24h *float64   `json:"health_percentage_24h"`

	HealthRecordTotalCounterRing   []uint64 `json:"health_record_total_counter_ring"`
	HealthRecordHealthyCounterRing []uint64 `json:"health_record_healthy_counter_ring"`
	RingGranularity                uint32   `json:"ring_granularity"`

	QQNumber *string  `json:"qq_number"`
	Wechat   *string  `json:"wechat"`
	Mail     *string  `json:"mail"`
	Tags     []string `json:"tags"`
}

func nodeToResponse(n *SharedNode) NodeResponse {
	version := n.Version
	desc := n.Description
	networkName := n.NetworkName
	networkSecret := n.NetworkSecret
	addr := n.Protocol + "://" + n.Host + ":" + itoa(n.Port)
	usage := 0.0
	if n.MaxConnections != 0 {
		usage = float64(n.CurrentConnections) / float64(n.MaxConnections) * 100
	}
	var qq, wechat, mail *string
	if n.QQNumber != "" {
		s := n.QQNumber
		qq = &s
	}
	if n.Wechat != "" {
		s := n.Wechat
		wechat = &s
	}
	if n.Mail != "" {
		s := n.Mail
		mail = &s
	}
	return NodeResponse{
		ID: n.ID, Name: n.Name, Host: n.Host, Port: n.Port, Protocol: n.Protocol,
		Version: &version, Description: &desc,
		MaxConnections: n.MaxConnections, CurrentConnections: n.CurrentConnections,
		IsActive: n.IsActive, IsApproved: n.IsApproved, AllowRelay: n.AllowRelay,
		NetworkName: &networkName, NetworkSecret: &networkSecret,
		CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt,
		Address: addr, UsagePercentage: usage,
		HealthRecordTotalCounterRing: []uint64{}, HealthRecordHealthyCounterRing: []uint64{},
		RingGranularity: 0,
		QQNumber: qq, Wechat: wechat, Mail: mail, Tags: []string{},
	}
}

func itoa(i int) string {
	// avoid strconv import for tiny helper
	return formatInt(i)
}

func formatInt(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	buf := [20]byte{}
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// HealthRecordResponse
type HealthRecordResponse struct {
	ID           int       `json:"id"`
	NodeID       int       `json:"node_id"`
	Status       string    `json:"status"`
	ResponseTime *int      `json:"response_time"`
	ErrorMessage *string   `json:"error_message"`
	CheckedAt    time.Time `json:"checked_at"`
}

func recordToResponse(r *HealthRecord) HealthRecordResponse {
	rt := r.ResponseTime
	em := r.ErrorMessage
	return HealthRecordResponse{
		ID: r.ID, NodeID: r.NodeID, Status: r.Status, ResponseTime: &rt, ErrorMessage: &em, CheckedAt: r.CheckedAt,
	}
}

// Filters

type NodeFilterParams struct {
	IsActive *bool  `json:"is_active"`
	Protocol *string `json:"protocol"`
	Search   *string `json:"search"`
	Tags     []string `json:"tags"`
}

type AdminNodeFilterParams struct {
	IsActive   *bool    `json:"is_active"`
	IsApproved *bool    `json:"is_approved"`
	Protocol   *string  `json:"protocol"`
	Search     *string  `json:"search"`
	Tag        *string  `json:"tag"`
	Tags       []string `json:"tags"`
}

type HealthFilterParams struct {
	Status *string    `json:"status"`
	Since  *time.Time `json:"since"`
}

// Admin

type AdminLoginRequest struct {
	Password string `json:"password"`
}

type AdminLoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ApproveNodeRequest struct {
	Approved bool `json:"approved"`
}

// error helpers

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func errBadRequest(msg string) error { return &apiError{status: 400, msg: msg} }
func errNotFound(msg string) error  { return &apiError{status: 404, msg: msg} }
func errUnauthorized(msg string) error { return &apiError{status: 401, msg: msg} }
func errInternal(msg string) error { return &apiError{status: 500, msg: msg} }

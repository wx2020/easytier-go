// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package uptime

import (
	"context"
	"net"
	"sync"
	"time"
)

// Ring constants matching Rust.
const (
	healthCheckRingGranularitySec = 60 * 15 // 15 minutes
	healthCheckRingMaxDurationSec = 60 * 60 * 24
	healthCheckRingSize           = healthCheckRingMaxDurationSec / healthCheckRingGranularitySec // 96
)

type ringItem struct {
	counter uint64
	round   uint64
}

func (r *ringItem) tryUpdateRound(timestamp uint64) {
	curRound := timestamp / uint64(healthCheckRingGranularitySec*healthCheckRingSize)
	if r.round != curRound {
		r.round = curRound
		r.counter = 0
	}
}
func (r *ringItem) inc(timestamp uint64) {
	r.tryUpdateRound(timestamp)
	r.counter++
}
func (r *ringItem) get(timestamp uint64) uint64 {
	r.tryUpdateRound(timestamp)
	return r.counter
}

// HealthyMemRecord mirrors Rust.
type HealthyMemRecord struct {
	mu sync.RWMutex

	NodeID              int
	CurrentHealthStatus HealthStatus
	LastErrorInfo       *string
	LastCheckTime       time.Time
	LastResponseTime    *int

	totalRing   []ringItem
	healthyRing []ringItem
}

func NewHealthyMemRecord(nodeID int) *HealthyMemRecord {
	return &HealthyMemRecord{
		NodeID:              nodeID,
		CurrentHealthStatus: HealthUnknown,
		LastCheckTime:       time.Now().UTC(),
		totalRing:           make([]ringItem, healthCheckRingSize),
		healthyRing:         make([]ringItem, healthCheckRingSize),
	}
}

func (h *HealthyMemRecord) Update(status HealthStatus, responseTime *int, errMsg *string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.CurrentHealthStatus = status
	h.LastCheckTime = time.Now().UTC()
	h.LastResponseTime = responseTime
	h.LastErrorInfo = errMsg
	now := uint64(h.LastCheckTime.Unix())
	idx := (int(now) / healthCheckRingGranularitySec) % healthCheckRingSize
	h.totalRing[idx].inc(now)
	h.healthyRing[idx].tryUpdateRound(now)
	if status == HealthHealthy {
		h.healthyRing[idx].inc(now)
	}
}

func (h *HealthyMemRecord) GetHealthStats(hours int) *HealthStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var total, healthy uint64
	for i := 0; i < healthCheckRingSize; i++ {
		total += h.totalRing[i].counter
		healthy += h.healthyRing[i].counter
	}
	perc := 0.0
	if total > 0 {
		perc = float64(healthy) / float64(total) * 100
	}
	var avg *float64
	if h.LastResponseTime != nil {
		v := float64(*h.LastResponseTime)
		avg = &v
	}
	last := h.LastCheckTime
	statusStr := string(h.CurrentHealthStatus)
	_ = hours // ring already aggregates 24h, ignore hours param for simplicity but return same
	return &HealthStats{
		TotalChecks: total, HealthyCount: healthy, UnhealthyCount: total - healthy,
		HealthPercentage: perc, UptimePercentage: perc,
		AverageResponseTime: avg, LastCheckTime: &last, LastStatus: &statusStr,
	}
}

func (h *HealthyMemRecord) GetCounterRing() (total []uint64, healthy []uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := int(h.LastCheckTime.Unix())
	total = make([]uint64, healthCheckRingSize)
	healthy = make([]uint64, healthCheckRingSize)
	for i := 0; i < healthCheckRingSize; i++ {
		ringTime := now - i*healthCheckRingGranularitySec
		if ringTime < 0 {
			ringTime = 0
		}
		idx := (ringTime / healthCheckRingGranularitySec) % healthCheckRingSize
		total[i] = h.totalRing[idx].get(uint64(ringTime))
		healthy[i] = h.healthyRing[idx].counter
	}
	return total, healthy
}

func (h *HealthyMemRecord) GetRingGranularity() uint32 { return uint32(healthCheckRingGranularitySec) }

// Scheduler periodically health-checks nodes.
type Scheduler struct {
	db       *DB
	interval time.Duration
	timeout  time.Duration

	mu      sync.RWMutex
	records map[int]*HealthyMemRecord

	stopCh chan struct{}
	wg     sync.WaitGroup

	checkFunc func(node *SharedNode) (HealthStatus, *int, *string)
}

// NewScheduler creates scheduler. If checkFunc is nil, uses TCP dial.
func NewScheduler(db *DB, interval, timeout time.Duration, checkFunc func(node *SharedNode) (HealthStatus, *int, *string)) *Scheduler {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if checkFunc == nil {
		checkFunc = tcpCheck(timeout)
	}
	return &Scheduler{
		db: db, interval: interval, timeout: timeout,
		records:   make(map[int]*HealthyMemRecord),
		stopCh:    make(chan struct{}),
		checkFunc: checkFunc,
	}
}

func tcpCheck(timeout time.Duration) func(node *SharedNode) (HealthStatus, *int, *string) {
	return func(node *SharedNode) (HealthStatus, *int, *string) {
		start := time.Now()
		addr := net.JoinHostPort(node.Host, formatInt(node.Port))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		elapsed := int(time.Since(start).Milliseconds())
		if err != nil {
			msg := err.Error()
			return HealthUnhealthy, nil, &msg
		}
		_ = conn.Close()
		return HealthHealthy, &elapsed, nil
	}
}

// Start begins background loop.
func (s *Scheduler) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		// initial check
		s.checkAll()
		for {
			select {
			case <-ticker.C:
				s.checkAll()
			case <-s.stopCh:
				return
			}
		}
	}()
}

// Stop halts scheduler.
func (s *Scheduler) Stop() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
	s.wg.Wait()
}

// Close alias for Stop.
func (s *Scheduler) Close() error { s.Stop(); return nil }

// checkAll iterates nodes.
func (s *Scheduler) checkAll() {
	nodes, err := s.db.GetAllNodes()
	if err != nil {
		return
	}
	for _, n := range nodes {
		status, rt, em := s.checkFunc(n)
		// Persist
		_, _ = s.db.CreateHealthRecord(n.ID, status, rt, em)
		// Update node is_active based on healthy
		isActive := status == HealthHealthy
		_, _ = s.db.UpdateNodeStatus(n.ID, isActive, nil)
		// Update memory ring
		s.mu.Lock()
		rec, ok := s.records[n.ID]
		if !ok {
			rec = NewHealthyMemRecord(n.ID)
			s.records[n.ID] = rec
		}
		s.mu.Unlock()
		rec.Update(status, rt, em)
	}
	// Cleanup if configured? Not here; caller may invoke cleanup manually.
}

// CheckOnce runs one iteration synchronously (for tests).
func (s *Scheduler) CheckOnce(ctx context.Context) error {
	s.checkAll()
	return nil
}

// TestConnection dials single node model.
func (s *Scheduler) TestConnection(node *SharedNode, timeout time.Duration) error {
	if timeout == 0 {
		timeout = s.timeout
	}
	status, _, em := tcpCheck(timeout)(node)
	if status != HealthHealthy {
		if em != nil {
			return &apiError{status: 500, msg: *em}
		}
		return &apiError{status: 500, msg: "unhealthy"}
	}
	return nil
}

// GetNodeMemoryRecord returns record copy if exists.
func (s *Scheduler) GetNodeMemoryRecord(nodeID int) *HealthyMemRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.records[nodeID]; ok {
		return r
	}
	return nil
}

func (s *Scheduler) GetNodeHealthStats(nodeID int, hours int) *HealthStats {
	if r := s.GetNodeMemoryRecord(nodeID); r != nil {
		return r.GetHealthStats(hours)
	}
	return nil
}

// Ensure scheduler also loads existing health_records into ring on start (like Rust load_health_records_from_db)
func (s *Scheduler) LoadFromDB() {
	nodes, err := s.db.GetAllNodes()
	if err != nil {
		return
	}
	for _, n := range nodes {
		// load last 24h records
		since := time.Now().UTC().Add(-24 * time.Hour)
		records, _, err := s.db.GetNodeHealthRecords(n.ID, &since, nil, nil)
		if err != nil {
			continue
		}
		rec := NewHealthyMemRecord(n.ID)
		// populate ring
		for _, r := range records {
			ts := uint64(r.CheckedAt.Unix())
			idx := (int(ts) / healthCheckRingGranularitySec) % healthCheckRingSize
			rec.totalRing[idx].inc(ts)
			if ParseHealthStatus(r.Status) == HealthHealthy {
				rec.healthyRing[idx].inc(ts)
			}
			// last status
			rec.CurrentHealthStatus = ParseHealthStatus(r.Status)
			rec.LastCheckTime = r.CheckedAt
			rt := r.ResponseTime
			if rt != 0 {
				rec.LastResponseTime = &rt
			}
			if r.ErrorMessage != "" {
				em := r.ErrorMessage
				rec.LastErrorInfo = &em
			}
		}
		s.mu.Lock()
		s.records[n.ID] = rec
		s.mu.Unlock()
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package peercenter implements center-peer selection, the global peer map
// data model, and the periodic job runner used to exchange global peer
// information between mesh peers. This is the Go counterpart of the Rust
// peer_center module.
package peercenter

import (
	"context"
	"errors"
	"hash/fnv"
	"sort"
	"sync"
	"time"
)

// Digest is an opaque stable fingerprint of the global peer map contents.
type Digest uint64

// PeerInfoProvider is implemented by the core runtime; it feeds the periodic
// report job and center selection with live peer and route state.
type PeerInfoProvider interface {
	MyPeerID() uint32
	// ListDirectPeers returns the current direct connections with latency
	// snapshots in milliseconds.
	ListDirectPeers() map[uint32]DirectPeerInfo
	// ListRoutes returns every reachable route. Public servers are excluded
	// from center selection.
	ListRoutes() []PeerRoute
}

// PeerRoute describes one reachable route for center-peer selection.
type PeerRoute struct {
	PeerID          uint32
	IsPublicServer  bool
}

// SelectCenterPeer returns the peer ID with the smallest non-public-server ID,
// or the caller's own ID when no other eligible peer exists. It mirrors the
// Rust rule: the center is the alphabetically smallest peer id.
func SelectCenterPeer(myPeerID uint32, routes []PeerRoute) uint32 {
	center := myPeerID
	for _, route := range routes {
		if route.IsPublicServer {
			continue
		}
		if route.PeerID < center {
			center = route.PeerID
		}
	}
	return center
}

// DirectPeerInfo is the latency metadata for one directed peer connection.
type DirectPeerInfo struct {
	LatencyMS int32
}

// GlobalPeerMapEntry groups the direct peers visible to one source peer.
type GlobalPeerMapEntry struct {
	DirectPeers map[uint32]DirectPeerInfo
}

// SrcDstPeerPair is a directed peer pair key.
type SrcDstPeerPair struct {
	Source uint32
	Dest   uint32
}

// CalcDigest computes a deterministic fingerprint of the peer map. It sorts
// the directed pairs so the result is stable across report orders, matching
// the Rust implementation's sorted-hash approach.
func CalcDigest(pairs []SrcDstPeerPair) Digest {
	// An empty map hashes to zero, matching the Rust DefaultHasher behaviour
	// where a fresh hasher finishes at 0.
	if len(pairs) == 0 {
		return 0
	}
	sorted := make([]SrcDstPeerPair, len(pairs))
	copy(sorted, pairs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Source != sorted[j].Source {
			return sorted[i].Source < sorted[j].Source
		}
		return sorted[i].Dest < sorted[j].Dest
	})
	hasher := fnv.New64a()
	var pairBytes [8]byte
	for _, pair := range sorted {
		putUint32LE(pairBytes[:4], pair.Source)
		putUint32LE(pairBytes[4:], pair.Dest)
		_, _ = hasher.Write(pairBytes[:])
	}
	return Digest(hasher.Sum64())
}

func putUint32LE(buf []byte, value uint32) {
	buf[0] = byte(value)
	buf[1] = byte(value >> 8)
	buf[2] = byte(value >> 16)
	buf[3] = byte(value >> 24)
}

// ServerEntry is one directed pair with its latency metadata and last update.
type ServerEntry struct {
	Info       DirectPeerInfo
	UpdateTime time.Time
}

// Server is the center peer's global peer map data store. It accepts reports
// from peers and serves digest-matched global maps.
type Server struct {
	mu             sync.Mutex
	globalMap      map[SrcDstPeerPair]ServerEntry
	peerReportTime map[uint32]time.Time
	digest         Digest
}

func NewServer() *Server {
	return &Server{
		globalMap:      make(map[SrcDstPeerPair]ServerEntry),
		peerReportTime: make(map[uint32]time.Time),
	}
}

// ReportPeers records the direct peers reported by one source peer and
// recomputes the digest.
func (s *Server) ReportPeers(myPeerID uint32, peers map[uint32]DirectPeerInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerReportTime[myPeerID] = time.Now()
	for peerID, info := range peers {
		pair := SrcDstPeerPair{Source: myPeerID, Dest: peerID}
		s.globalMap[pair] = ServerEntry{Info: info, UpdateTime: time.Now()}
	}
	s.digest = s.calcDigestLocked()
}

// GlobalMap returns a copy of the current directed-peer map.
func (s *Server) GlobalMap() map[SrcDstPeerPair]DirectPeerInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[SrcDstPeerPair]DirectPeerInfo, len(s.globalMap))
	for pair, entry := range s.globalMap {
		result[pair] = entry.Info
	}
	return result
}

// GetGlobalPeerMap returns the map and digest. When digest matches the
// request's digest and is non-zero, it returns nil with the current digest to
// signal "no update needed", matching the Rust protocol.
func (s *Server) GetGlobalPeerMap(requestDigest Digest) (map[SrcDstPeerPair]DirectPeerInfo, Digest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if requestDigest == s.digest && requestDigest != 0 {
		return nil, s.digest, true
	}
	result := make(map[SrcDstPeerPair]DirectPeerInfo, len(s.globalMap))
	for pair, entry := range s.globalMap {
		result[pair] = entry.Info
	}
	return result, s.digest, false
}

// CurrentDigest returns the latest recomputed digest.
func (s *Server) CurrentDigest() Digest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.digest
}

// CleanOutdated removes entries and peer reports older than ttl.
func (s *Server) CleanOutdated(ttl time.Duration, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-ttl)
	for pair, entry := range s.globalMap {
		if entry.UpdateTime.Before(cutoff) {
			delete(s.globalMap, pair)
		}
	}
	for peerID, reportTime := range s.peerReportTime {
		if reportTime.Before(cutoff) {
			delete(s.peerReportTime, peerID)
		}
	}
	s.digest = s.calcDigestLocked()
}

func (s *Server) calcDigestLocked() Digest {
	pairs := make([]SrcDstPeerPair, 0, len(s.globalMap))
	for pair := range s.globalMap {
		pairs = append(pairs, pair)
	}
	return CalcDigest(pairs)
}

// Snapshot is a convenience view of the current global map grouped by source.
func (s *Server) Snapshot() map[uint32]GlobalPeerMapEntry {
	pairs := s.GlobalMap()
	result := make(map[uint32]GlobalPeerMapEntry)
	for pair, info := range pairs {
		entry, ok := result[pair.Source]
		if !ok {
			entry = GlobalPeerMapEntry{DirectPeers: make(map[uint32]DirectPeerInfo)}
			result[pair.Source] = entry
		}
		entry.DirectPeers[pair.Dest] = info
	}
	return result
}

// JobResult tells the periodic runner how long to sleep before the next run.
type JobResult struct {
	SleepTime time.Duration
	Err       error
}

// JobFunc is one periodic job. It receives the selected center peer and the
// peer map digest hint.
type JobFunc func(ctx context.Context, centerPeer uint32) JobResult

// Runner executes a job periodically. Each invocation first re-selects the
// center peer from the routes and passes it to the job, mirroring the Rust
// PeerCenterBase::init_periodic_job loop.
type Runner struct {
	myPeerID uint32
	routes   func() []PeerRoute
	job      JobFunc

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	running bool
}

func NewRunner(myPeerID uint32, routes func() []PeerRoute, job JobFunc) *Runner {
	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{myPeerID: myPeerID, routes: routes, job: job, ctx: ctx, cancel: cancel}
}

// Start launches the periodic job loop.
func (r *Runner) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return
	}
	r.running = true
	r.wg.Add(1)
	go r.loop()
}

func (r *Runner) loop() {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}
		var routes []PeerRoute
		if r.routes != nil {
			routes = r.routes()
		}
		center := SelectCenterPeer(r.myPeerID, routes)
		result := r.job(r.ctx, center)
		var sleep time.Duration
		if result.Err != nil {
			sleep = 3 * time.Second
		} else if result.SleepTime > 0 {
			sleep = result.SleepTime
		}
		select {
		case <-r.ctx.Done():
			return
		case <-time.After(sleep):
		}
	}
}

// Stop cancels the loop and waits for the current job to finish.
func (r *Runner) Stop() {
	r.cancel()
	r.wg.Wait()
}

var (
	ErrCenterShutdown = errors.New("peer center shutdown")
)
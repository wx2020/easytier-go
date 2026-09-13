// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// OSPF-style LSA flooding.
//
// Rust reference: easytier/src/peers/peer_ospf_route.rs (6676 lines).
// The Go core already has the pieces: Advertisement encode/decode
// (advertisement.go), newest-wins ConvergenceTable (convergence.go), and
// Dijkstra Engine (route.go). This file adds the missing flooding layer:
// versioned origination, neighbor relay with dedup, expiry, and periodic
// re-announce. Transport is injected via Broadcast so the same code runs
// over peer-RPC mesh, direct channels, or in-memory test fabrics.
package route

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
)

const (
	// floodInterval is the periodic re-announce period for local LSAs.
	floodInterval = 30 * time.Second
	// floodMaxAge expires origins that stop refreshing.
	floodMaxAge = 5 * time.Minute
	// floodMaxPeers bounds one originated advertisement.
	floodMaxPeers = MaxAdvertisementPeers
)

// BroadcastFunc delivers one originated or relayed advertisement to all
// neighbors except (optionally) the one it was received from. The
// implementation may send over peer-RPC mesh or any other transport.
type BroadcastFunc func(ctx context.Context, advertisement Advertisement, exceptOrigin uint32) error

// Flooder originates local LSAs and floods remote ones.
type Flooder struct {
	localPeerID uint32
	table       *ConvergenceTable
	broadcast   BroadcastFunc

	sessionID uint64
	// natTypeFn reports the local UDP NAT classification for outgoing LSAs.
	natTypeFn  func() common.NatType
	mu         sync.Mutex
	version    uint64
	links      map[uint32]uint32
	proxyCIDRs []string
	natTypes   map[uint32]common.NatType
	routeIDs   map[uint32]uint64
	seen       map[uint32]uint64
	lastSeen   map[uint32]time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewFlooder creates a flooder rooted at localPeerID. table may be nil, in
// which case an internal ConvergenceTable is created.
func NewFlooder(localPeerID uint32, table *ConvergenceTable, broadcast BroadcastFunc) (*Flooder, error) {
	if localPeerID == 0 {
		return nil, errors.New("flood local peer ID must not be zero")
	}
	if broadcast == nil {
		return nil, errors.New("flood broadcast function is required")
	}
	if table == nil {
		table = NewConvergenceTable(localPeerID)
	}
	return &Flooder{
		localPeerID: localPeerID,
		table:       table,
		broadcast:   broadcast,
		sessionID:   NewSessionID(),
		links:       make(map[uint32]uint32),
		natTypes:    make(map[uint32]common.NatType),
		routeIDs:    make(map[uint32]uint64),
		seen:        make(map[uint32]uint64),
		lastSeen:    make(map[uint32]time.Time),
	}, nil
}

// Table exposes the underlying convergence table.
func (f *Flooder) Table() *ConvergenceTable { return f.table }

// SessionID returns the local sync session identifier carried in
// SyncRouteInfoRequest envelopes.
func (f *Flooder) SessionID() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessionID
}

// SetSessionID overrides the local sync session identifier.
func (f *Flooder) SetSessionID(id uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessionID = id
}

// SetLinks replaces the local adjacency list (neighbor -> cost).
func (f *Flooder) SetLinks(links map[uint32]uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links = appendLinks(nil, links)
}

// SetProxyCIDRs replaces the locally proxied CIDRs.
func (f *Flooder) SetProxyCIDRs(cidrs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proxyCIDRs = append([]string(nil), cidrs...)
}

// SetNATTypeFn installs the provider for the local UDP NAT classification
// included in every originated LSA (reference RoutePeerInfo.udp_nat_type).
func (f *Flooder) SetNATTypeFn(fn func() common.NatType) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.natTypeFn = fn
}

// UDPNatType returns the NAT classification last flooded by peerID, or
// Unknown when nothing has been advertised yet.
func (f *Flooder) UDPNatType(peerID uint32) common.NatType {
	f.mu.Lock()
	defer f.mu.Unlock()
	if natType, ok := f.natTypes[peerID]; ok {
		return natType
	}
	return common.NatType_Unknown
}

// PeerRouteID returns the per-start route identity last flooded by peerID,
// or 0 when unknown. It powers duplicate-peer detection.
func (f *Flooder) PeerRouteID(peerID uint32) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.routeIDs[peerID]
}

// OriginVersion returns the local origin's current LSA version.
func (f *Flooder) OriginVersion() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.version
}

// SeenVersion returns the last applied LSA version from peerID.
func (f *Flooder) SeenVersion(peerID uint32) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[peerID]
}

// LocalPeerID returns the flooder's origin peer id.
func (f *Flooder) LocalPeerID() uint32 {
	return f.localPeerID
}

// Originate builds, installs, and broadcasts the local LSA, bumping the
// version. It returns the originated advertisement.
func (f *Flooder) Originate(ctx context.Context) (Advertisement, error) {
	f.mu.Lock()
	f.version++
	version := f.version
	links := appendLinks(nil, f.links)
	cidrs := append([]string(nil), f.proxyCIDRs...)
	var natType common.NatType
	if f.natTypeFn != nil {
		natType = f.natTypeFn()
	}
	f.mu.Unlock()

	peers := make([]PeerCost, 0, len(links))
	for peer, cost := range links {
		if peer == 0 || peer == f.localPeerID {
			continue
		}
		peers = append(peers, PeerCost{Peer: peer, Cost: cost})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Peer < peers[j].Peer })
	if len(peers) > floodMaxPeers {
		peers = peers[:floodMaxPeers]
	}
	advertisement := Advertisement{
		Origin:      f.localPeerID,
		Version:     version,
		Peers:       peers,
		ProxyCIDRs:  cidrs,
		Timestamp:   time.Now().Unix(),
		UDPNatType:  natType,
		PeerRouteID: f.sessionID,
	}
	if _, _, err := validatedAdvertisement(advertisement); err != nil {
		return Advertisement{}, err
	}
	f.table.Accept(advertisement)
	f.mu.Lock()
	f.seen[advertisement.Origin] = advertisement.Version
	f.natTypes[advertisement.Origin] = advertisement.UDPNatType
	f.routeIDs[advertisement.Origin] = advertisement.PeerRouteID
	f.lastSeen[advertisement.Origin] = time.Now()
	f.mu.Unlock()
	if err := f.broadcast(ctx, advertisement, 0); err != nil {
		return Advertisement{}, err
	}
	return advertisement, nil
}

// Receive installs a remote LSA and relays it when it is newer than the
// stored copy. fromPeer identifies the neighbor that sent it and is excluded
// from relay. It reports whether the LSA was new.
func (f *Flooder) Receive(ctx context.Context, advertisement Advertisement, fromPeer uint32) (bool, error) {
	if _, _, err := validatedAdvertisement(advertisement); err != nil {
		return false, err
	}
	f.mu.Lock()
	if advertisement.Version <= f.seen[advertisement.Origin] && f.seen[advertisement.Origin] != 0 {
		f.mu.Unlock()
		return false, nil
	}
	f.mu.Unlock()
	if !f.table.Accept(advertisement) {
		return false, nil
	}
	f.mu.Lock()
	f.seen[advertisement.Origin] = advertisement.Version
	f.natTypes[advertisement.Origin] = advertisement.UDPNatType
	f.routeIDs[advertisement.Origin] = advertisement.PeerRouteID
	f.lastSeen[advertisement.Origin] = time.Now()
	f.mu.Unlock()
	if err := f.broadcast(ctx, advertisement, fromPeer); err != nil {
		return true, err
	}
	return true, nil
}

// Expire removes origins older than maxAge (except the local one) and
// reports how many were dropped.
func (f *Flooder) Expire(now time.Time, maxAge time.Duration) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	dropped := 0
	for origin, last := range f.lastSeen {
		if origin == f.localPeerID {
			continue
		}
		if now.Sub(last) > maxAge {
			delete(f.lastSeen, origin)
			delete(f.seen, origin)
			delete(f.natTypes, origin)
			delete(f.routeIDs, origin)
			dropped++
		}
	}
	return dropped
}

// Routes returns the current shortest routes from the local peer.
func (f *Flooder) Routes() []Route {
	return f.table.Snapshot()
}

// Start begins periodic re-announce until ctx is done or Stop is called.
func (f *Flooder) Start(ctx context.Context) {
	if ctx == nil {
		return
	}
	f.mu.Lock()
	if f.ctx != nil {
		f.mu.Unlock()
		return
	}
	f.ctx, f.cancel = context.WithCancel(ctx)
	f.mu.Unlock()
	f.wg.Add(1)
	go f.loop()
}

func (f *Flooder) loop() {
	defer f.wg.Done()
	f.mu.Lock()
	ctx := f.ctx
	f.mu.Unlock()
	ticker := time.NewTicker(floodInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = f.Expire(time.Now(), floodMaxAge)
			_, _ = f.Originate(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// Stop halts periodic re-announce.
func (f *Flooder) Stop() {
	f.mu.Lock()
	cancel := f.cancel
	f.cancel = nil
	f.ctx = nil
	f.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	f.wg.Wait()
}

func appendLinks(_ []PeerCost, links map[uint32]uint32) map[uint32]uint32 {
	out := make(map[uint32]uint32, len(links))
	for peer, cost := range links {
		out[peer] = cost
	}
	return out
}

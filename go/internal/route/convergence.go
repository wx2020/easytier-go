// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"sort"
	"sync"
)

// ConvergenceTable retains the newest advertisement from each origin.
type ConvergenceTable struct {
	localPeerID uint32

	mu             sync.RWMutex
	advertisements map[uint32]Advertisement
}

// NewConvergenceTable creates a table whose snapshots are rooted at localPeerID.
func NewConvergenceTable(localPeerID uint32) *ConvergenceTable {
	return &ConvergenceTable{
		localPeerID:    localPeerID,
		advertisements: make(map[uint32]Advertisement),
	}
}

// Accept installs an advertisement if its version is newer than the stored one.
func (t *ConvergenceTable) Accept(advertisement Advertisement) bool {
	if _, _, err := validatedAdvertisement(advertisement); err != nil {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	current, exists := t.advertisements[advertisement.Origin]
	if exists && advertisement.Version <= current.Version {
		return false
	}
	t.advertisements[advertisement.Origin] = cloneAdvertisement(advertisement)
	return true
}

// Snapshot returns shortest routes over all currently accepted advertisements.
func (t *ConvergenceTable) Snapshot() []Route {
	t.mu.RLock()
	advertisements := make([]Advertisement, 0, len(t.advertisements))
	for _, advertisement := range t.advertisements {
		advertisements = append(advertisements, cloneAdvertisement(advertisement))
	}
	localPeerID := t.localPeerID
	t.mu.RUnlock()

	sort.Slice(advertisements, func(i, j int) bool {
		return advertisements[i].Origin < advertisements[j].Origin
	})
	edges := make(map[routeEdge]uint32)
	for _, advertisement := range advertisements {
		for _, peer := range advertisement.Peers {
			edge := newRouteEdge(advertisement.Origin, peer.Peer)
			if cost, exists := edges[edge]; !exists || peer.Cost < cost {
				edges[edge] = peer.Cost
			}
		}
	}

	engine := NewEngine(localPeerID)
	edgeList := make([]routeEdge, 0, len(edges))
	for edge := range edges {
		edgeList = append(edgeList, edge)
	}
	sort.Slice(edgeList, func(i, j int) bool {
		if edgeList[i].a != edgeList[j].a {
			return edgeList[i].a < edgeList[j].a
		}
		return edgeList[i].b < edgeList[j].b
	})
	for _, edge := range edgeList {
		engine.AddLink(edge.a, edge.b, edges[edge])
	}
	return engine.Snapshot()
}

func cloneAdvertisement(advertisement Advertisement) Advertisement {
	advertisement.Peers = append([]PeerCost(nil), advertisement.Peers...)
	advertisement.ProxyCIDRs = append([]string(nil), advertisement.ProxyCIDRs...)
	return advertisement
}

type routeEdge struct {
	a uint32
	b uint32
}

func newRouteEdge(a, b uint32) routeEdge {
	if a > b {
		a, b = b, a
	}
	return routeEdge{a: a, b: b}
}

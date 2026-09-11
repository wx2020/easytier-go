// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package route computes deterministic shortest paths between mesh peers.
package route

import (
	"container/heap"
	"sort"
	"sync"
)

// Route describes the route to a destination peer from an Engine's local peer.
type Route struct {
	Destination uint32
	NextHop     uint32
	Cost        uint64
}

// Engine maintains an undirected, weighted peer graph.
type Engine struct {
	localPeerID uint32

	mu    sync.RWMutex
	links map[uint32]map[uint32]uint32
}

// NewEngine creates a route engine for localPeerID.
func NewEngine(localPeerID uint32) *Engine {
	return &Engine{
		localPeerID: localPeerID,
		links:       make(map[uint32]map[uint32]uint32),
	}
}

// AddLink adds or updates an undirected link between two peers.
func (e *Engine) AddLink(a, b, cost uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.links[a] == nil {
		e.links[a] = make(map[uint32]uint32)
	}
	if e.links[b] == nil {
		e.links[b] = make(map[uint32]uint32)
	}
	e.links[a][b] = cost
	e.links[b][a] = cost
}

// RemoveLink removes the undirected link between two peers.
func (e *Engine) RemoveLink(a, b uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.links[a], b)
	delete(e.links[b], a)
	if len(e.links[a]) == 0 {
		delete(e.links, a)
	}
	if len(e.links[b]) == 0 {
		delete(e.links, b)
	}
}

// Snapshot returns the current shortest routes from the local peer. Equal-cost
// paths select the lowest first hop; queue ties then select the lowest node ID.
func (e *Engine) Snapshot() []Route {
	links := e.copyLinks()
	distances := make(map[uint32]path)
	queue := routeHeap{{node: e.localPeerID}}
	heap.Init(&queue)
	distances[e.localPeerID] = path{}

	for queue.Len() > 0 {
		current := heap.Pop(&queue).(queueItem)
		best, ok := distances[current.node]
		if !ok || current.cost != best.cost || current.firstHop != best.firstHop {
			continue
		}
		for _, neighbor := range sortedNeighbors(links[current.node]) {
			if neighbor == e.localPeerID {
				continue
			}
			firstHop := current.firstHop
			if current.node == e.localPeerID {
				firstHop = neighbor
			}
			candidate := path{cost: current.cost + uint64(links[current.node][neighbor]), firstHop: firstHop}
			previous, exists := distances[neighbor]
			if exists && !candidate.less(previous) {
				continue
			}
			distances[neighbor] = candidate
			heap.Push(&queue, queueItem{node: neighbor, cost: candidate.cost, firstHop: candidate.firstHop})
		}
	}

	destinations := make([]uint32, 0, len(distances)-1)
	for destination := range distances {
		if destination != e.localPeerID {
			destinations = append(destinations, destination)
		}
	}
	sort.Slice(destinations, func(i, j int) bool { return destinations[i] < destinations[j] })
	routes := make([]Route, 0, len(destinations))
	for _, destination := range destinations {
		best := distances[destination]
		routes = append(routes, Route{Destination: destination, NextHop: best.firstHop, Cost: best.cost})
	}
	return routes
}

func (e *Engine) copyLinks() map[uint32]map[uint32]uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	links := make(map[uint32]map[uint32]uint32, len(e.links))
	for peer, neighbors := range e.links {
		copiedNeighbors := make(map[uint32]uint32, len(neighbors))
		for neighbor, cost := range neighbors {
			copiedNeighbors[neighbor] = cost
		}
		links[peer] = copiedNeighbors
	}
	return links
}

func sortedNeighbors(neighbors map[uint32]uint32) []uint32 {
	peers := make([]uint32, 0, len(neighbors))
	for peer := range neighbors {
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i] < peers[j] })
	return peers
}

type path struct {
	cost     uint64
	firstHop uint32
}

func (p path) less(other path) bool {
	return p.cost < other.cost || p.cost == other.cost && p.firstHop < other.firstHop
}

type queueItem struct {
	node     uint32
	cost     uint64
	firstHop uint32
}

type routeHeap []queueItem

func (h routeHeap) Len() int { return len(h) }

func (h routeHeap) Less(i, j int) bool {
	return h[i].cost < h[j].cost ||
		h[i].cost == h[j].cost && (h[i].firstHop < h[j].firstHop ||
			h[i].firstHop == h[j].firstHop && h[i].node < h[j].node)
}

func (h routeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *routeHeap) Push(value any) {
	*h = append(*h, value.(queueItem))
}

func (h *routeHeap) Pop() any {
	old := *h
	last := len(old) - 1
	item := old[last]
	*h = old[:last]
	return item
}

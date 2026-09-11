// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"container/heap"
)

type minScored[K comparable, V any] struct {
	score K
	value V
	index int
}

type minHeap[K comparable, V any] []*minScored[K, V]

func (h minHeap[K, V]) Len() int           { return len(h) }
func (h minHeap[K, V]) Less(i, j int) bool { return lessK(h[i].score, h[j].score) }
func (h minHeap[K, V]) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *minHeap[K, V]) Push(x interface{}) {
	n := len(*h)
	item := x.(*minScored[K, V])
	item.index = n
	*h = append(*h, item)
}

func (h *minHeap[K, V]) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*h = old[:n-1]
	return item
}

func lessK[K comparable](a, b K) bool {
	switch v := any(a).(type) {
	case int:
		return v < any(b).(int)
	case int32:
		return v < any(b).(int32)
	case int64:
		return v < any(b).(int64)
	case float64:
		return v < any(b).(float64)
	case uint32:
		return v < any(b).(uint32)
	case uint64:
		return v < any(b).(uint64)
	default:
		return false
	}
}

type EdgeRef[V comparable, K comparable] struct {
	Target V
	Cost   K
}

type Graph[V comparable, K comparable] struct {
	Nodes map[V][]EdgeRef[V, K]
}

func NewGraph[V comparable, K comparable]() *Graph[V, K] {
	return &Graph[V, K]{
		Nodes: make(map[V][]EdgeRef[V, K]),
	}
}

func (g *Graph[V, K]) AddNode(node V) {
	if _, exists := g.Nodes[node]; !exists {
		g.Nodes[node] = nil
	}
}

func (g *Graph[V, K]) AddEdge(from, to V, cost K) {
	g.AddNode(from)
	g.AddNode(to)
	g.Nodes[from] = append(g.Nodes[from], EdgeRef[V, K]{Target: to, Cost: cost})
}

func (g *Graph[V, K]) Edges(node V) []EdgeRef[V, K] {
	return g.Nodes[node]
}

type DijkstraResult[V comparable, K comparable] struct {
	Scores   map[V]K
	FirstHop map[V]hopInfo[V]
}

type hopInfo[V comparable] struct {
	Node     V
	Distance int
}

func DijkstraWithFirstHop[V comparable, K comparable](graph *Graph[V, K], start V, zeroScore K) DijkstraResult[V, K] {
	scores := make(map[V]K)
	firstHop := make(map[V]hopInfo[V])
	visited := make(map[V]bool)

	scores[start] = zeroScore
	firstHop[start] = hopInfo[V]{Node: start, Distance: 0}

	h := &minHeap[K, V]{}
	heap.Push(h, &minScored[K, V]{score: zeroScore, value: start})

	for h.Len() > 0 {
		item := heap.Pop(h).(*minScored[K, V])
		node := item.value
		nodeScore := item.score

		if visited[node] {
			continue
		}
		visited[node] = true

		for _, edge := range graph.Edges(node) {
			next := edge.Target
			if visited[next] {
				continue
			}

			nextScore := addK(nodeScore, edge.Cost)

			if existingScore, exists := scores[next]; !exists || lessK(nextScore, existingScore) {
				scores[next] = nextScore
				heap.Push(h, &minScored[K, V]{score: nextScore, value: next})

				hop := hopInfo[V]{Node: next, Distance: 0}
				if prev, hasPrev := firstHop[node]; hasPrev && node != start {
					hop = hopInfo[V]{Node: prev.Node, Distance: prev.Distance + 1}
				} else {
					hop = hopInfo[V]{Node: next, Distance: 1}
				}
				firstHop[next] = hop
			}
		}
	}

	return DijkstraResult[V, K]{
		Scores:   scores,
		FirstHop: firstHop,
	}
}

func addK[K comparable](a, b K) K {
	switch v := any(a).(type) {
	case int:
		return any(v + any(b).(int)).(K)
	case int32:
		return any(v + any(b).(int32)).(K)
	case int64:
		return any(v + any(b).(int64)).(K)
	case float64:
		return any(v + any(b).(float64)).(K)
	case uint32:
		return any(v + any(b).(uint32)).(K)
	case uint64:
		return any(v + any(b).(uint64)).(K)
	default:
		return a
	}
}

type PeerID = uint32

type RouteCostCalculator interface {
	CalculateCost(src, dst PeerID) int32
	BeginUpdate()
	EndUpdate()
	NeedUpdate() bool
}

type GlobalPeerMapEntry struct {
	DirectPeers map[PeerID]DirectPeerInfo
}

type DirectPeerInfo struct {
	LatencyMS int32
}

type globalPeerMapCostCalculator struct {
	globalPeerMap        map[PeerID]GlobalPeerMapEntry
	globalPeerMapSnap    map[PeerID]GlobalPeerMapEntry
	lastUpdateTime       int64
	mapUpdateTime        *int64
}

func NewRouteCostCalculator(globalPeerMap map[PeerID]GlobalPeerMapEntry, mapUpdateTime *int64) RouteCostCalculator {
	return &globalPeerMapCostCalculator{
		globalPeerMap:     globalPeerMap,
		globalPeerMapSnap: make(map[PeerID]GlobalPeerMapEntry),
		mapUpdateTime:     mapUpdateTime,
	}
}

func (c *globalPeerMapCostCalculator) directedCost(src, dst PeerID) (int32, bool) {
	if entry, ok := c.globalPeerMapSnap[src]; ok {
		if info, ok := entry.DirectPeers[dst]; ok {
			return info.LatencyMS, true
		}
	}
	return 0, false
}

func (c *globalPeerMapCostCalculator) CalculateCost(src, dst PeerID) int32 {
	if cost, ok := c.directedCost(src, dst); ok {
		return cost
	}
	if cost, ok := c.directedCost(dst, src); ok {
		return cost
	}
	return 500
}

func (c *globalPeerMapCostCalculator) BeginUpdate() {
	c.globalPeerMapSnap = copyPeerMap(c.globalPeerMap)
}

func (c *globalPeerMapCostCalculator) EndUpdate() {
	if c.mapUpdateTime != nil {
		c.lastUpdateTime = *c.mapUpdateTime
	}
}

func (c *globalPeerMapCostCalculator) NeedUpdate() bool {
	if c.mapUpdateTime == nil {
		return false
	}
	return c.lastUpdateTime < *c.mapUpdateTime
}

func copyPeerMap(m map[PeerID]GlobalPeerMapEntry) map[PeerID]GlobalPeerMapEntry {
	result := make(map[PeerID]GlobalPeerMapEntry, len(m))
	for k, v := range m {
		peers := make(map[PeerID]DirectPeerInfo, len(v.DirectPeers))
		for pk, pv := range v.DirectPeers {
			peers[pk] = pv
		}
		result[k] = GlobalPeerMapEntry{DirectPeers: peers}
	}
	return result
}

func ComputeMultiPathRoutes(globalPeerMap map[PeerID]GlobalPeerMapEntry, start PeerID) map[PeerID]PeerID {
	graph := NewGraph[PeerID, int32]()
	for src, entry := range globalPeerMap {
		graph.AddNode(src)
		for dst, info := range entry.DirectPeers {
			graph.AddEdge(src, dst, info.LatencyMS)
		}
	}

	result := DijkstraWithFirstHop(graph, start, int32(0))
	nextHops := make(map[PeerID]PeerID)
	for node, hop := range result.FirstHop {
		if node == start {
			continue
		}
		nextHops[node] = hop.Node
	}
	return nextHops
}



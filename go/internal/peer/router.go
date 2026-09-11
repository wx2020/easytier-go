// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"fmt"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const MaxForwardCounter uint8 = 7

type RouteAction uint8

const (
	RouteActionLocal RouteAction = iota
	RouteActionForward
)

type RouteDecision struct {
	Action       RouteAction
	NextHop      uint32
	Packet       protocol.Packet
	NoProxy      bool
	NotSendToTUN bool
}

type PacketRouter struct {
	localPeerID uint32
	mu          sync.RWMutex
	routes      map[uint32]uint32
}

func NewPacketRouter(localPeerID uint32, routes map[uint32]uint32) (*PacketRouter, error) {
	if localPeerID == 0 {
		return nil, fmt.Errorf("local peer ID must not be zero")
	}

	copyRoutes := make(map[uint32]uint32, len(routes))
	for destination, nextHop := range routes {
		if destination == 0 {
			return nil, fmt.Errorf("route destination must not be zero")
		}
		if nextHop == 0 {
			return nil, fmt.Errorf("route next hop for peer %d must not be zero", destination)
		}
		if destination == localPeerID || nextHop == localPeerID {
			return nil, fmt.Errorf("route must not point through the local peer")
		}
		copyRoutes[destination] = nextHop
	}
	return &PacketRouter{localPeerID: localPeerID, routes: copyRoutes}, nil
}

func (r *PacketRouter) Process(packet protocol.Packet) (RouteDecision, error) {
	if packet.Header.FromPeerID == 0 {
		return RouteDecision{}, fmt.Errorf("packet source peer ID must not be zero")
	}
	if packet.Header.ForwardCounter > MaxForwardCounter {
		return RouteDecision{}, fmt.Errorf("packet forward counter %d exceeds %d", packet.Header.ForwardCounter, MaxForwardCounter)
	}

	decision := RouteDecision{
		Packet:       packet,
		NoProxy:      packet.Header.Flags&protocol.FlagNoProxy != 0,
		NotSendToTUN: packet.Header.Flags&protocol.FlagNotSendToTUN != 0,
	}
	if packet.Header.ToPeerID == r.localPeerID {
		decision.Action = RouteActionLocal
		return decision, nil
	}
	if packet.Header.ToPeerID == 0 {
		if !isBroadcastControl(packet.Header.PacketType) {
			return RouteDecision{}, fmt.Errorf("broadcast destination is only valid for control packets")
		}
		decision.Action = RouteActionLocal
		return decision, nil
	}
	r.mu.RLock()
	nextHop, ok := r.routes[packet.Header.ToPeerID]
	r.mu.RUnlock()
	if !ok {
		return RouteDecision{}, fmt.Errorf("no route to peer %d", packet.Header.ToPeerID)
	}
	decision.Action = RouteActionForward
	decision.NextHop = nextHop
	decision.Packet.Header.ForwardCounter++
	return decision, nil
}

// SetRoutes atomically replaces the forwarding table. Callers can derive this
// table from a route engine without interrupting packets already in flight.
func (r *PacketRouter) SetRoutes(routes map[uint32]uint32) error {
	copyRoutes := make(map[uint32]uint32, len(routes))
	for destination, nextHop := range routes {
		if destination == 0 || nextHop == 0 {
			return fmt.Errorf("route destination and next hop must not be zero")
		}
		if destination == r.localPeerID || nextHop == r.localPeerID {
			return fmt.Errorf("route must not point through the local peer")
		}
		copyRoutes[destination] = nextHop
	}
	r.mu.Lock()
	r.routes = copyRoutes
	r.mu.Unlock()
	return nil
}

// Routes returns a copy of the current forwarding table.
func (r *PacketRouter) Routes() map[uint32]uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	routes := make(map[uint32]uint32, len(r.routes))
	for destination, nextHop := range r.routes {
		routes[destination] = nextHop
	}
	return routes
}

func isBroadcastControl(packetType uint8) bool {
	switch packetType {
	case protocol.PacketTypeHandshake,
		protocol.PacketTypePing,
		protocol.PacketTypePong,
		protocol.PacketTypeRPCRequest,
		protocol.PacketTypeRPCResponse,
		protocol.PacketTypeNoiseHandshakeMsg1,
		protocol.PacketTypeNoiseHandshakeMsg2,
		protocol.PacketTypeNoiseHandshakeMsg3,
		protocol.PacketTypeRelayHandshake,
		protocol.PacketTypeRelayHandshakeAck:
		return true
	default:
		return false
	}
}

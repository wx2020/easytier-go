// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package relay

import (
	"fmt"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// ForeignNetworkManager handles foreign-network envelopes, routing isolation
// and trusted-key checks.
type ForeignNetworkManager struct {
	localPeerID uint32
	policy      *Policy

	mu       sync.RWMutex
	networks map[string]*foreignEntry // network -> entry
	// peer -> set of networks
	peerNetworks map[uint32]map[string]struct{}
}

type foreignEntry struct {
	network string
	peers   map[uint32]struct{}
}

func NewForeignNetworkManager(localPeerID uint32, policy *Policy) *ForeignNetworkManager {
	if policy == nil {
		policy = NewPolicy(Config{RelayNetworkWhitelist: "*", ForeignRelayBPSLimit: ^uint64(0)})
	}
	return &ForeignNetworkManager{
		localPeerID:  localPeerID,
		policy:       policy,
		networks:     make(map[string]*foreignEntry),
		peerNetworks: make(map[uint32]map[string]struct{}),
	}
}

// AddPeer registers a peer in a foreign network.
// Returns error if network not allowed by whitelist (and not RPC via relay_all).
func (m *ForeignNetworkManager) AddPeer(network string, peerID uint32, packetType uint8) error {
	return m.AddPeerWithKey(network, peerID, nil, packetType)
}

// AddPeerWithKey registers a peer with optional X25519 pubkey for trusted-key check.
func (m *ForeignNetworkManager) AddPeerWithKey(network string, peerID uint32, pubkey []byte, packetType uint8) error {
	if !m.policy.CanAddForeignPeer(network, packetType) {
		return fmt.Errorf("network %q not in whitelist", network)
	}
	// If trusted store has keys for this network, require pubkey to be trusted
	if pubkey != nil && len(pubkey) == 32 && m.policy.Trusted().Count(network) > 0 {
		if !m.policy.IsPubkeyTrusted(pubkey, network) {
			return fmt.Errorf("pubkey not trusted for network %q", network)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.networks[network]
	if !ok {
		e = &foreignEntry{network: network, peers: make(map[uint32]struct{})}
		m.networks[network] = e
	}
	e.peers[peerID] = struct{}{}
	if m.peerNetworks[peerID] == nil {
		m.peerNetworks[peerID] = make(map[string]struct{})
	}
	m.peerNetworks[peerID][network] = struct{}{}
	return nil
}

// RemovePeer removes a peer from network.
func (m *ForeignNetworkManager) RemovePeer(network string, peerID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.networks[network]; ok {
		delete(e.peers, peerID)
		if len(e.peers) == 0 {
			delete(m.networks, network)
		}
	}
	if nets, ok := m.peerNetworks[peerID]; ok {
		delete(nets, network)
		if len(nets) == 0 {
			delete(m.peerNetworks, peerID)
		}
	}
}

// IsPeerInNetwork reports whether peer belongs to network.
func (m *ForeignNetworkManager) IsPeerInNetwork(peerID uint32, network string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.networks[network]
	if !ok {
		return false
	}
	_, ok = e.peers[peerID]
	return ok
}

// ListNetworks returns known foreign networks.
func (m *ForeignNetworkManager) ListNetworks() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.networks))
	for n := range m.networks {
		out = append(out, n)
	}
	return out
}

// PeersInNetwork returns peers for network.
func (m *ForeignNetworkManager) PeersInNetwork(network string) []uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.networks[network]
	if !ok {
		return nil
	}
	out := make([]uint32, 0, len(e.peers))
	for p := range e.peers {
		out = append(out, p)
	}
	return out
}

// HandleEnvelope validates and decides whether to relay a foreign envelope.
// It prevents cross-network leaks: destination must be in the envelope's network.
func (m *ForeignNetworkManager) HandleEnvelope(env protocol.ForeignNetworkPacket) (shouldRelay bool, reason string) {
	packetType := env.NestedPacket.Header.PacketType
	size := len(env.NestedPacket.Payload)
	// Policy check (whitelist, bandwidth, disableRelayData, RPC)
	if !m.policy.ShouldRelay(env.NetworkName, packetType, size) {
		return false, "policy denied"
	}
	// Leak prevention: destination must be member of claimed network
	m.mu.RLock()
	e, ok := m.networks[env.NetworkName]
	m.mu.RUnlock()
	if !ok {
		return false, "unknown network"
	}
	m.mu.RLock()
	_, known := e.peers[env.DestinationPeerID]
	m.mu.RUnlock()
	if !known {
		// If destination not directly known, we allow via encapsulated relay
		// only when destination is not in a different foreign network.
		// Check if peer exists in any other network -> leak attempt.
		m.mu.RLock()
		nets := m.peerNetworks[env.DestinationPeerID]
		m.mu.RUnlock()
		if nets != nil {
			// Peer exists but in different network -> leak
			if _, inSame := nets[env.NetworkName]; !inSame {
				return false, "cross-network leak denied"
			}
		}
		// If peer not known at all, allow encapsulated forwarding via parent (like Rust fallback to ForeignPacket)
		// but still must pass policy already. For this simplified manager we allow if policy passes.
	}
	return true, ""
}

// MarshalEnvelope creates a foreign envelope for sending a packet to a foreign peer.
func (m *ForeignNetworkManager) MarshalEnvelope(network string, packet protocol.Packet) ([]byte, error) {
	if !m.policy.IsNetworkAllowed(network) && !(IsRPCPacket(packet.Header.PacketType) && m.policy.cfg.RelayAllPeerRPC) {
		return nil, fmt.Errorf("network %q not allowed to relay", network)
	}
	// Ensure we don't leak: packet must be intended for peer in same network
	// Caller should have validated destination is in network; we just marshal.
	env := protocol.ForeignNetworkPacket{
		DestinationPeerID: packet.Header.ToPeerID,
		NetworkName:       network,
		NestedPacket:      packet,
	}
	return env.Marshal()
}

// UnmarshalEnvelope parses raw envelope bytes and applies HandleEnvelope logic.
func (m *ForeignNetworkManager) UnmarshalEnvelope(data []byte) (protocol.ForeignNetworkPacket, bool, error) {
	env, err := protocol.ParseForeignNetworkPacket(data)
	if err != nil {
		return protocol.ForeignNetworkPacket{}, false, err
	}
	should, reason := m.HandleEnvelope(env)
	if !should {
		return env, false, fmt.Errorf("envelope denied: %s", reason)
	}
	return env, true, nil
}

// Policy returns underlying policy.
func (m *ForeignNetworkManager) Policy() *Policy { return m.policy }

// UpdatePolicy atomically updates policy config.
func (m *ForeignNetworkManager) UpdatePolicy(cfg Config) {
	m.policy.UpdateConfig(cfg)
}

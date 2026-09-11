// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package relay

import (
	"path/filepath"
	"strings"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// Config holds relay policy flags derived from config.Flags.
type Config struct {
	RelayNetworkWhitelist string // space-separated wildcards, "*" means all
	RelayAllPeerRPC       bool
	ForeignRelayBPSLimit  uint64 // ^uint64(0) == unlimited
	DisableRelayData      bool
}

// Policy checks whitelist, trusted keys, bandwidth and RPC controls.
type Policy struct {
	cfg     Config
	buckets *BucketManager
	trusted *TrustedStore
}

// NewPolicy creates a relay policy.
func NewPolicy(cfg Config) *Policy {
	return &Policy{
		cfg:     cfg,
		buckets: NewBucketManager(cfg.ForeignRelayBPSLimit),
		trusted: NewTrustedStore(),
	}
}

// NewPolicyWithBuckets allows injecting a bucket manager.
func NewPolicyWithBuckets(cfg Config, buckets *BucketManager, trusted *TrustedStore) *Policy {
	if buckets == nil {
		buckets = NewBucketManager(cfg.ForeignRelayBPSLimit)
	}
	if trusted == nil {
		trusted = NewTrustedStore()
	}
	return &Policy{cfg: cfg, buckets: buckets, trusted: trusted}
}

// UpdateConfig replaces policy config and resets buckets.
func (p *Policy) UpdateConfig(cfg Config) {
	p.cfg = cfg
	if p.buckets != nil {
		p.buckets.SetBPSLimit(cfg.ForeignRelayBPSLimit)
	}
}

// Trusted returns the trusted store.
func (p *Policy) Trusted() *TrustedStore { return p.trusted }

// IsNetworkAllowed reports whether network is whitelisted.
// An empty whitelist denies all (except RPC when RelayAllPeerRPC).
func (p *Policy) IsNetworkAllowed(network string) bool {
	return isNetworkInWhitelist(network, p.cfg.RelayNetworkWhitelist)
}

// IsRPCPacket reports whether packet type is RPC.
func IsRPCPacket(packetType uint8) bool {
	return packetType == protocol.PacketTypeRPCRequest || packetType == protocol.PacketTypeRPCResponse
}

// IsRelayDataPacket reports whether packet is considered relay data.
func IsRelayDataPacket(packetType uint8) bool {
	switch packetType {
	case protocol.PacketTypeData, protocol.PacketTypeKCPSrc, protocol.PacketTypeKCPDst, protocol.PacketTypeQUICSrc, protocol.PacketTypeQUICDst, protocol.PacketTypeForeignNetwork:
		return true
	default:
		return false
	}
}

// CanAddForeignPeer checks whether a foreign peer for network may be accepted.
// Mirrors Rust add_peer_conn whitelist check.
func (p *Policy) CanAddForeignPeer(network string, packetType uint8) bool {
	if IsRPCPacket(packetType) && p.cfg.RelayAllPeerRPC {
		return true
	}
	if isNetworkInWhitelist(network, p.cfg.RelayNetworkWhitelist) {
		return true
	}
	if IsRPCPacket(packetType) && p.cfg.RelayAllPeerRPC {
		return true
	}
	return false
}

// ShouldRelay decides if a packet for network should be relayed.
// packetType is from the nested packet. size is payload length.
// isRPC is derived from packetType but caller may override.
func (p *Policy) ShouldRelay(network string, packetType uint8, size int) bool {
	// RPC bypass whitelist when RelayAllPeerRPC set
	if IsRPCPacket(packetType) {
		if p.cfg.RelayAllPeerRPC {
			return true
		}
		// RPC still respects whitelist when flag off
		if !isNetworkInWhitelist(network, p.cfg.RelayNetworkWhitelist) {
			return false
		}
		// RPC is control, bypass data disable and bps limit
		return true
	}
	// Data path: must pass whitelist
	if !isNetworkInWhitelist(network, p.cfg.RelayNetworkWhitelist) {
		return false
	}
	if IsRelayDataPacket(packetType) {
		if p.cfg.DisableRelayData {
			return false
		}
		if !p.buckets.TryConsume(network, uint64(size)) {
			return false
		}
	}
	return true
}

// CanRelay is an alias with explicit size.
func (p *Policy) CanRelay(network string, packet protocol.Packet) bool {
	return p.ShouldRelay(network, packet.Header.PacketType, len(packet.Payload))
}

// IsPubkeyTrustedForNetwork checks trusted store.
func (p *Policy) IsPubkeyTrusted(pubkey []byte, network string) bool {
	return p.trusted.IsTrustedAny(pubkey, network)
}

func isNetworkInWhitelist(network, whitelist string) bool {
	whitelist = strings.TrimSpace(whitelist)
	if whitelist == "" {
		return false
	}
	if whitelist == "*" {
		return true
	}
	// Split by whitespace or comma
	fields := strings.FieldsFunc(whitelist, func(r rune) bool { return r == ' ' || r == ',' || r == ';' })
	for _, pat := range fields {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if pat == "*" {
			return true
		}
		// Use filepath.Match which supports * and ? wildcards
		matched, err := filepath.Match(pat, network)
		if err == nil && matched {
			return true
		}
		// Also consider wildmatch style where "*" may appear mid: filepath.Match already handles
		// But to support patterns like "net*" without full match, filepath does prefix via "*"
		// e.g. "net*" matches "net1" via filepath.Match
	}
	return false
}

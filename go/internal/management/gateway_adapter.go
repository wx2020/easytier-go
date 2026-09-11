// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package management

import (
	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/gateway"
)

// GatewayAdapter exposes gateway proxy entries as management ProxyEntry for RPC/status.
type GatewayAdapter struct {
	manager *gateway.Manager
}

// NewGatewayAdapter creates a management adapter for the given gateway manager.
func NewGatewayAdapter(manager *gateway.Manager) *GatewayAdapter {
	return &GatewayAdapter{manager: manager}
}

// ProxyEntries satisfies ProxyProvider.
func (a *GatewayAdapter) ProxyEntries() []ProxyEntry {
	if a == nil || a.manager == nil {
		return []ProxyEntry{}
	}
	entries := a.manager.ListEntries()
	out := make([]ProxyEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, ProxyEntry{
			Source:        e.Src,
			Destination:   e.Dst,
			StartTime:     uint64(e.StartTime),
			State:         string(e.State),
			TransportType: string(e.TransportType),
		})
	}
	return out
}

// ProxyFlagsFromConfig translates EasyTier config flags into gateway proxy flags.
func ProxyFlagsFromConfig(cfg *config.Config) gateway.ProxyFlags {
	if cfg == nil || cfg.Flags == nil {
		def := config.DefaultFlags()
		return gateway.ProxyFlags{
			EnableKCPProxy:                def.EnableKCPProxy,
			DisableKCPInput:               def.DisableKCPInput,
			DisableRelayKCP:               def.DisableRelayKCP,
			EnableRelayForeignNetworkKCP:  def.EnableRelayForeignNetworkKCP,
			EnableQUICProxy:               def.EnableQUICProxy,
			DisableQUICInput:              def.DisableQUICInput,
			DisableRelayQUIC:              def.DisableRelayQUIC,
			EnableRelayForeignNetworkQUIC: def.EnableRelayForeignNetworkQUIC,
		}
	}
	return gateway.ProxyFlags{
		EnableKCPProxy:                cfg.Flags.EnableKCPProxy,
		DisableKCPInput:               cfg.Flags.DisableKCPInput,
		DisableRelayKCP:               cfg.Flags.DisableRelayKCP,
		EnableRelayForeignNetworkKCP:  cfg.Flags.EnableRelayForeignNetworkKCP,
		EnableQUICProxy:               cfg.Flags.EnableQUICProxy,
		DisableQUICInput:              cfg.Flags.DisableQUICInput,
		DisableRelayQUIC:              cfg.Flags.DisableRelayQUIC,
		EnableRelayForeignNetworkQUIC: cfg.Flags.EnableRelayForeignNetworkQUIC,
	}
}

// NewGatewayManagerFromConfig builds a gateway Manager from an EasyTier config.
func NewGatewayManagerFromConfig(cfg config.Config, kcpLoss, quicLoss gateway.LossyOptions) *gateway.Manager {
	flags := ProxyFlagsFromConfig(&cfg)
	return gateway.NewManager(flags, kcpLoss, quicLoss)
}

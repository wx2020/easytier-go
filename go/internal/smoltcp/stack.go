// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package smoltcp

import (
	"net/netip"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

// Stack wraps Net and is optional based on config flag use-smoltcp.
// It mirrors the Rust gateway's optional smoltcp feature.
type Stack struct {
	Net     *Net
	Device  *ChannelDevicePair
	Enabled bool
}

// NewStack creates a stack if enabled via config, otherwise returns disabled stack.
// ipStr is the IPv4 address to assign to the stack (e.g. "10.0.0.1/24").
func NewStack(cfg config.Config, ipStr string) (*Stack, error) {
	enabled := false
	if cfg.Flags != nil {
		enabled = cfg.Flags.UseSmoltcp
	}
	// Also consider noTun as enabling smoltcp like Rust does.
	if !enabled && cfg.Flags != nil && cfg.Flags.NoTUN {
		enabled = true
	}
	if !enabled {
		return &Stack{Enabled: false}, nil
	}
	prefix, err := ParseIPAddr(ipStr)
	if err != nil {
		// Fallback to 10.0.0.1/24
		prefix = netip.MustParsePrefix("10.0.0.1/24")
	}
	caps := DefaultCapabilities(1280)
	pair := NewChannelDevice(caps)
	netCfg := NewNetConfig(prefix, nil, nil)
	netCfg.AnyIP = true
	n, err := New(pair.Device, netCfg)
	if err != nil {
		return nil, err
	}
	return &Stack{
		Net:     n,
		Device:  pair,
		Enabled: true,
	}, nil
}

// NewStackWithConfig is a helper for tests that directly uses NetConfig.
func NewStackWithConfig(prefix string, cfg NetConfig) (*Stack, *ChannelDevicePair, *Net, error) {
	p, err := ParseIPAddr(prefix)
	if err != nil {
		return nil, nil, nil, err
	}
	cfg.IPAddr = p
	caps := DefaultCapabilities(1280)
	pair := NewChannelDevice(caps)
	n, err := New(pair.Device, cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	stack := &Stack{Net: n, Device: pair, Enabled: true}
	return stack, pair, n, err
}

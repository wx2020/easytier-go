// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package smoltcp provides gateway-level integration for the optional
// user-space TCP/IP stack. It mirrors Rust's gateway/tokio_smoltcp module
// and is the gateway-facing re-export of internal/smoltcp.
package smoltcp

import (
	"net/netip"

	"github.com/EasyTier/EasyTier/go/internal/config"
	parent "github.com/EasyTier/EasyTier/go/internal/smoltcp"
)

// Re-export core types.
type (
	Net                = parent.Net
	NetConfig          = parent.NetConfig
	BufferSize         = parent.BufferSize
	TcpListener        = parent.TcpListener
	TcpStream          = parent.TcpStream
	UdpSocket          = parent.UdpSocket
	ChannelDevice      = parent.ChannelDevice
	DeviceCapabilities = parent.DeviceCapabilities
	Stack              = parent.Stack
	ChannelDevicePair  = parent.ChannelDevicePair
)

// IsSmoltcpEnabled reports whether the stack should be used.
func IsSmoltcpEnabled(cfg config.Config) bool {
	if cfg.Flags == nil {
		return false
	}
	return cfg.Flags.UseSmoltcp || cfg.Flags.NoTUN
}

// NewStack creates a stack when enabled.
func NewStack(cfg config.Config, ipPrefix string) (*Stack, error) {
	return parent.NewStack(cfg, ipPrefix)
}

// NewNetConfig creates a NetConfig.
func NewNetConfig(prefix netip.Prefix, gateway []netip.Addr, buf *BufferSize) NetConfig {
	return parent.NewNetConfig(prefix, gateway, buf)
}

// DefaultBufferSize returns defaults.
func DefaultBufferSize() BufferSize { return parent.DefaultBufferSize() }

// DefaultCapabilities returns IP capabilities.
func DefaultCapabilities(mtu int) DeviceCapabilities {
	return parent.DefaultCapabilities(mtu)
}

// NewChannelDevice creates a channel device pair.
func NewChannelDevice(caps DeviceCapabilities) *ChannelDevicePair {
	return parent.NewChannelDevice(caps)
}

// MustParseIPAddr panics on invalid.
func MustParseIPAddr(s string) netip.Prefix { return parent.MustParseIPAddr(s) }

// ParseIPAddr parses IP.
func ParseIPAddr(s string) (netip.Prefix, error) { return parent.ParseIPAddr(s) }

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package smoltcp

import (
	"net"
	"net/netip"
)

// BufferSize mirrors Rust socket_allocator::BufferSize.
type BufferSize struct {
	TCPRxSize     int
	TCTxSize      int
	UDPRxSize     int
	UDPTxSize     int
	UDPRxMetaSize int
	UDPTxMetaSize int
}

func DefaultBufferSize() BufferSize {
	return BufferSize{
		TCPRxSize:     8192,
		TCTxSize:      8192,
		UDPRxSize:     8192,
		UDPTxSize:     8192,
		UDPRxMetaSize: 32,
		UDPTxMetaSize: 32,
	}
}

// NetConfig mirrors Rust NetConfig.
type NetConfig struct {
	IPAddr     netip.Prefix
	Gateway    []netip.Addr
	BufferSize BufferSize
	// AnyIP when true allows the stack to receive packets for any destination.
	AnyIP bool
	// MaxSockets limits concurrent sockets (resource-limit test).
	MaxSockets int
}

func NewNetConfig(ipAddr netip.Prefix, gateway []netip.Addr, buf *BufferSize) NetConfig {
	bs := DefaultBufferSize()
	if buf != nil {
		bs = *buf
	}
	return NetConfig{
		IPAddr:     ipAddr,
		Gateway:    gateway,
		BufferSize: bs,
		MaxSockets: 1024,
	}
}

// DeviceConfig helpers.
func ParseIPAddr(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		// Try bare IP with /24 default for IPv4 like Rust.
		addr, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return netip.Prefix{}, err
		}
		if addr.Is4() {
			return netip.PrefixFrom(addr, 24), nil
		}
		return netip.PrefixFrom(addr, 64), nil
	}
	return p, nil
}

func MustParseIPAddr(s string) netip.Prefix {
	p, err := ParseIPAddr(s)
	if err != nil {
		panic(err)
	}
	return p
}

// Helper to create DeviceCapabilities for IP medium.
func DefaultCapabilities(mtu int) DeviceCapabilities {
	if mtu == 0 {
		mtu = 1280
	}
	return DeviceCapabilities{
		MTU:    mtu,
		Medium: MediumIP,
	}
}

// IsSmoltcpEnabled reports whether the config enables the stack.
func IsSmoltcpEnabled(useSmoltcp bool, noTun bool) bool {
	return useSmoltcp || noTun
}

// Additional helper for gateway integration: derive net IP from config.
func NetIPFromConfig(ipv4 string) (net.IP, error) {
	if ipv4 == "" {
		return net.ParseIP("10.0.0.1"), nil
	}
	p, err := ParseIPAddr(ipv4)
	if err != nil {
		return nil, err
	}
	return net.ParseIP(p.Addr().String()), nil
}

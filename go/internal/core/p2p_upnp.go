// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package core

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/mapping"
	"github.com/EasyTier/EasyTier/go/internal/punch"
)

// upnpPortMapper adapts mapping.Mapper to the punch.PortMapper contract: the
// punch listener pool asks for one public UDP mapping per socket, and the
// adapter leases a router port (UPnP IGD first, NAT-PMP fallback) and composes
// the public address from the STUN-collected IP.
type upnpPortMapper struct {
	mapper *mapping.Mapper
	// publicIP reports the host's detected public IPv4 address; an invalid
	// or unspecified result makes the lease fail.
	publicIP func() netip.Addr

	mu     sync.Mutex
	leases map[uint16]netip.AddrPort
}

// newUPnPPortMapper builds the adapter. publicIP must be non-nil.
func newUPnPPortMapper(mapper *mapping.Mapper, publicIP func() netip.Addr) *upnpPortMapper {
	return &upnpPortMapper{mapper: mapper, publicIP: publicIP, leases: make(map[uint16]netip.AddrPort)}
}

// AcquireUDPLease implements punch.PortMapper. It is idempotent per port:
// repeated calls return the composed public address of the existing lease.
func (m *upnpPortMapper) AcquireUDPLease(ctx context.Context, port uint16) (netip.AddrPort, error) {
	m.mu.Lock()
	if addr, ok := m.leases[port]; ok {
		m.mu.Unlock()
		return addr, nil
	}
	m.mu.Unlock()

	lan := lanAddress()
	if !lan.IsValid() || lan.IsUnspecified() || lan.IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("upnp: no usable LAN address detected")
	}
	listenerKey := fmt.Sprintf("udp://%s:%d", lan, port)
	lease, err := m.mapper.AddMapping(ctx, listenerKey, netip.AddrPortFrom(lan, port))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("upnp: lease port %d: %w", port, err)
	}
	ip := m.publicIP()
	if !ip.IsValid() || ip.IsUnspecified() {
		return netip.AddrPort{}, fmt.Errorf("upnp: no public address available for the lease")
	}
	addr := netip.AddrPortFrom(ip, lease.ExternalPort)
	m.mu.Lock()
	m.leases[port] = addr
	m.mu.Unlock()
	return addr, nil
}

// lanAddress detects the host's primary LAN IPv4 address without sending
// packets: a UDP connect records the route's source address.
func lanAddress() netip.Addr {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return netip.Addr{}
	}
	defer conn.Close()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return netip.Addr{}
	}
	addr, ok := netip.AddrFromSlice(udpAddr.IP.To4())
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

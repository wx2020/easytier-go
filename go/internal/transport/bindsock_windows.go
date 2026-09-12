//go:build windows

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

// The WS2IPDEF option numbers for interface-bound unicast traffic. Neither
// constant is exported by x/sys/windows.
const (
	windowsIPUnicastIf   = 31 // IP_UNICAST_IF
	windowsIPv6UnicastIf = 31 // IPV6_UNICAST_IF
)

// bindDeviceOS pins outbound traffic to dev with IP_UNICAST_IF (IPv4) or
// IPV6_UNICAST_IF (IPv6), mirroring setup_socket_for_win. MSDN documents
// IP_UNICAST_IF as taking the interface index in network byte order and
// IPV6_UNICAST_IF in host byte order.
func bindDeviceOS(fd int, dev, network, address string) error {
	iface, err := devIndex(dev)
	if err != nil {
		return err
	}
	handle := windows.Handle(fd)
	if networkIsIPv6(network, address) {
		return windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, windowsIPv6UnicastIf, iface)
	}
	// Network byte order for the IPv4 option.
	index := uint32(iface)
	buffer := []byte{byte(index >> 24), byte(index >> 16), byte(index >> 8), byte(index)}
	return windows.Setsockopt(handle, windows.IPPROTO_IP, windowsIPUnicastIf, &buffer[0], 4)
}

// devIndex resolves an interface name to its index.
func devIndex(dev string) (int, error) {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return 0, fmt.Errorf("bind-to-device %q: %w", dev, err)
	}
	if iface.Index <= 0 {
		return 0, fmt.Errorf("bind-to-device %q: invalid index %d", dev, iface.Index)
	}
	return iface.Index, nil
}

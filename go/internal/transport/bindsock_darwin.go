//go:build darwin

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// bindDeviceOS pins the socket to dev with IP_BOUND_IF (IPv4) or
// IPV6_BOUND_IF (IPv6), mirroring the oracle's macOS bind_device_by_index.
func bindDeviceOS(fd int, dev, network, address string) error {
	iface, err := devIndex(dev)
	if err != nil {
		return err
	}
	if networkIsIPv6(network, address) {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface)
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, iface)
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

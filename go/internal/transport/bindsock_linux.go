//go:build linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import "golang.org/x/sys/unix"

// bindDeviceOS pins the socket to dev with SO_BINDTODEVICE. The socket
// option requires CAP_NET_RAW; unprivileged callers receive EPERM.
func bindDeviceOS(fd int, dev, network, address string) error {
	return unix.BindToDevice(fd, dev)
}

//go:build !linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"fmt"

	"github.com/EasyTier/EasyTier/go/internal/tun"
)

func createPlatformTUN(name string, mtu int, ipv4, ipv6 string) (tun.Device, error) {
	return nil, fmt.Errorf("platform TUN is not implemented on this OS (name=%q mtu=%d)", name, mtu)
}

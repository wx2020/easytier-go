//go:build !linux && !darwin && !windows

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import "fmt"

// bindDeviceOS has no socket option on this platform.
func bindDeviceOS(fd int, dev, network, address string) error {
	return fmt.Errorf("bind-to-device %q: unsupported on %s", dev, "platform")
}

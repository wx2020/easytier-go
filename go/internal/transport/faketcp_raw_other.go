//go:build !linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"fmt"
	"runtime"
)

// openRawCapture has no AF_PACKET equivalent off Linux.
func openRawCapture(device string, program BPFProgram) (PacketCapture, error) {
	return nil, fmt.Errorf("fake-tcp raw capture on %s (device %q): %w", runtime.GOOS, device, ErrFakeTCPUnsupported)
}

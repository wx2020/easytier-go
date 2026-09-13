//go:build !linux && !windows && !darwin

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"fmt"
	"runtime"
)

// openRawCapture has no raw backend on this platform.
func openRawCapture(device string, program BPFProgram) (PacketCapture, error) {
	return nil, fmt.Errorf("fake-tcp raw capture on %s (device %q): %w", runtime.GOOS, device, ErrFakeTCPUnsupported)
}

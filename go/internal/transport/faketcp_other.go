//go:build !linux && !windows && !darwin

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"fmt"
	"runtime"
)

func isFakeTCPPrivileged() bool { return false }

func openWindowsCapture(filterString string) (PacketCapture, error) {
	return nil, fmt.Errorf("windivert backend is not linked (GOOS=%s): %w", runtime.GOOS, ErrFakeTCPUnsupported)
}

func openMacOSCapture(device string, program BPFProgram) (PacketCapture, error) {
	return nil, fmt.Errorf("macOS BPF backend is not linked (GOOS=%s): %w", runtime.GOOS, ErrFakeTCPUnsupported)
}

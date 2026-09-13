//go:build darwin

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"fmt"
	"os"
	"runtime"
)

func isFakeTCPPrivileged() bool {
	// BPF device nodes are typically root-owned; capture requires uid 0.
	return os.Geteuid() == 0
}

// openMacOSCapture selects the BPF backend for the platform dispatch from
// faketcp_capture.go.
func openMacOSCapture(device string, program BPFProgram) (PacketCapture, error) {
	return openMacOSBPFCapture(device, program)
}

// openWindowsCapture has no implementation on darwin.
func openWindowsCapture(filterString string) (PacketCapture, error) {
	return nil, fmt.Errorf("windivert backend is not linked (GOOS=%s): %w", runtime.GOOS, ErrFakeTCPUnsupported)
}

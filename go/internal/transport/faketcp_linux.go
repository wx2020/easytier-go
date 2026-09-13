//go:build linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"fmt"
	"os"
	"runtime"
)

func isFakeTCPPrivileged() bool {
	// Raw packet capture on Linux requires CAP_NET_RAW or uid 0.
	return os.Geteuid() == 0
}

// openWindowsCapture and openMacOSCapture have no implementation on Linux;
// the platform backend is the AF_PACKET capture in faketcp_raw_linux.go.
func openWindowsCapture(filterString string) (PacketCapture, error) {
	return nil, fmt.Errorf("windivert backend is not linked (GOOS=%s): %w", runtime.GOOS, ErrFakeTCPUnsupported)
}

func openMacOSCapture(device string, program BPFProgram) (PacketCapture, error) {
	return nil, fmt.Errorf("macOS BPF backend is not linked (GOOS=%s): %w", runtime.GOOS, ErrFakeTCPUnsupported)
}

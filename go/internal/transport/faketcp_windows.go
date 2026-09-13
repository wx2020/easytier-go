//go:build windows

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func isFakeTCPPrivileged() bool {
	// WinDivert requires an elevated process (the driver service install
	// needs Administrator). DLL presence is checked separately at open time.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// openWindowsCapture selects the WinDivert backend for the platform
// dispatch from faketcp_capture.go.
func openWindowsCapture(filterString string) (PacketCapture, error) {
	return openWinDivertCapture(filterString)
}

// openMacOSCapture has no implementation on Windows.
func openMacOSCapture(device string, program BPFProgram) (PacketCapture, error) {
	return nil, fmt.Errorf("macOS BPF backend is not linked (GOOS=%s): %w", "windows", ErrFakeTCPUnsupported)
}

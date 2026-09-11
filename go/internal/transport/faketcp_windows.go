//go:build windows

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

func isFakeTCPPrivileged() bool {
	// On Windows, WinDivert/pcap requires Administrator. For Go-Go tests we
	// treat the fallback TCP emulation as compatible and report non-privileged
	// without failing.
	return false
}

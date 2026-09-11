//go:build linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import "os"

func isFakeTCPPrivileged() bool {
	// Raw packet capture on Linux requires CAP_NET_RAW or uid 0.
	return os.Geteuid() == 0
}

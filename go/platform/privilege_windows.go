//go:build windows

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import "os"

func isPrivilegedImpl() bool {
	if v := os.Getenv("EASYTIER_FORCE_PRIVILEGED"); v == "1" {
		return true
	}
	// Simplified: on Windows, check for admin is complex; assume false for dry-run.
	return false
}

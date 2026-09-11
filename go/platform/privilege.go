//go:build !windows

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import "os"

func isPrivilegedImpl() bool {
	// On Unix, check euid == 0. On other platforms, check for admin.
	// For dry-run tests we always return false unless overridden by env.
	if v := os.Getenv("EASYTIER_FORCE_PRIVILEGED"); v == "1" {
		return true
	}
	return os.Geteuid() == 0
}

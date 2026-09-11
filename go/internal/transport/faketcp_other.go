//go:build !linux && !windows

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

func isFakeTCPPrivileged() bool { return false }

//go:build !cgo

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

// Keep the package buildable when cross-builds disable cgo. The C ABI is
// intentionally unavailable in this mode.
func main() {}

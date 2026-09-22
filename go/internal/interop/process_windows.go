//go:build interop && windows

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package interop

import (
	"os/exec"
	"time"
)

func setProcessGroup(cmd *exec.Cmd) {
	// On Windows, child processes run under standard console/job attributes.
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

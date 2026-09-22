// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"sync"
)

// Android TUN FD handling mirrors go/platform Android adapter's one-active policy.
// This file is built on Android or linux+cgo for testing the injection path.

var androidState = struct {
	sync.Mutex
	active     bool
	activeFD   int
	activeName string
}{activeFD: -1}

// ValidateAndroidFD validates an injected VpnService FD.
func ValidateAndroidFD(fd int) error {
	if fd < 0 {
		return fmt.Errorf("%w: invalid Android TUN FD %d", ErrInvalidFD, fd)
	}
	return nil
}

// PlanAndroidTun returns a dry-run plan for wrapping an Android VpnService FD.
func PlanAndroidTun(cfg Config, fd int) (Plan, error) {
	if err := ValidateAndroidFD(fd); err != nil {
		return Plan{}, err
	}
	plan := newPlan("android")
	if fd < 0 {
		return Plan{}, fmt.Errorf("%w: Android requires injected FD", ErrInvalidConfig)
	}
	plan.add("validate VpnService FD", []string{"validate-fd", fmt.Sprintf("%d", fd)}, false, nil)
	androidState.Lock()
	active := androidState.active
	androidState.Unlock()
	if active {
		plan.Warnings = append(plan.Warnings, "one-active-TUN policy: existing TUN must be closed")
	}
	plan.add("wrap injected FD", []string{"dup", fmt.Sprintf("%d", fd)}, false, []string{"close dup fd"})
	name := cfg.Name
	if name == "" {
		name = "tun0"
	}
	plan.add("configure TUN via VpnService", []string{"vpn-builder", name, fmt.Sprintf("mtu=%d", cfg.MTU)}, false, nil)
	return plan, nil
}

// AcquireAndroidTun marks the Android TUN as active (one-active check).
func AcquireAndroidTun(name string, fd int) error {
	androidState.Lock()
	defer androidState.Unlock()
	if androidState.active {
		return fmt.Errorf("%w: Android VpnService allows only one active TUN", ErrInvalidConfig)
	}
	if fd < 0 {
		return fmt.Errorf("%w: invalid FD %d", ErrInvalidFD, fd)
	}
	androidState.active = true
	androidState.activeFD = fd
	androidState.activeName = name
	return nil
}

// ReleaseAndroidTun clears the active Android TUN.
func ReleaseAndroidTun() {
	androidState.Lock()
	androidState.active = false
	androidState.activeFD = -1
	androidState.activeName = ""
	androidState.Unlock()
}

// IsAndroidTunActive reports whether an Android TUN is currently acquired.
func IsAndroidTunActive() bool {
	androidState.Lock()
	defer androidState.Unlock()
	return androidState.active
}

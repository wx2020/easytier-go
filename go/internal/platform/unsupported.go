//go:build !linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import "fmt"

// New creates a TUN device when the current platform provides one.
func New(config Config) (Device, error) {
	return nil, unsupported()
}

// NewTUN is the convenience form of New for a named device.
func NewTUN(name string, mtu int) (Device, error) {
	return New(Config{Name: name, MTU: mtu})
}

// NewFromFD wraps an already-open TUN descriptor when supported.
func NewFromFD(fd int, config Config) (Device, error) {
	return nil, unsupported()
}

// NewTUNFromFD is the convenience form of NewFromFD.
func NewTUNFromFD(fd int, mtu int) (Device, error) {
	return NewFromFD(fd, Config{MTU: mtu})
}

func unsupported() error {
	return fmt.Errorf("%w: only Linux currently provides a TUN adapter", ErrUnsupported)
}

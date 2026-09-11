// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package platform contains platform-specific network device contracts.
package platform

import (
	"context"
	"errors"
)

const (
	DefaultMTU    = 1500
	MaxMTU        = 65535
	MaxPacketSize = 65535
)

var (
	ErrUnsupported      = errors.New("TUN devices are unsupported on this platform")
	ErrInvalidConfig    = errors.New("invalid TUN configuration")
	ErrInvalidMTU       = errors.New("invalid TUN MTU")
	ErrInvalidPacketMax = errors.New("invalid TUN maximum packet size")
	ErrInvalidFD        = errors.New("invalid TUN file descriptor")
	ErrInvalidPacket    = errors.New("invalid TUN packet")
	ErrPacketTooLarge   = errors.New("TUN packet exceeds configured bounds")
	ErrClosed           = errors.New("TUN device is closed")
)

// Config controls creation and packet bounds for a TUN device. MaxPacketSize
// defaults to MTU when omitted and must not be smaller than MTU otherwise.
type Config struct {
	Name          string
	MTU           int
	MaxPacketSize int
}

// Device exchanges complete packets with a virtual network device.
type Device interface {
	ReadPacket(ctx context.Context) ([]byte, error)
	WritePacket(ctx context.Context, packet []byte) error
	Close() error
}

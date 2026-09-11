// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webclient

import (
	"context"
	"errors"
	"net"
)

// ErrNoiseUnsupported indicates that the optional connection upgrade is not
// implemented by this package.
var ErrNoiseUnsupported = errors.New("webclient Noise upgrade is unsupported")

// NoiseUpgrader is an optional future transport hook. Packet transports in
// this package currently reject it; no encrypted or secure-web compatibility
// is claimed until a real interoperable implementation is available.
type NoiseUpgrader interface {
	Upgrade(context.Context, net.Conn) (net.Conn, error)
}

// UnsupportedNoiseUpgrader explicitly rejects a requested Noise upgrade.
type UnsupportedNoiseUpgrader struct{}

func (UnsupportedNoiseUpgrader) Upgrade(context.Context, net.Conn) (net.Conn, error) {
	return nil, ErrNoiseUnsupported
}

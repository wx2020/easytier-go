// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"encoding/binary"
	"fmt"
)

// WGTunnelHeaderSize is the synthetic IPv4 header used for wg:// transport.
const WGTunnelHeaderSize = 20

// MarshalWGTunnelHeader returns the 20-byte synthetic IPv4 header for wg://.
// It mirrors easytier/src/tunnel/wireguard.rs:fill_ip_header.
func MarshalWGTunnelHeader(payloadLen int) []byte {
	h := make([]byte, WGTunnelHeaderSize)
	h[0] = 0x45
	h[1] = 0
	total := payloadLen + PeerManagerHeaderSize + WGTunnelHeaderSize
	binary.BigEndian.PutUint16(h[2:4], uint16(total))
	// h[4..8] already zero (identification + flags/frag)
	h[8] = 64
	h[9] = 0
	// h[10..12] checksum zero
	// h[12..20] src/dst zero
	return h
}

// ParseWGTunnelHeader validates a 20-byte WG header and returns payload length.
func ParseWGTunnelHeader(h []byte) (int, error) {
	if len(h) < WGTunnelHeaderSize {
		return 0, fmt.Errorf("WG header too short: %d", len(h))
	}
	if h[0] != 0x45 {
		return 0, fmt.Errorf("WG header version mismatch: 0x%02x", h[0])
	}
	if h[8] != 64 {
		return 0, fmt.Errorf("WG header TTL mismatch: %d", h[8])
	}
	total := int(binary.BigEndian.Uint16(h[2:4]))
	if total < WGTunnelHeaderSize+PeerManagerHeaderSize {
		return 0, fmt.Errorf("WG total length %d too small", total)
	}
	payloadLen := total - WGTunnelHeaderSize - PeerManagerHeaderSize
	if payloadLen < 0 {
		return 0, fmt.Errorf("WG payload length negative: %d", payloadLen)
	}
	return payloadLen, nil
}

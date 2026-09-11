// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package wginterop speaks standard WireGuard (boringtun-compatible Noise)
// to stock clients.
//
// Reference: boringtun-easytier 0.6.1 src/noise/{handshake,session,mod,
// rate_limiter}.rs, as used by easytier/src/tunnel/wireguard.rs (Tunn).
// Only the responder (server/portal) path plus the transport data plane
// are implemented: the portal answers stock initiations and decapsulates
// stock data packets. Initiating handshakes (Go as a WG client) is out of
// scope.
//
// Wire sizes (bytes): initiation 148, response 92, cookie reply 64, data
// header 16 + AEAD tag 16. Message type is u32 LE: 1/2/3/4.
package wginterop

import (
	"errors"
)

// Message types, matching boringtun noise/mod.rs.
const (
	MsgTypeHandshakeInit     uint32 = 1
	MsgTypeHandshakeResponse uint32 = 2
	MsgTypeCookieReply       uint32 = 3
	MsgTypeData              uint32 = 4
)

// Wire sizes, matching boringtun noise/mod.rs.
const (
	HandshakeInitSize = 148
	HandshakeRespSize = 92
	CookieReplySize   = 64
	DataHeaderSize    = 16
	DataOverheadSize  = 32
	MaxDataPacketSize = 2048
	TimestampSize     = 12
	MacSize           = 16
	CookieSize        = 16
	CookieNonceSize   = 24
)

// Protocol labels, matching boringtun noise/handshake.rs.
const (
	labelMAC1   = "mac1----"
	labelCookie = "cookie--"
)

// Initial chain values, copied verbatim from boringtun
// noise/handshake.rs INITIAL_CHAIN_KEY / INITIAL_CHAIN_HASH.
var initialChainKey = [32]byte{
	96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208,
	22, 235, 66, 6, 248, 114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
}

var initialChainHash = [32]byte{
	34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50,
	45, 156, 108, 102, 34, 147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
}

var (
	// ErrInvalidPacket is a malformed datagram (size/type/reserved).
	ErrInvalidPacket = errors.New("wginterop: invalid packet")
	// ErrInvalidMAC is a MAC1 authentication failure: silent drop.
	ErrInvalidMAC = errors.New("wginterop: invalid mac")
	// ErrWrongKey is a static-identity mismatch: silent drop.
	ErrWrongKey = errors.New("wginterop: wrong key")
	// ErrStaleTimestamp is a replayed/old handshake timestamp.
	ErrStaleTimestamp = errors.New("wginterop: stale timestamp")
	// ErrWrongIndex is an unknown session index.
	ErrWrongIndex = errors.New("wginterop: wrong index")
	// ErrNoSession is data for an unknown session.
	ErrNoSession = errors.New("wginterop: no session")
	// ErrInvalidCounter is an out-of-window data counter.
	ErrInvalidCounter = errors.New("wginterop: invalid counter")
	// ErrDuplicateCounter is a replayed data counter.
	ErrDuplicateCounter = errors.New("wginterop: duplicate counter")
	// ErrInvalidTag is an AEAD authentication failure.
	ErrInvalidTag = errors.New("wginterop: invalid aead tag")
	// ErrUnderLoad asks the caller to drop under DoS pressure.
	ErrUnderLoad = errors.New("wginterop: under load")
)

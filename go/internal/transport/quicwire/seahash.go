// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"encoding/binary"
)

const (
	seaHashK1 = 0x16f11fe89b0d677c
	seaHashK2 = 0xb480a793d8e6c86c
	seaHashK3 = 0x6fe2e5aaf078ebc9
	seaHashK4 = 0x14f994a4c5259381
)

func diffuse(x uint64) uint64 {
	x *= 0x6eed0e9da4d94a4f
	a := x >> 32
	b := x >> 60
	x ^= a >> b
	x *= 0x6eed0e9da4d94a4f
	return x
}

// SeaHasher implements the exact streaming SeaHash algorithm as used by Rust's
// seahash::SeaHasher (default seeds).
type SeaHasher struct {
	state   [4]uint64
	written uint64
	tail    uint64
	ntail   int
}

// NewSeaHasher creates a new SeaHasher with default seeds.
func NewSeaHasher() *SeaHasher {
	return &SeaHasher{
		state: [4]uint64{seaHashK1, seaHashK2, seaHashK3, seaHashK4},
	}
}

// Reset resets the hasher to its initial state.
func (h *SeaHasher) Reset() {
	h.state = [4]uint64{seaHashK1, seaHashK2, seaHashK3, seaHashK4}
	h.written = 0
	h.tail = 0
	h.ntail = 0
}

func (h *SeaHasher) push(x uint64) {
	a := diffuse(h.state[0] ^ x)
	h.state[0] = h.state[1]
	h.state[1] = h.state[2]
	h.state[2] = h.state[3]
	h.state[3] = a
	h.written += 8
}

// Write writes bytes into the SeaHasher.
func (h *SeaHasher) Write(p []byte) (int, error) {
	nTotal := len(p)
	for len(p) > 0 {
		// Fill tail up to 8 bytes
		if h.ntail > 0 || len(p) < 8 {
			copied := 8 - h.ntail
			if copied > len(p) {
				copied = len(p)
			}
			for i := 0; i < copied; i++ {
				h.tail |= uint64(p[i]) << (8 * (h.ntail + i))
			}
			h.ntail += copied
			p = p[copied:]
			if h.ntail == 8 {
				h.push(h.tail)
				h.tail = 0
				h.ntail = 0
			}
			continue
		}

		// Fast path for 32-byte (4 x uint64) chunks
		for len(p) >= 32 {
			h.state[0] = diffuse(h.state[0] ^ binary.LittleEndian.Uint64(p[0:8]))
			h.state[1] = diffuse(h.state[1] ^ binary.LittleEndian.Uint64(p[8:16]))
			h.state[2] = diffuse(h.state[2] ^ binary.LittleEndian.Uint64(p[16:24]))
			h.state[3] = diffuse(h.state[3] ^ binary.LittleEndian.Uint64(p[24:32]))
			h.written += 32
			p = p[32:]
		}

		// Handle remaining 8, 16, 24 byte chunks
		excessive := len(p)
		if excessive >= 24 {
			a := diffuse(h.state[0] ^ binary.LittleEndian.Uint64(p[0:8]))
			b := diffuse(h.state[1] ^ binary.LittleEndian.Uint64(p[8:16]))
			c := diffuse(h.state[2] ^ binary.LittleEndian.Uint64(p[16:24]))
			h.state[0] = h.state[3]
			h.state[1] = a
			h.state[2] = b
			h.state[3] = c
			h.written += 24
			p = p[24:]
		} else if excessive >= 16 {
			a := diffuse(h.state[0] ^ binary.LittleEndian.Uint64(p[0:8]))
			b := diffuse(h.state[1] ^ binary.LittleEndian.Uint64(p[8:16]))
			h.state[0] = h.state[2]
			h.state[1] = h.state[3]
			h.state[2] = a
			h.state[3] = b
			h.written += 16
			p = p[16:]
		} else if excessive >= 8 {
			h.push(binary.LittleEndian.Uint64(p[0:8]))
			p = p[8:]
		} else if excessive > 0 {
			for i := 0; i < len(p); i++ {
				h.tail |= uint64(p[i]) << (8 * i)
			}
			h.ntail = len(p)
			p = nil
		}
	}
	return nTotal, nil
}

// WriteU64 writes a uint64 in little-endian order, matching Rust Hasher::write_u64.
func (h *SeaHasher) WriteU64(v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	_, _ = h.Write(b[:])
}

// WriteUsize writes a usize (64-bit little-endian) matching Rust Hasher::write_usize on 64-bit target.
func (h *SeaHasher) WriteUsize(v int) {
	h.WriteU64(uint64(v))
}

// WriteSliceHash writes a byte slice mimicking Rust `slice.hash(&mut hasher)`.
// In Rust's `impl Hash for [u8]`, it first writes length prefix (as 64-bit usize),
// then writes the raw slice bytes.
func (h *SeaHasher) WriteSliceHash(p []byte) {
	h.WriteUsize(len(p))
	_, _ = h.Write(p)
}

// Finish computes the final 64-bit hash value matching Rust SeaHasher::finish().
func (h *SeaHasher) Finish() uint64 {
	a := h.state[0]
	if h.ntail > 0 {
		a = diffuse(h.state[0] ^ h.tail)
	}
	return diffuse(a ^ h.state[1] ^ h.state[2] ^ h.state[3] ^ (h.written + uint64(h.ntail)))
}

// QuinnPlaintextChecksum computes the 8-byte checksum used by quinn-plaintext 0.3.0.
// In quinn-plaintext:
//
//	let mut hasher = SeaHasher::default();
//	header.hash(&mut hasher);
//	payload.hash(&mut hasher);
//	let checksum = hasher.finish();
func QuinnPlaintextChecksum(header, payload []byte) uint64 {
	hasher := NewSeaHasher()
	hasher.WriteSliceHash(header)
	hasher.WriteSliceHash(payload)
	return hasher.Finish()
}

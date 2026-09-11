// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import "encoding/binary"

// GenerateDigestFromStrings reproduces EasyTier 2.6.4's
// generate_digest_from_str. Rust DefaultHasher is SipHash-1-3 with zero keys;
// the chained big-endian blocks are part of the on-wire identity contract.
func GenerateDigestFromStrings(first, second string) [32]byte {
	hasher := newSipHasher13()
	hasher.Write([]byte(first))
	hasher.Write([]byte(second))
	var digest [32]byte
	for index := 0; index < len(digest)/8; index++ {
		sum := hasher.Sum64()
		binary.BigEndian.PutUint64(digest[index*8:], sum)
		hasher.Write(digest[:(index+1)*8])
	}
	return digest
}

type sipHasher13 struct {
	v0, v1, v2, v3 uint64
	tail           uint64
	tailLength     uint
	length         uint64
}

func newSipHasher13() sipHasher13 {
	return sipHasher13{
		v0: 0x736f6d6570736575,
		v1: 0x646f72616e646f6d,
		v2: 0x6c7967656e657261,
		v3: 0x7465646279746573,
	}
}

func (h *sipHasher13) Write(data []byte) {
	h.length += uint64(len(data))
	for _, value := range data {
		h.tail |= uint64(value) << (8 * h.tailLength)
		h.tailLength++
		if h.tailLength == 8 {
			h.compress(h.tail)
			h.tail = 0
			h.tailLength = 0
		}
	}
}

func (h sipHasher13) Sum64() uint64 {
	last := h.tail | (h.length << 56)
	h.compress(last)
	h.v2 ^= 0xff
	for range 3 {
		h.round()
	}
	return h.v0 ^ h.v1 ^ h.v2 ^ h.v3
}

func (h *sipHasher13) compress(word uint64) {
	h.v3 ^= word
	h.round()
	h.v0 ^= word
}

func (h *sipHasher13) round() {
	h.v0 += h.v1
	h.v1 = (h.v1 << 13) | (h.v1 >> 51)
	h.v1 ^= h.v0
	h.v0 = (h.v0 << 32) | (h.v0 >> 32)
	h.v2 += h.v3
	h.v3 = (h.v3 << 16) | (h.v3 >> 48)
	h.v3 ^= h.v2
	h.v0 += h.v3
	h.v3 = (h.v3 << 21) | (h.v3 >> 43)
	h.v3 ^= h.v0
	h.v2 += h.v1
	h.v1 = (h.v1 << 17) | (h.v1 >> 47)
	h.v1 ^= h.v2
	h.v2 = (h.v2 << 32) | (h.v2 >> 32)
}

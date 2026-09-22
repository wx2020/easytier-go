// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"testing"
)

func TestVarintRoundTrip(t *testing.T) {
	testValues := []uint64{
		0, 1, 25, 63,
		64, 65, 100, 16383,
		16384, 16385, 1000000, 1073741823,
		1073741824, 1073741825, 1 << 40, MaxVarint,
	}

	for _, v := range testValues {
		b := AppendVarint(nil, v)
		if len(b) != VarintLen(v) {
			t.Fatalf("VarintLen mismatch for %d: len(b)=%d, VarintLen=%d", v, len(b), VarintLen(v))
		}
		decoded, n, err := ReadVarint(b)
		if err != nil {
			t.Fatalf("ReadVarint failed for %d: %v", v, err)
		}
		if n != len(b) {
			t.Fatalf("ReadVarint n mismatch for %d: got %d, want %d", v, n, len(b))
		}
		if decoded != v {
			t.Fatalf("decoded mismatch for %d: got %d", v, decoded)
		}
	}
}

func TestRFC9000AppendixA_PacketNumberDecode(t *testing.T) {
	// RFC 9000 Appendix A sample:
	// If largestAcked is 0xa82f30ea, and packet number is 0xa82f9b32 (diff is 0x6a48, fits in 16 bits),
	// truncated packet number is 0x9b32 (len=2), decoded must be 0xa82f9b32.
	largestAcked := uint64(0xa82f30ea)
	actualPN := uint64(0xa82f9b32)

	trunc, pnLen := EncodePacketNumber(actualPN, largestAcked)
	if pnLen != 2 {
		t.Fatalf("expected pnLen=2, got %d", pnLen)
	}
	if trunc != 0x9b32 {
		t.Fatalf("expected trunc=0x9b32, got 0x%x", trunc)
	}

	decoded := DecodePacketNumber(trunc, pnLen, largestAcked)
	if decoded != actualPN {
		t.Fatalf("DecodePacketNumber got 0x%x, want 0x%x", decoded, actualPN)
	}
}

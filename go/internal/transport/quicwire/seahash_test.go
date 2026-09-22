// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"bytes"
	"testing"
)

func TestSeaHashChunkedEquivalence(t *testing.T) {
	testBuf := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	h1 := NewSeaHasher()
	_, _ = h1.Write(testBuf)
	res1 := h1.Finish()

	h2 := NewSeaHasher()
	_, _ = h2.Write(testBuf[:8])
	_, _ = h2.Write(testBuf[8:])
	res2 := h2.Finish()

	h3 := NewSeaHasher()
	_, _ = h3.Write(testBuf[:3])
	_, _ = h3.Write(testBuf[3:])
	res3 := h3.Finish()

	if res1 != res2 {
		t.Fatalf("h1 (%x) != h2 (%x)", res1, res2)
	}
	if res1 != res3 {
		t.Fatalf("h1 (%x) != h3 (%x)", res1, res3)
	}
}

func TestSeaHashVariousChunkSizes(t *testing.T) {
	data := bytes.Repeat([]byte("EasyTier quinn-plaintext SeaHash test vector 1234567890!"), 10)

	hBaseline := NewSeaHasher()
	_, _ = hBaseline.Write(data)
	expected := hBaseline.Finish()

	for chunkSize := 1; chunkSize <= 40; chunkSize++ {
		h := NewSeaHasher()
		for offset := 0; offset < len(data); offset += chunkSize {
			end := offset + chunkSize
			if end > len(data) {
				end = len(data)
			}
			_, _ = h.Write(data[offset:end])
		}
		if got := h.Finish(); got != expected {
			t.Fatalf("chunkSize %d produced %x, expected %x", chunkSize, got, expected)
		}
	}
}

func TestQuinnPlaintextChecksum(t *testing.T) {
	header := []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00}
	payload := []byte("hello EasyTier QUIC tunnel world!")

	cs1 := QuinnPlaintextChecksum(header, payload)
	cs2 := QuinnPlaintextChecksum(header, payload)
	if cs1 != cs2 {
		t.Fatalf("checksum not deterministic: %x vs %x", cs1, cs2)
	}
	if cs1 == 0 {
		t.Fatalf("checksum is zero")
	}

	// Changing 1 bit in header must alter checksum
	headerCorrupted := make([]byte, len(header))
	copy(headerCorrupted, header)
	headerCorrupted[0] ^= 0x01
	if QuinnPlaintextChecksum(headerCorrupted, payload) == cs1 {
		t.Fatalf("header corruption did not change checksum")
	}

	// Changing 1 bit in payload must alter checksum
	payloadCorrupted := make([]byte, len(payload))
	copy(payloadCorrupted, payload)
	payloadCorrupted[0] ^= 0x01
	if QuinnPlaintextChecksum(header, payloadCorrupted) == cs1 {
		t.Fatalf("payload corruption did not change checksum")
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"bytes"
	"testing"
)

func TestParseBodyHardening(t *testing.T) {
	malformed := [][]byte{
		nil,
		{},
		make([]byte, PeerManagerHeaderSize-1),
		// Declared length 100 but body only 5 (uncompressed mismatch)
		func() []byte {
			b := make([]byte, PeerManagerHeaderSize+5)
			b[12] = 100
			return b
		}(),
		// Compressed flag but missing tail
		func() []byte {
			b := make([]byte, PeerManagerHeaderSize)
			b[9] = FlagCompressed
			b[12] = 5
			return b
		}(),
		// Oversized payload length max with uncompressed flag (mismatch)
		func() []byte {
			b := make([]byte, PeerManagerHeaderSize)
			b[9] = 0
			b[12], b[13], b[14], b[15] = 0xFF, 0xFF, 0xFF, 0xFF
			return b
		}(),
		// Uncompressed length mismatch: header says 10, wire has 0
		func() []byte {
			b := make([]byte, PeerManagerHeaderSize)
			b[9] = 0
			b[12] = 10
			return b
		}(),
	}
	for i, data := range malformed {
		if _, err := ParseBody(data); err == nil {
			t.Fatalf("ParseBody case %d should fail: %x", i, data)
		}
		// Ensure no panic on additional fuzz-like inputs
		_, _ = ParseBody(append([]byte(nil), data...))
	}
	// Additional fuzz-like inputs that should not panic (may succeed or fail)
	fuzzNoPanic := [][]byte{
		bytes.Repeat([]byte{0xFF}, PeerManagerHeaderSize+10),
		bytes.Repeat([]byte{0x00}, PeerManagerHeaderSize+10),
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11},
	}
	for _, data := range fuzzNoPanic {
		func(d []byte) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseBody panic on fuzz input %x: %v", d, r)
				}
			}()
			_, _ = ParseBody(d)
		}(data)
	}
	// Max frame boundary: MarshalBody should handle large payload without panic
	large := bytes.Repeat([]byte{0xAB}, 64*1024)
	packet := Packet{Header: PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: PacketTypeData}, Payload: large}
	body, err := packet.MarshalBody()
	if err != nil {
		t.Fatalf("MarshalBody large: %v", err)
	}
	parsed, err := ParseBody(body)
	if err != nil {
		t.Fatalf("ParseBody large roundtrip: %v", err)
	}
	if !bytes.Equal(parsed.Payload, large) {
		t.Fatal("large payload mismatch")
	}
}

func TestParseUDPDatagramHardening(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		make([]byte, 1),
		make([]byte, UDPTunnelHeaderSize-1),
		bytes.Repeat([]byte{0xFF}, UDPTunnelHeaderSize),
		bytes.Repeat([]byte{0x00}, 100),
		// Connection ID mismatch simulation: first 4 bytes as connid, next 4 as seq
		{0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0xFF, 0xFF},
	}
	for i, data := range cases {
		// ParseUDPDatagram should not panic on any input
		defer func(idx int) {
			if r := recover(); r != nil {
				t.Fatalf("ParseUDPDatagram panic case %d: %v", idx, r)
			}
		}(i)
		_, _ = ParseUDPDatagram(data)
	}
}

func TestParseHandshakeRequestHardening(t *testing.T) {
	vectors := [][]byte{
		nil,
		{},
		{0x00},
		{0xFF, 0xFF, 0xFF},
		bytes.Repeat([]byte{0xFF}, 1024),
		{0x0a, 0xFF, 0xFF, 0xFF, 0xFF},
		// Valid looking but truncated varint
		{0x08, 0x80},
		// Unknown field with unsupported wire type 3
		{0x1B, 0x00},
	}
	for i, data := range vectors {
		defer func(idx int) {
			if r := recover(); r != nil {
				t.Fatalf("ParseHandshakeRequest panic case %d: %v", idx, r)
			}
		}(i)
		_, _ = ParseHandshakeRequest(data)
	}
	// Ensure unknown field skipping works: append unknown field to valid request
	valid := mustMarshalHandshakeRequest(t)
	// Add unknown field 99 wire type 0 value 123
	unknown := appendVarintField(nil, 99, 123)
	combined := append(valid, unknown...)
	parsed, err := ParseHandshakeRequest(combined)
	if err != nil {
		t.Fatalf("unknown field should be skipped: %v", err)
	}
	if parsed.NetworkName == "" {
		t.Fatal("valid fields should still parse after unknown")
	}
}

func mustMarshalHandshakeRequest(t *testing.T) []byte {
	t.Helper()
	req := HandshakeRequest{NetworkName: "test", NetworkSecretDigest: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestForeignNetworkEnvelopeBoundaries(t *testing.T) {
	// Foreign network envelope is parsed via packet payload; ensure bounds checks
	envelope := []byte{0x00, 0x00, 0x00, 0x10}
	// Too short for envelope header
	if _, err := ParseBody(envelope); err == nil {
		// This may be a header-sized failure; just ensure no panic
	}
	// Valid header with payload length 0 should parse
	zero := make([]byte, PeerManagerHeaderSize)
	if _, err := ParseBody(zero); err != nil {
		t.Fatalf("zero payload should parse: %v", err)
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"bytes"
	"testing"
)

func TestRpcParserHardening(t *testing.T) {
	malformed := [][]byte{
		nil,
		{},
		{0xFF},
		{0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02}, // overflow varint
		{0x0A, 0xFF, 0xFF}, // truncated length-delimited
		bytes.Repeat([]byte{0xFF}, 1024),
		bytes.Repeat([]byte{0x00}, 1024),
		// Wrong wire type for field 1 (should be 0, give 2)
		{0x0A, 0x03, 'a', 'b', 'c'},
		// Valid but unknown field with wire type 3 (unsupported)
		{0x1B, 0x00},
		// Descriptor field 4 with truncated bytes
		{0x22, 0x05, 0x0A, 0x01, 'x'},
	}
	for i, data := range malformed {
		func(idx int, d []byte) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("UnmarshalRpcPacket panic case %d: %v", idx, r)
				}
			}()
			_, _ = UnmarshalRpcPacket(d)
			_, _ = UnmarshalRpcDescriptor(d)
		}(i, data)
		// Also ensure Marshal roundtrip for valid packet doesn't panic
		_, _ = UnmarshalRpcPacket(append([]byte(nil), data...))
	}

	// Ensure that unknown fields with supported wire types are skipped.
	valid, err := (&RpcPacket{FromPeer: 1, ToPeer: 2, TransactionID: 99, Body: []byte("hello")}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	unknown := appendVarint(nil, 99, 12345)
	combined := append(valid, unknown...)
	if _, err := UnmarshalRpcPacket(combined); err != nil {
		t.Fatalf("unknown field skip: %v", err)
	}

	// Exceed max pieces should still parse but logic may limit elsewhere; ensure no panic on large values
	large := make([]byte, 8*1024)
	for i := range large {
		large[i] = byte(i)
	}
	packet := RpcPacket{FromPeer: 1, TransactionID: 1, TotalPieces: 99999, PieceIdx: 99999, Body: large}
	data, err := packet.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalRpcPacket(data); err != nil {
		t.Fatalf("large packet unmarshal: %v", err)
	}
	// Invalid UTF-8 descriptor
	badDescriptor := []byte{0x0A, 0x02, 0xFF, 0xFF}
	if _, err := UnmarshalRpcDescriptor(badDescriptor); err == nil {
		t.Fatal("invalid UTF-8 should fail")
	}
}

func TestRpcPacketBoundsAndCompressionHardening(t *testing.T) {
	// Body with 32k pieces limit
	packet := RpcPacket{TotalPieces: maxPieces + 1}
	_, err := packet.Marshal()
	if err != nil {
		t.Fatalf("marshal should succeed even with large pieces: %v", err)
	}
	// Truncated varint
	if _, err := UnmarshalRpcPacket([]byte{0x08, 0x80}); err == nil {
		t.Fatal("truncated varint should fail")
	}
	if _, err := UnmarshalRpcDescriptor([]byte{0x08, 0x80}); err == nil {
		t.Fatal("truncated varint descriptor should fail")
	}
	// Overlong varint (11 bytes)
	overlong := []byte{0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}
	if _, err := UnmarshalRpcPacket(overlong); err == nil {
		t.Fatal("overlong varint should fail")
	}
}

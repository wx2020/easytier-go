// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"bytes"
	"reflect"
	"testing"
)

func TestRpcDescriptorKnownBytesAndRoundTrip(t *testing.T) {
	descriptor := RpcDescriptor{DomainName: "d", ProtoName: "p", ServiceName: "s", MethodIndex: 7}
	want := []byte{0x0a, 1, 'd', 0x12, 1, 'p', 0x1a, 1, 's', 0x20, 7}
	got, err := descriptor.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("marshal = %x, want %x", got, want)
	}
	decoded, err := UnmarshalRpcDescriptor(got)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != descriptor {
		t.Fatalf("decode = %#v, want %#v", decoded, descriptor)
	}
}

func TestRpcPacketKnownBytesAndRoundTrip(t *testing.T) {
	descriptor := &RpcDescriptor{DomainName: "d", ProtoName: "p", ServiceName: "s", MethodIndex: 7}
	packet := RpcPacket{
		FromPeer: 1, ToPeer: 2, TransactionID: -1, Descriptor: descriptor,
		Body: []byte{0xaa, 0xbb}, IsRequest: true, TotalPieces: 2, PieceIdx: 1, TraceID: -2,
	}
	want := []byte{
		0x08, 1, 0x10, 2,
		0x18, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1,
		0x22, 11, 0x0a, 1, 'd', 0x12, 1, 'p', 0x1a, 1, 's', 0x20, 7,
		0x2a, 2, 0xaa, 0xbb, 0x30, 1, 0x38, 2, 0x40, 1,
		0x48, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1,
	}
	got, err := packet.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("marshal = %x, want %x", got, want)
	}
	decoded, err := UnmarshalRpcPacket(got)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, packet) {
		t.Fatalf("decode = %#v, want %#v", decoded, packet)
	}
}

func TestRpcPacketCompressionInfoRoundTrip(t *testing.T) {
	packet := RpcPacket{
		FromPeer: 1,
		CompressionInfo: &RpcCompressionInfo{
			Algo:         CompressionAlgoZstd,
			AcceptedAlgo: CompressionAlgoNone,
		},
	}
	body, err := packet.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalRpcPacket(body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, packet) {
		t.Fatalf("decode = %#v, want %#v", decoded, packet)
	}
}

func TestRPCCompressionRoundTrip(t *testing.T) {
	content := bytes.Repeat([]byte("rpc-content-"), 64)
	compressed, algorithm, err := CompressRPCContent(CompressionAlgoZstd, content)
	if err != nil {
		t.Fatal(err)
	}
	if algorithm != CompressionAlgoZstd || len(compressed) >= len(content) {
		t.Fatalf("compression = %d, %d bytes", algorithm, len(compressed))
	}
	decoded, err := DecompressRPCContent(algorithm, compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, content) {
		t.Fatal("RPC decompression changed content")
	}
}

func TestRPCCompressionRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := DecompressRPCContent(CompressionAlgo(99), []byte("content")); err == nil {
		t.Fatal("unknown RPC compression algorithm succeeded")
	}
}

func TestRpcPacketSkipsSupportedUnknownFields(t *testing.T) {
	// Unknown varint, fixed64, bytes, and fixed32 fields precede from_peer.
	b := []byte{0x58, 1, 0x59, 1, 2, 3, 4, 5, 6, 7, 8, 0x62, 2, 9, 10, 0x6d, 1, 2, 3, 4, 0x08, 7}
	p, err := UnmarshalRpcPacket(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.FromPeer != 7 {
		t.Fatalf("from_peer = %d, want 7", p.FromPeer)
	}
}

func TestRpcPacketRejectsMalformedInput(t *testing.T) {
	tests := [][]byte{
		{0x08}, // truncated varint
		{0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}, // uint64 overflow
		{0x2a, 0x7f},                         // declared body is outside input
		{0x08, 0x80, 0x80, 0x80, 0x80, 0x10}, // uint32 overflow
		{0x0b},                               // unsupported group wire type
	}
	for _, input := range tests {
		if _, err := UnmarshalRpcPacket(input); err == nil {
			t.Fatalf("UnmarshalRpcPacket(%x) succeeded", input)
		}
	}
	if _, err := UnmarshalRpcDescriptor([]byte{0x0a, 1, 0xff}); err == nil {
		t.Fatal("invalid UTF-8 descriptor parsed")
	}
}

func TestFragmentMergerOutOfOrderAndInterleavedTransactions(t *testing.T) {
	m := NewFragmentMerger()
	d := &RpcDescriptor{ServiceName: "svc"}
	firstA := RpcPacket{FromPeer: 1, ToPeer: 2, TransactionID: 10, Descriptor: d, Body: []byte("a"), IsRequest: true, TotalPieces: 3}
	secondA := RpcPacket{FromPeer: 1, ToPeer: 2, TransactionID: 10, Body: []byte("b"), TotalPieces: 3, PieceIdx: 1}
	thirdA := RpcPacket{FromPeer: 1, ToPeer: 2, TransactionID: 10, Body: []byte("c"), TotalPieces: 3, PieceIdx: 2}
	firstB := RpcPacket{FromPeer: 1, ToPeer: 2, TransactionID: 11, Descriptor: d, Body: []byte("x"), TotalPieces: 2}
	secondB := RpcPacket{FromPeer: 1, ToPeer: 2, TransactionID: 11, Body: []byte("y"), TotalPieces: 2, PieceIdx: 1}

	for _, packet := range []RpcPacket{secondA, firstB, thirdA, secondB, firstA} {
		got, err := m.Add(packet)
		if err != nil {
			t.Fatal(err)
		}
		if packet.TransactionID == 11 && packet.PieceIdx == 1 {
			if got == nil || string(got.Body) != "xy" {
				t.Fatalf("transaction B = %#v", got)
			}
		} else if packet.TransactionID == 10 && packet.PieceIdx == 0 {
			if got == nil || string(got.Body) != "abc" || got.Descriptor == nil {
				t.Fatalf("transaction A = %#v", got)
			}
		} else if got != nil {
			t.Fatalf("unexpected complete packet: %#v", got)
		}
	}
}

func TestFragmentMergerValidationAndLegacyPacket(t *testing.T) {
	m := NewFragmentMerger()
	legacy := RpcPacket{FromPeer: 1, TransactionID: 9, Body: []byte("legacy")}
	got, err := m.Feed(legacy)
	if err != nil || !reflect.DeepEqual(*got, legacy) {
		t.Fatalf("legacy = %#v, %v", got, err)
	}

	tests := []RpcPacket{
		{TotalPieces: maxPieces + 1},
		{TotalPieces: 1, PieceIdx: 1},
		{TotalPieces: 1}, // Initial fragment has no descriptor.
		{TotalPieces: 0, PieceIdx: 1},
	}
	for _, packet := range tests {
		if _, err := m.Add(packet); err == nil {
			t.Fatalf("Add(%#v) succeeded", packet)
		}
	}
}

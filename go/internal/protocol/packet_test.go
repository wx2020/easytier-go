// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"bytes"
	"testing"
)

func TestPeerPacketRoundTripMatchesLittleEndianWireLayout(t *testing.T) {
	packet := Packet{
		Header: PeerManagerHeader{
			FromPeerID:     0x11223344,
			ToPeerID:       0x55667788,
			PacketType:     PacketTypeData,
			Flags:          FlagEncrypted | FlagCompressed,
			ForwardCounter: 7,
			Length:         3,
		},
		Payload: []byte{0xaa, 0xbb, 0xcc},
	}

	body, err := packet.MarshalBody()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55,
		PacketTypeData, FlagEncrypted | FlagCompressed, 7, 0,
		3, 0, 0, 0, 0xaa, 0xbb, 0xcc,
	}
	if !bytes.Equal(body, want) {
		t.Fatalf("wire body = %x, want %x", body, want)
	}

	got, err := ParseBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header != (PeerManagerHeader{0x11223344, 0x55667788, PacketTypeData, FlagEncrypted | FlagCompressed, 7, 3}) {
		t.Fatalf("header = %#v", got.Header)
	}
	if !bytes.Equal(got.Payload, packet.Payload) {
		t.Fatalf("payload = %x, want %x", got.Payload, packet.Payload)
	}
}

func TestParseBodyRejectsMismatchedPayloadLength(t *testing.T) {
	_, err := ParseBody(make([]byte, PeerManagerHeaderSize))
	if err != nil {
		t.Fatalf("zero payload header should parse: %v", err)
	}

	body := make([]byte, PeerManagerHeaderSize)
	body[12] = 1
	if _, err := ParseBody(body); err == nil {
		t.Fatal("expected mismatched payload length error")
	}
}

func TestCompressedPeerPacketPreservesOriginalLength(t *testing.T) {
	packet := Packet{
		Header:  PeerManagerHeader{PacketType: PacketTypeData},
		Payload: bytes.Repeat([]byte("compressible-"), 32),
	}
	original := append([]byte(nil), packet.Payload...)
	if err := CompressPacket(&packet, CompressionZstd); err != nil {
		t.Fatal(err)
	}
	if !packet.Header.IsCompressed() {
		t.Fatal("packet was not compressed")
	}
	if packet.Header.Length != uint32(len(original)) {
		t.Fatalf("header length = %d, want %d", packet.Header.Length, len(original))
	}

	body, err := packet.MarshalBody()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Payload) >= int(parsed.Header.Length) {
		t.Fatalf("wire payload length = %d, original length = %d", len(parsed.Payload), parsed.Header.Length)
	}
	if err := DecompressPacket(&parsed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Payload, original) || parsed.Header.IsCompressed() || parsed.Header.Length != uint32(len(original)) {
		t.Fatalf("decompressed packet = %#v", parsed)
	}
}

func TestCompressedPeerPacketRejectsUnknownAlgorithm(t *testing.T) {
	packet := Packet{
		Header:  PeerManagerHeader{PacketType: PacketTypeData, Flags: FlagCompressed, Length: 1},
		Payload: []byte{0x01, 0xff},
	}
	if err := DecompressPacket(&packet); err == nil {
		t.Fatal("unknown compression algorithm succeeded")
	}
}

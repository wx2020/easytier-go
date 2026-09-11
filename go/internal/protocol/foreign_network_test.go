// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"bytes"
	"testing"
)

func TestForeignNetworkPacketRoundTrip(t *testing.T) {
	packet := ForeignNetworkPacket{
		DestinationPeerID: 0x11223344,
		NetworkName:       "shared.et.net",
		NestedPacket: Packet{
			Header:  PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: PacketTypeData},
			Payload: []byte{0xaa},
		},
	}
	data, err := packet.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data[:10], []byte{23, 0, 0x44, 0x33, 0x22, 0x11, 10, 0, 13, 0}) {
		t.Fatalf("foreign header = %x", data[:10])
	}

	decoded, err := ParseForeignNetworkPacket(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.DestinationPeerID != packet.DestinationPeerID || decoded.NetworkName != packet.NetworkName {
		t.Fatalf("decoded = %#v", decoded)
	}
	if decoded.NestedPacket.Header.PacketType != PacketTypeData || !bytes.Equal(decoded.NestedPacket.Payload, []byte{0xaa}) {
		t.Fatalf("nested packet = %#v", decoded.NestedPacket)
	}
}

func TestForeignNetworkPacketRejectsInvalidRanges(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		make([]byte, 9),
		{10, 0, 0, 0, 0, 0, 10, 0, 1, 0},
		{9, 0, 0, 0, 0, 0, 10, 0, 0, 0},
	} {
		if _, err := ParseForeignNetworkPacket(data); err == nil {
			t.Fatalf("ParseForeignNetworkPacket(%x) succeeded", data)
		}
	}
}

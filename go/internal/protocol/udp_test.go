// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"bytes"
	"testing"
)

func TestUDPDatagramRoundTripMatchesRustLayout(t *testing.T) {
	datagram := UDPDatagram{
		Header:  UDPTunnelHeader{ConnectionID: 0x11223344, MessageType: UDPPacketTypeData},
		Payload: []byte{0xaa, 0xbb},
	}
	got, err := datagram.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x44, 0x33, 0x22, 0x11, UDPPacketTypeData, 0, 2, 0, 0xaa, 0xbb}
	if !bytes.Equal(got, want) {
		t.Fatalf("datagram = %x, want %x", got, want)
	}

	decoded, err := ParseUDPDatagram(got)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header.ConnectionID != datagram.Header.ConnectionID || decoded.Header.MessageType != UDPPacketTypeData {
		t.Fatalf("header = %#v", decoded.Header)
	}
	if !bytes.Equal(decoded.Payload, datagram.Payload) {
		t.Fatalf("payload = %x", decoded.Payload)
	}
}

func TestUDPDatagramRejectsInvalidLength(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		make([]byte, 7),
		{0, 0, 0, 0, UDPPacketTypeData, 0, 1, 0},
	} {
		if _, err := ParseUDPDatagram(data); err == nil {
			t.Fatalf("ParseUDPDatagram(%x) succeeded", data)
		}
	}
}

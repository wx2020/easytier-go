// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gateway

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestIpReassembler(t *testing.T) {
	// last fragment (no MF flag), id 0x1c46, offset 0x0200
	lastFragment := []byte{
		0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x20, 0x01, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
		0x04, 0x05, 0x06, 0x07, 0x04, 0x05, 0x06, 0x07,
	}
	// first fragment, offset 0, MF set
	firstFragment := []byte{
		0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x00, 0x02, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	}
	// middle fragment, offset 8, MF set
	secondFragment := []byte{
		0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x20, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
		0x08, 0x09, 0x0a, 0x0b, 0x04, 0x05, 0x06, 0x07,
	}
	// expired fragment with a different id
	expiredFragment := []byte{
		0x45, 0x00, 0x00, 0x1c, 0x1c, 0x47, 0x20, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	}

	source := net.IPv4(192, 168, 0, 1)
	destination := net.IPv4(192, 168, 0, 2)

	reassembler := NewIPReassembler(time.Second)

	fragments := [][]byte{lastFragment, firstFragment, secondFragment, expiredFragment}
	for idx, fragment := range fragments {
		got := reassembler.AddFragment(source, destination, fragment)
		if idx < 2 {
			if got != nil {
				t.Fatalf("fragment %d: expected no assembly, got %d bytes", idx, len(got))
			}
		} else if idx == 2 {
			if got == nil {
				t.Fatalf("fragment %d: expected assembled packet", idx)
			}
			if want := 24; len(got) != want {
				t.Fatalf("assembled length = %d, want %d", len(got), want)
			}
		} else {
			if got != nil {
				t.Fatalf("fragment %d with different id should not assemble", idx)
			}
		}
	}

	// The third fragment assembled the packet, the expired one is still pending.
	reassembler.RemoveExpiredPackets()
	if got, want := len(reassembler.packets), 1; got != want {
		t.Fatalf("pending packets = %d, want %d", got, want)
	}

	time.Sleep(2 * time.Second)
	reassembler.RemoveExpiredPackets()
	if got, want := len(reassembler.packets), 0; got != want {
		t.Fatalf("pending packets after expiry = %d, want %d", got, want)
	}
}

func TestComposeIPv4PacketFragmentsAndChecksum(t *testing.T) {
	payload := make([]byte, 1300)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)

	var packets [][]byte
	err := ComposeIPv4Packet(src, dst, 1, payload, 1200, 0xabcd, func(buf []byte) error {
		packets = append(packets, append([]byte(nil), buf...))
		return nil
	})
	if err != nil {
		t.Fatalf("ComposeIPv4Packet: %v", err)
	}
	if got, want := len(packets), 2; got != want {
		t.Fatalf("fragment count = %d, want %d", got, want)
	}

	// Verify header checksums of each fragment by zeroing the checksum field
	// before recomputing, as required by RFC 1071.
	for i, pkt := range packets {
		stored := binary.BigEndian.Uint16(pkt[10:12])
		header := append([]byte(nil), pkt[:20]...)
		header[10], header[11] = 0, 0
		if computed := ipv4Checksum(header); stored != computed {
			t.Fatalf("fragment %d checksum mismatch: stored %#04x computed %#04x", i, stored, computed)
		}
	}

	// Verify first fragment has MF flag and offset 0.
	flagsOffset := binary.BigEndian.Uint16(packets[0][6:8])
	if flagsOffset&ipv4FlagMF == 0 {
		t.Fatalf("first fragment should have MF flag")
	}
	if flagsOffset&ipv4FragOffsetMask != 0 {
		t.Fatalf("first fragment should have offset 0, got %d", flagsOffset&ipv4FragOffsetMask)
	}

	// Last fragment has no MF but non-zero offset.
	flagsOffset = binary.BigEndian.Uint16(packets[1][6:8])
	if flagsOffset&ipv4FlagMF != 0 {
		t.Fatalf("last fragment should not have MF flag")
	}
	if got, want := flagsOffset&ipv4FragOffsetMask, uint16(1200/8); got != want {
		t.Fatalf("last fragment offset = %d, want %d", got, want)
	}
}
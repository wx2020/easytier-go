// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package smoltcp

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestTCPChecksumKnownVector(t *testing.T) {
	src := net.IPv4(192, 168, 0, 1)
	dst := net.IPv4(192, 168, 0, 2)

	// A minimal TCP segment: SYN-ACK with zero checksum field.
	segment := buildTCPPacket(1234, 80, 100, 200, TCPFlagSyn|TCPFlagAck, 8192, []byte{1, 2, 3})
	segment[16], segment[17] = 0, 0

	checksum := tcpChecksum(src, dst, segment)
	if checksum == 0 {
		t.Fatalf("TCP checksum computed to zero")
	}

	// Writing it back and re-checking yields the stored value, so the receiver
	// sees a zero folded sum.
	recheck := tcpChecksum(src, dst, func() []byte {
		filled := append([]byte(nil), segment...)
		binary.BigEndian.PutUint16(filled[16:18], checksum)
		return filled
	}())
	if recheck != checksum {
		t.Fatalf("recomputed checksum %#04x does not match stored %#04x", recheck, checksum)
	}
}

func TestTCPChecksumIncludesPseudoHeader(t *testing.T) {
	// One's-complement checksums are additive, so swapping src and dst leaves
	// the same byte multisets and the same result (checksums are symmetric).
	// Changing a pseudo-header byte, however, must change the folded checksum.
	base := buildTCPPacket(5000, 80, 1, 1, TCPFlagAck, 8192, nil)

	sumA := tcpChecksum(net.IPv4(198, 51, 100, 1), net.IPv4(10, 0, 0, 1), base)
	sumB := tcpChecksum(net.IPv4(198, 51, 100, 2), net.IPv4(10, 0, 0, 1), base)
	if sumA == sumB {
		t.Fatalf("pseudo-header byte must change the checksum: %#04x == %#04x", sumA, sumB)
	}

	if tcpChecksum(net.IPv4(198, 51, 100, 1), net.IPv4(10, 0, 0, 1), base) !=
		tcpChecksum(net.IPv4(10, 0, 0, 1), net.IPv4(198, 51, 100, 1), base) {
		t.Fatalf("checksum must be symmetric for swapped pseudo-header multisets")
	}
}

func TestUDPChecksumKnownVector(t *testing.T) {
	src := net.IPv4(192, 168, 0, 1)
	dst := net.IPv4(192, 168, 0, 2)
	datagram := buildUDPPacket(1234, 53, []byte("example"))
	checksum := udpChecksum(src, dst, datagram)
	if checksum == 0 {
		t.Fatalf("UDP checksum computed to zero")
	}
}

func TestBuildIPv4FillsTCPChecksum(t *testing.T) {
	src := net.IPv4(10, 1, 1, 1)
	dst := net.IPv4(10, 1, 1, 2)
	segment := buildTCPPacket(4321, 22, 0, 0, TCPFlagSyn, 8192, nil)
	pkt := buildIPv4Packet(src, dst, 6, segment)
	if len(pkt) != 20+len(segment) {
		t.Fatalf("packet length = %d, want %d", len(pkt), 20+len(segment))
	}
	stored := binary.BigEndian.Uint16(pkt[20+16 : 20+18])
	if stored == 0 {
		t.Fatalf("TCP checksum field in the IP packet is zero")
	}
	// The stored checksum must be the one computed for the TCP segment.
	if stored != tcpChecksum(src, dst, pkt[20:]) {
		t.Fatalf("stored %#04x != computed %#04x", stored, tcpChecksum(src, dst, pkt[20:]))
	}
}
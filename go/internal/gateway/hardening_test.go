// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gateway

import (
	"bytes"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/acl"
)

func TestGatewayParserHardening(t *testing.T) {
	malformed := [][]byte{
		nil,
		{},
		{0x00},
		{0x40}, // version 4 but truncated
		// IPv4 with invalid IHL
		{0x44, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 0, 2, 1, 192, 0, 2, 2},
		// IPv4 with fragment offset
		func() []byte {
			b := makeIPv4Packet("10.0.0.1", "10.0.0.2", 6, []byte{0x00, 0x50, 0x01, 0xBB})
			b[6] = 0x20 // More fragments
			return b
		}(),
		bytes.Repeat([]byte{0xFF}, 100),
		bytes.Repeat([]byte{0x00}, 100),
		// IPv6 with invalid payload length
		func() []byte {
			b := make([]byte, 40)
			b[0] = 0x60
			b[4], b[5] = 0xFF, 0xFF
			return b
		}(),
		// IPv6 with fragment header (next header 44)
		func() []byte {
			b := make([]byte, 40)
			b[0] = 0x60
			b[6] = 44
			return b
		}(),
	}
	for i, data := range malformed {
		func(idx int, d []byte) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParsePacket panic case %d: %v", idx, r)
				}
			}()
			_, _ = ParsePacket(d)
			_, _ = ParsePacket(d, acl.DirectionInbound)
		}(i, data)
		// Ensure no allocation panic on truncated
		_, _ = ParsePacket(append([]byte(nil), data...))
	}
	// Valid packets should still parse
	validV4 := makeIPv4Packet("192.0.2.1", "192.0.2.2", 6, []byte{0x00, 0x50, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00})
	if _, err := ParsePacket(validV4); err != nil {
		t.Fatalf("valid IPv4 failed: %v", err)
	}
	validV6 := makeIPv6Packet("2001:db8::1", "2001:db8::2", 6, []byte{0x00, 0x50, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00})
	if _, err := ParsePacket(validV6); err != nil {
		t.Fatalf("valid IPv6 failed: %v", err)
	}
	// Invalid direction should be rejected
	if _, err := ParsePacket(validV4, 99); err == nil {
		t.Fatal("invalid direction should fail")
	}
	if _, err := ParsePacket(validV4, acl.DirectionInbound, acl.DirectionOutbound); err == nil {
		t.Fatal("multiple directions should fail")
	}
	// Unsupported protocol
	badProto := makeIPv4Packet("10.0.0.1", "10.0.0.2", 99, nil)
	if _, err := ParsePacket(badProto); err == nil {
		t.Fatal("unsupported protocol should fail")
	}
}

func TestGatewayParserBoundaryHardening(t *testing.T) {
	// Extension header loop limit: 8 headers should be enforced
	data := make([]byte, 40+8*8)
	data[0] = 0x60
	// payload length = 8*8
	data[4], data[5] = byte((8*8)>>8), byte(8*8)
	data[6] = 0 // Hop-by-Hop
	for i := 0; i < 8; i++ {
		off := 40 + i*8
		data[off] = 0 // next header Hop-by-Hop for first 7, last will be TCP
		if i == 7 {
			data[off] = 6
		}
		data[off+1] = 0 // length 0 => 8 bytes
	}
	if _, err := ParsePacket(data); err == nil {
		t.Fatal("8 extension headers should be rejected (limit is 8)")
	}
}

func makeIPv4Packet(src, dst string, proto uint8, payload []byte) []byte {
	// Minimal IPv4 header 20 bytes + payload
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	total := 20 + len(payload)
	hdr[2], hdr[3] = byte(total>>8), byte(total)
	hdr[8] = 64
	hdr[9] = proto
	ipSrc := bytesToAddr4(src)
	ipDst := bytesToAddr4(dst)
	copy(hdr[12:16], ipSrc)
	copy(hdr[16:20], ipDst)
	return append(hdr, payload...)
}

func makeIPv6Packet(src, dst string, nextHeader uint8, payload []byte) []byte {
	hdr := make([]byte, 40)
	hdr[0] = 0x60
	payloadLen := len(payload)
	hdr[4], hdr[5] = byte(payloadLen>>8), byte(payloadLen)
	hdr[6] = nextHeader
	hdr[7] = 64
	copy(hdr[8:24], bytesToAddr16(src))
	copy(hdr[24:40], bytesToAddr16(dst))
	return append(hdr, payload...)
}

func bytesToAddr4(s string) []byte {
	// parse simple dotted quad
	var b [4]byte
	var a, b2, c, d int
	_, _ = bytesSscanf(s, "%d.%d.%d.%d", &a, &b2, &c, &d)
	b[0], b[1], b[2], b[3] = byte(a), byte(b2), byte(c), byte(d)
	return b[:]
}

func bytesToAddr16(s string) []byte {
	// Use netip for simplicity if parsing fails fallback to zero
	// Avoid import cycle: parse manually for test helper
	b := make([]byte, 16)
	// For tests we use known addresses like 2001:db8::1, parse manually simple
	if s == "2001:db8::1" {
		b[0], b[1] = 0x20, 0x01
		b[2], b[3] = 0x0d, 0xb8
		b[15] = 1
	} else if s == "2001:db8::2" {
		b[0], b[1] = 0x20, 0x01
		b[2], b[3] = 0x0d, 0xb8
		b[15] = 2
	}
	return b
}

func bytesSscanf(s, format string, args ...interface{}) (int, error) {
	// Minimal sscanf for dotted quad
	var n int
	_, err := bytesSscanfImpl(s, args...)
	return n, err
}

func bytesSscanfImpl(s string, args ...interface{}) (int, error) {
	// Simplistic: expect 4 ints
	if len(args) != 4 {
		return 0, nil
	}
	parts := bytes.Split([]byte(s), []byte{'.'})
	if len(parts) != 4 {
		return 0, nil
	}
	for i, p := range parts {
		var v int
		for _, c := range p {
			v = v*10 + int(c-'0')
		}
		switch i {
		case 0:
			*args[0].(*int) = v
		case 1:
			*args[1].(*int) = v
		case 2:
			*args[2].(*int) = v
		case 3:
			*args[3].(*int) = v
		}
	}
	return 4, nil
}

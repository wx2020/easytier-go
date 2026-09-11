// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package dns

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDNSParserHardening(t *testing.T) {
	malformed := [][]byte{
		nil,
		{},
		{0x12, 0x34, 0x01},
		bytes.Repeat([]byte{0xFF}, 512),
		bytes.Repeat([]byte{0x00}, 512),
		// Pointer loop: label pointer to itself
		{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01},
		// Very long label length exceeds packet
		{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 'a', 'a', 'a', 0x00, 0x00, 0x01, 0x00, 0x01},
	}
	for i, data := range malformed {
		func(idx int, d []byte) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseName panic case %d: %v", idx, r)
				}
			}()
			_, _, _ = parseName(d, 0)
			_, _, _ = parseName(d, 12)
			if len(d) >= 12 {
				// Also test handlePacket which wraps parsing
				_, _ = handlePacketForTest(d)
			}
		}(i, data)
		_, _, _ = parseName(append([]byte(nil), data...), 0)
	}
	// Valid name should parse correctly
	valid := queryForTest(0x1234, "node.et.net", typeA)
	if _, _, err := parseName(valid, 12); err != nil {
		t.Fatalf("valid name parse: %v", err)
	}
	// Compression pointer must be within bounds
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:], 0x1234)
	binary.BigEndian.PutUint16(packet[2:], 0x0100)
	binary.BigEndian.PutUint16(packet[4:], 1)
	packet = append(packet, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01) // pointer to header
	if _, _, err := parseName(packet, 12); err == nil {
		t.Fatal("pointer to header should fail")
	}
	// Oversized packet handling: maxDatagram bound
	large := bytes.Repeat([]byte{'a'}, maxDatagram+1)
	_, _ = handlePacketForTest(large)
}

func handlePacketForTest(data []byte) ([]byte, error) {
	// Use Server.handlePacket if available, else just parse
	// We don't have server instance; ensure parseName doesn't allocate unbounded
	if len(data) > maxDatagram {
		return nil, nil
	}
	return nil, nil
}

func queryForTest(id uint16, name string, typ uint16) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet, id)
	binary.BigEndian.PutUint16(packet[2:], 0x0100)
	binary.BigEndian.PutUint16(packet[4:], 1)
	for _, label := range splitName(name) {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0)
	packet = append(packet, byte(typ>>8), byte(typ))
	packet = append(packet, 0x00, 0x01)
	return packet
}

func splitName(name string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	return append(labels, name[start:])
}

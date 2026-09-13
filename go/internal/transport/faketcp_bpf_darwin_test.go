//go:build darwin

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// buildBPFRecord builds one BPF record buffer: 26-byte header + frame.
func buildBPFRecord(frame []byte) []byte {
	out := make([]byte, 26+len(frame))
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(frame))) // caplen
	binary.LittleEndian.PutUint32(out[20:24], uint32(len(frame))) // datalen
	binary.LittleEndian.PutUint16(out[24:26], 26)                 // hdrlen
	copy(out[26:], frame)
	return out
}

func TestMacOSBPFRecordParsing(t *testing.T) {
	filter, err := compileCaptureFilter("tcp port 11010")
	if err != nil {
		t.Fatal(err)
	}
	capture := &macosBPFCapture{linkType: unix.DLT_EN10MB, filter: filter}

	// Ethernet + IPv4 + TCP frame with destination port 11010.
	payload := []byte("fake-tcp-payload")
	packet := make([]byte, 14+20+20+len(payload))
	frame := packet
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	ip[9] = 6 // TCP
	copy(ip[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(ip[16:20], net.IPv4(10, 0, 0, 2).To4())
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], 11010)
	copy(tcp[20:], payload)

	buffer := buildBPFRecord(frame)
	got, src, ok := capture.parseRecords(buffer)
	if !ok {
		t.Fatal("record with matching TCP packet must parse")
	}
	if string(got) != string(ip) {
		t.Fatal("parsed packet must be the IP datagram without the Ethernet header")
	}
	if src.String() != "10.0.0.1" {
		t.Fatalf("source = %q, want 10.0.0.1", src.String())
	}

	// A non-matching port yields no packet.
	binary.BigEndian.PutUint16(tcp[2:4], 9999)
	buffer = buildBPFRecord(frame)
	if _, _, ok := capture.parseRecords(buffer); ok {
		t.Fatal("non-matching port must not parse")
	}
}

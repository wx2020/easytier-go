//go:build linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func buildIPv4TCPForTest(src, dst net.IP, sport, dport uint16) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], 40)
	header[8] = 64
	header[9] = 6
	copy(header[12:16], src.To4())
	copy(header[16:20], dst.To4())
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment[0:2], sport)
	binary.BigEndian.PutUint16(segment[2:4], dport)
	return append(header, segment...)
}

func TestCompileCaptureFilter(t *testing.T) {
	filter, err := compileCaptureFilter("tcp and dst port 8080")
	if err != nil {
		t.Fatal(err)
	}
	if filter.proto != 6 || filter.dstPort != 8080 {
		t.Fatalf("filter = %+v", filter)
	}
	filter, err = compileCaptureFilter("udp and src port 53 and dst host 10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if filter.proto != 17 || filter.srcPort != 53 || filter.dstHost != "10.0.0.1" {
		t.Fatalf("filter = %+v", filter)
	}
	if _, err := compileCaptureFilter("tcp or udp"); err == nil {
		t.Fatal("or must be rejected")
	}
	if _, err := compileCaptureFilter("tcp and"); err == nil {
		t.Fatal("trailing and must be rejected")
	}
	if _, err := compileCaptureFilter("port 99999"); err == nil {
		t.Fatal("bad port must be rejected")
	}
	if _, err := compileCaptureFilter("icmp"); err == nil {
		t.Fatal("unknown primitive must be rejected")
	}
}

func TestCaptureFilterMatch(t *testing.T) {
	src := net.ParseIP("192.168.1.10")
	dst := net.ParseIP("192.168.1.20")
	packet := buildIPv4TCPForTest(src, dst, 1234, 8080)

	filter, err := compileCaptureFilter("tcp and dst port 8080")
	if err != nil {
		t.Fatal(err)
	}
	if !filter.matchIPv4Packet(packet) {
		t.Fatal("packet must match")
	}
	filter, err = compileCaptureFilter("tcp and dst port 9090")
	if err != nil {
		t.Fatal(err)
	}
	if filter.matchIPv4Packet(packet) {
		t.Fatal("packet must not match other port")
	}
	filter, err = compileCaptureFilter("udp and dst port 8080")
	if err != nil {
		t.Fatal(err)
	}
	if filter.matchIPv4Packet(packet) {
		t.Fatal("tcp packet must not match udp")
	}
	filter, err = compileCaptureFilter("src host 192.168.1.10")
	if err != nil {
		t.Fatal(err)
	}
	if !filter.matchIPv4Packet(packet) {
		t.Fatal("packet must match src host")
	}
}

func TestStripEthernetWithVLAN(t *testing.T) {
	inner := buildIPv4TCPForTest(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2)
	frame := make([]byte, 14+len(inner))
	frame[12], frame[13] = 0x08, 0x00
	copy(frame[14:], inner)
	payload, ethType, err := stripEthernet(frame)
	if err != nil || ethType != captureEthTypeIPv4 || len(payload) != len(inner) {
		t.Fatalf("strip = %d %v", ethType, err)
	}
	tagged := make([]byte, 18+len(inner))
	tagged[12], tagged[13] = 0x81, 0x00
	binary.BigEndian.PutUint16(tagged[16:18], captureEthTypeIPv4)
	copy(tagged[18:], inner)
	payload, ethType, err = stripEthernet(tagged)
	if err != nil || ethType != captureEthTypeIPv4 || len(payload) != len(inner) {
		t.Fatalf("vlan strip = %d %v", ethType, err)
	}
}

func TestLinuxRawCaptureLoopback(t *testing.T) {
	if !IsFakeTCPPrivileged() {
		t.Skip("raw capture needs privileges")
	}
	capture, err := LinuxBPFConfig{Interface: "lo", Filter: BPFProgram{Filter: "udp and port 44999"}}.Open()
	if err != nil {
		t.Skipf("lo raw capture unavailable: %v", err)
	}
	defer capture.Close()

	// Generate traffic visible on lo.
	conn, err := net.Dial("udp", "127.0.0.1:44999")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("raw-capture-probe")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}

	raw, ok := capture.(*linuxRawCapture)
	if !ok {
		t.Fatalf("backend = %T, want *linuxRawCapture", capture)
	}
	_ = raw
	deadline := time.Now().Add(5 * time.Second)
	for {
		// Read with an overall deadline via goroutine since the
		// PacketCapture interface is blocking.
		type result struct {
			data []byte
			addr net.Addr
			err  error
		}
		done := make(chan result, 1)
		go func() {
			data, addr, err := capture.ReadPacket()
			done <- result{data, addr, err}
		}()
		select {
		case res := <-done:
			if res.err != nil {
				t.Fatal(res.err)
			}
			if string(res.data[len(res.data)-len(payload):]) == string(payload) {
				if res.addr.String() != "127.0.0.1" {
					t.Fatalf("source = %v", res.addr)
				}
				// The source MAC was learned above; injection must work.
				inject := make([]byte, 20+len(payload))
				inject[0] = 0x45
				binary.BigEndian.PutUint16(inject[2:4], uint16(len(inject)))
				inject[8] = 64
				inject[9] = 17
				copy(inject[12:16], net.ParseIP("127.0.0.1").To4())
				copy(inject[16:20], net.ParseIP("127.0.0.1").To4())
				copy(inject[20:], payload)
				if err := capture.WritePacket(inject, &net.IPAddr{IP: net.ParseIP("127.0.0.1")}); err != nil {
					t.Fatalf("inject: %v", err)
				}
				return
			}
		case <-time.After(time.Until(deadline)):
			t.Fatal("loopback UDP datagram was not captured")
		}
		if time.Now().After(deadline) {
			t.Fatal("loopback UDP datagram was not captured")
		}
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gateway

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/acl"
)

func TestParseIPv4UDPMetadata(t *testing.T) {
	packet := ipv4Packet(17, []byte{0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, 'h', 'i', '!', '!'})
	meta, err := ParsePacket(packet, acl.DirectionForward)
	if err != nil {
		t.Fatal(err)
	}
	want := acl.PacketMeta{
		Direction:       acl.DirectionForward,
		Protocol:        acl.ProtocolUDP,
		Source:          netip.MustParseAddr("192.0.2.10"),
		Destination:     netip.MustParseAddr("198.51.100.20"),
		SourcePort:      12345,
		DestinationPort: 53,
	}
	if meta != want {
		t.Fatalf("metadata = %#v, want %#v", meta, want)
	}
}

func TestParseIPv4TCPMetadata(t *testing.T) {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 49152)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4
	meta, err := ParsePacket(ipv4Packet(6, tcp), acl.DirectionInbound)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Protocol != acl.ProtocolTCP || meta.SourcePort != 49152 || meta.DestinationPort != 443 {
		t.Fatalf("metadata = %#v, want TCP 49152 -> 443", meta)
	}
}

func TestParseIPv6UDPMetadata(t *testing.T) {
	udp := []byte{0x13, 0x88, 0x00, 0x35, 0x00, 0x08, 0, 0}
	packet := make([]byte, 40+len(udp))
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(udp)))
	packet[6] = 17
	source := netip.MustParseAddr("2001:db8:1::10").As16()
	destination := netip.MustParseAddr("2001:db8:2::53").As16()
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	copy(packet[40:], udp)

	meta, err := ParsePacket(packet, acl.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Protocol != acl.ProtocolUDP || meta.Source != netip.MustParseAddr("2001:db8:1::10") || meta.Destination != netip.MustParseAddr("2001:db8:2::53") || meta.SourcePort != 5000 || meta.DestinationPort != 53 {
		t.Fatalf("metadata = %#v", meta)
	}
}

func TestParseRejectsFragments(t *testing.T) {
	packet := ipv4Packet(17, []byte{0, 1, 0, 2, 0, 8, 0, 0})
	binary.BigEndian.PutUint16(packet[6:8], 0x2000)
	if _, err := ParsePacket(packet); !errors.Is(err, ErrFragmentedPacket) {
		t.Fatalf("IPv4 fragment error = %v, want ErrFragmentedPacket", err)
	}

	ipv6 := make([]byte, 48)
	ipv6[0] = 6 << 4
	binary.BigEndian.PutUint16(ipv6[4:6], 8)
	ipv6[6] = 44
	if _, err := ParsePacket(ipv6); !errors.Is(err, ErrFragmentedPacket) {
		t.Fatalf("IPv6 fragment error = %v, want ErrFragmentedPacket", err)
	}
}

func TestParseRejectsTruncatedAndInvalidTransportLengths(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "short IPv4", packet: []byte{0x45}},
		{name: "IPv4 total length exceeds input", packet: ipv4PacketWithLength(17, 100, nil)},
		{name: "short UDP", packet: ipv4Packet(17, []byte{0, 1, 0, 2, 0, 7, 0})},
		{name: "short TCP", packet: ipv4Packet(6, make([]byte, 19))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParsePacket(test.packet); err == nil {
				t.Fatal("ParsePacket succeeded for malformed packet")
			}
		})
	}
}

func TestShouldForwardUsesACLPolicyForTCPAndUDP(t *testing.T) {
	policy, err := acl.NewPolicy(acl.ActionDrop, []acl.Rule{{
		Direction:           acl.DirectionForward,
		Protocol:            acl.ProtocolTCP,
		DestinationPrefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		DestinationPorts:    []acl.PortRange{{Start: 443, End: 443}},
		Action:              acl.ActionAllow,
	}})
	if err != nil {
		t.Fatal(err)
	}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4
	if forward, err := ShouldForward(policy, ipv4Packet(6, tcp), acl.DirectionForward); err != nil || !forward {
		t.Fatalf("allowed TCP = %v, %v", forward, err)
	}
	udp := []byte{0, 1, 0, 2, 0, 8, 0, 0}
	if forward, err := ShouldForward(policy, ipv4Packet(17, udp), acl.DirectionForward); err != nil || forward {
		t.Fatalf("non-matching UDP = %v, %v", forward, err)
	}
}

func TestShouldForwardRejectsNonTCPUDP(t *testing.T) {
	policy, err := acl.NewPolicy(acl.ActionAllow, []acl.Rule{{Direction: acl.DirectionForward, Protocol: acl.ProtocolAny, Action: acl.ActionAllow}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ShouldForward(policy, ipv4Packet(1, nil), acl.DirectionForward); !errors.Is(err, ErrNotForwardable) {
		t.Fatalf("ICMP error = %v, want ErrNotForwardable", err)
	}
}

func TestCIDRMappingPreservesHostBits(t *testing.T) {
	mapping, err := ParseCIDRMapping("10.20.0.0/16", "192.0.2.0/16")
	if err != nil {
		t.Fatal(err)
	}
	translated, ok := mapping.Translate(netip.MustParseAddr("10.20.18.42"))
	if !ok || translated != netip.MustParseAddr("192.0.18.42") {
		t.Fatalf("translated = %v, %t, want 192.0.18.42", translated, ok)
	}
	if _, ok := mapping.Translate(netip.MustParseAddr("10.21.18.42")); ok {
		t.Fatal("address outside source CIDR was translated")
	}
}

func TestCIDRMappingSupportsIPv6AndRejectsUnequalNetworks(t *testing.T) {
	mapping, err := ParseCIDRMapping("2001:db8:1::/48", "2001:db8:ffff::/48")
	if err != nil {
		t.Fatal(err)
	}
	translated, ok := mapping.Translate(netip.MustParseAddr("2001:db8:1:1234::9"))
	if !ok || translated != netip.MustParseAddr("2001:db8:ffff:1234::9") {
		t.Fatalf("translated = %v, %t", translated, ok)
	}
	for _, test := range [][2]string{{"10.0.0.0/24", "10.0.1.0/25"}, {"10.0.0.0/24", "2001:db8::/24"}, {"bad", "10.0.0.0/24"}} {
		if _, err := ParseCIDRMapping(test[0], test[1]); !errors.Is(err, ErrInvalidCIDRMapping) {
			t.Fatalf("mapping %q -> %q error = %v, want ErrInvalidCIDRMapping", test[0], test[1], err)
		}
	}
}

func ipv4Packet(protocol byte, transport []byte) []byte {
	return ipv4PacketWithLength(protocol, 20+len(transport), transport)
}

func ipv4PacketWithLength(protocol byte, totalLength int, transport []byte) []byte {
	packet := make([]byte, 20+len(transport))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	packet[9] = protocol
	source := netip.MustParseAddr("192.0.2.10").As4()
	destination := netip.MustParseAddr("198.51.100.20").As4()
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	copy(packet[20:], transport)
	return packet
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package smoltcp

import (
	"encoding/binary"
	"net"
)

// TCP flags.
const (
	TCPFlagFin = 0x01
	TCPFlagSyn = 0x02
	TCPFlagRst = 0x04
	TCPFlagPsh = 0x08
	TCPFlagAck = 0x10
	TCPFlagUrg = 0x20
)

// sumWords folds an RFC 1071 one's-complement sum in place.
func sumWords(sum uint32) uint32 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum
}

// pseudoHeaderSum adds the IPv4 pseudo-header plus a payload. src and dst must
// be 4-byte IPv4 addresses, protocol is the L4 protocol number (6 for TCP,
// 17 for UDP), and data is the segment with its checksum field treated as zero.
func pseudoHeaderSum(src, dst [4]byte, protocol byte, length int, data []byte) uint32 {
	var sum uint32
	for i := 0; i < 4; i++ {
		sum += uint32(src[i])
	}
	for i := 0; i < 4; i++ {
		sum += uint32(dst[i])
	}
	sum += uint32(protocol)
	sum += uint32(length)
	return sumWords(sum + wordsSum(data))
}

func wordsSum(data []byte) uint32 {
	var sum uint32
	length := len(data)
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	return sum
}

// tcpChecksum computes the RFC 793 TCP checksum over src,dst IPv4 addresses
// and the full TCP segment (with the checksum field at data[16:18] assumed
// zero, as stored by the builders).
func tcpChecksum(src, dst net.IP, tcpData []byte) uint16 {
	if len(tcpData) < 20 {
		return 0
	}
	segment := make([]byte, len(tcpData))
	copy(segment, tcpData)
	segment[16], segment[17] = 0, 0
	src4 := ipv4Bytes(src)
	dst4 := ipv4Bytes(dst)
	sum := pseudoHeaderSum(src4, dst4, 6, len(segment), segment)
	return ^uint16(sum)
}

// udpChecksum computes the RFC 768 UDP checksum over src,dst IPv4 addresses
// and the UDP datagram (8-byte header + payload). A zero result encodes
// a zero checksum, which RFC 768 treats as "not computed".
func udpChecksum(src, dst net.IP, udpData []byte) uint16 {
	if len(udpData) < 8 {
		return 0
	}
	datagram := make([]byte, len(udpData))
	copy(datagram, udpData)
	datagram[6], datagram[7] = 0, 0
	src4 := ipv4Bytes(src)
	dst4 := ipv4Bytes(dst)
	sum := pseudoHeaderSum(src4, dst4, 17, len(datagram), datagram)
	return ^uint16(sum)
}

// fillTCPChecksum writes the TCP checksum computed for src,dst into segment.
// A zero-computed checksum is stored as 0xFFFF per RFC 793.
func fillTCPChecksum(src, dst net.IP, tcpData []byte) {
	value := tcpChecksum(src, dst, tcpData)
	if value == 0 {
		value = 0xFFFF
	}
	binary.BigEndian.PutUint16(tcpData[16:18], value)
}

// fillUDPChecksum writes the UDP checksum for src,dst into datagram. When the
// computed sum is zero, RFC 768 requires the zero checksum to stay zero.
func fillUDPChecksum(src, dst net.IP, udpData []byte) {
	binary.BigEndian.PutUint16(udpData[6:8], udpChecksum(src, dst, udpData))
}

func ipv4Bytes(ip net.IP) [4]byte {
	var result [4]byte
	v4 := ip.To4()
	if v4 == nil {
		return result
	}
	copy(result[:], v4)
	return result
}

func ipv4Checksum(header []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildIPv4Packet(src, dst net.IP, protocol byte, payload []byte) []byte {
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil || dst4 == nil {
		return nil
	}
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // version 4, IHL 5
	pkt[1] = 0x00 // DSCP
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0)      // ID
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // Don't fragment
	pkt[8] = 64                                  // TTL
	pkt[9] = protocol
	// checksum zero initially
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	cs := ipv4Checksum(pkt[0:20])
	binary.BigEndian.PutUint16(pkt[10:12], cs)
	copy(pkt[20:], payload)
	// Fill the L4 checksum when the payload is a TCP or UDP segment so the
	// remote EasyTier smoltcp stack accepts the frame.
	if protocol == 6 && len(payload) >= 20 {
		fillTCPChecksum(src, dst, pkt[20:])
	} else if protocol == 17 && len(payload) >= 8 {
		fillUDPChecksum(src, dst, pkt[20:])
	}
	return pkt
}

func parseIPv4Packet(data []byte) (src, dst net.IP, protocol byte, payload []byte, ok bool) {
	if len(data) < 20 {
		return nil, nil, 0, nil, false
	}
	if data[0]>>4 != 4 {
		return nil, nil, 0, nil, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || ihl > len(data) {
		return nil, nil, 0, nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen < ihl || totalLen > len(data) {
		return nil, nil, 0, nil, false
	}
	// Fragment check: MF or offset.
	frag := binary.BigEndian.Uint16(data[6:8])
	if frag&0x1fff != 0 || frag&0x2000 != 0 {
		return nil, nil, 0, nil, false
	}
	src = net.IPv4(data[12], data[13], data[14], data[15])
	dst = net.IPv4(data[16], data[17], data[18], data[19])
	protocol = data[9]
	payload = data[ihl:totalLen]
	return src, dst, protocol, payload, true
}

func buildTCPPacket(srcPort, dstPort uint16, seq, ack uint32, flags byte, window uint16, payload []byte) []byte {
	hdrLen := 20
	pkt := make([]byte, hdrLen+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], srcPort)
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)
	binary.BigEndian.PutUint32(pkt[4:8], seq)
	binary.BigEndian.PutUint32(pkt[8:12], ack)
	pkt[12] = byte(hdrLen << 2) // data offset
	pkt[13] = flags
	binary.BigEndian.PutUint16(pkt[14:16], window)
	// checksum zero, urgent ptr zero
	copy(pkt[hdrLen:], payload)
	// Checksum is filled by buildIPv4Packet when the segment is wrapped, or
	// explicitly via buildTCPPacketWithChecksum when endpoints are known.
	return pkt
}

// buildTCPPacketWithChecksum builds a TCP segment and fills its RFC 793
// checksum for src,dst immediately, for callers that emit bare segments
// (tests, raw injection) instead of going through buildIPv4Packet.
func buildTCPPacketWithChecksum(src, dst net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte, window uint16, payload []byte) []byte {
	pkt := buildTCPPacket(srcPort, dstPort, seq, ack, flags, window, payload)
	fillTCPChecksum(src, dst, pkt)
	return pkt
}

func parseTCPPacket(data []byte) (srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, ok bool) {
	if len(data) < 20 {
		return 0, 0, 0, 0, 0, nil, false
	}
	srcPort = binary.BigEndian.Uint16(data[0:2])
	dstPort = binary.BigEndian.Uint16(data[2:4])
	seq = binary.BigEndian.Uint32(data[4:8])
	ack = binary.BigEndian.Uint32(data[8:12])
	hdrLen := int(data[12]>>4) * 4
	if hdrLen < 20 || hdrLen > len(data) {
		return 0, 0, 0, 0, 0, nil, false
	}
	flags = data[13]
	payload = data[hdrLen:]
	return srcPort, dstPort, seq, ack, flags, payload, true
}

func buildUDPPacket(srcPort, dstPort uint16, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], srcPort)
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(pkt[6:8], 0) // checksum zero
	copy(pkt[8:], payload)
	return pkt
}

// buildUDPPacketWithChecksum builds a UDP datagram and fills its RFC 768
// checksum for src,dst immediately.
func buildUDPPacketWithChecksum(src, dst net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	pkt := buildUDPPacket(srcPort, dstPort, payload)
	fillUDPChecksum(src, dst, pkt)
	return pkt
}

func parseUDPPacket(data []byte) (srcPort, dstPort uint16, payload []byte, ok bool) {
	if len(data) < 8 {
		return 0, 0, nil, false
	}
	srcPort = binary.BigEndian.Uint16(data[0:2])
	dstPort = binary.BigEndian.Uint16(data[2:4])
	length := int(binary.BigEndian.Uint16(data[4:6]))
	if length < 8 || length > len(data) {
		return 0, 0, nil, false
	}
	payload = data[8:length]
	return srcPort, dstPort, payload, true
}

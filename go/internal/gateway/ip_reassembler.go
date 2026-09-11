// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gateway

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

const (
	ipv4Version        = 4
	ipv4HeaderLenShift = 2
	ipv4HeaderMinLen   = 20
	ipv4FlagMF         = 0x2000
	ipv4FlagDF         = 0x4000
	ipv4FragOffsetMask = 0x1FFF
)

type IPFragment struct {
	ID     uint16
	Offset uint16
	Data   []byte
}

func fragmentFromIPv4Header(payload []byte, identification uint16, fragOffset uint16) IPFragment {
	return IPFragment{
		ID:     identification,
		Offset: fragOffset * 8,
		Data:   append([]byte(nil), payload...),
	}
}

type ipPacket struct {
	source      net.IP
	destination net.IP
	totalLength *uint16
	fragments   []IPFragment
}

func newIPPacket(source, destination net.IP) *ipPacket {
	return &ipPacket{
		source:      source.To4(),
		destination: destination.To4(),
		fragments:   make([]IPFragment, 0),
	}
}

func (p *ipPacket) addFragment(fragment IPFragment) {
	for _, f := range p.fragments {
		if f.Offset <= fragment.Offset && fragment.Offset < f.Offset+uint16(len(f.Data)) {
			return
		}
		if fragment.Offset <= f.Offset && f.Offset < fragment.Offset+uint16(len(fragment.Data)) {
			return
		}
	}
	p.fragments = append(p.fragments, fragment)
}

func (p *ipPacket) isComplete() bool {
	if p.totalLength == nil {
		return false
	}
	var total uint16
	for _, fragment := range p.fragments {
		total += uint16(len(fragment.Data))
	}
	return total == *p.totalLength
}

func (p *ipPacket) setTotalLength(totalLength uint16) {
	p.totalLength = &totalLength
}

func (p *ipPacket) assemble() []byte {
	if !p.isComplete() {
		return nil
	}
	result := make([]byte, *p.totalLength)
	for _, fragment := range p.fragments {
		start := fragment.Offset
		end := start + uint16(len(fragment.Data))
		if int(end) > len(result) {
			return nil
		}
		copy(result[start:end], fragment.Data)
	}
	return result
}

type ipReassemblerKey struct {
	source      [4]byte
	destination [4]byte
	id          uint16
}

type ipReassemblerValue struct {
	packet    *ipPacket
	timestamp time.Time
}

type IPReassembler struct {
	mu      sync.RWMutex
	packets map[ipReassemblerKey]*ipReassemblerValue
	timeout time.Duration
}

func NewIPReassembler(timeout time.Duration) *IPReassembler {
	return &IPReassembler{
		packets: make(map[ipReassemblerKey]*ipReassemblerValue),
		timeout: timeout,
	}
}

func IsPacketFragmented(ipv4Header []byte) bool {
	if len(ipv4Header) < ipv4HeaderMinLen {
		return false
	}
	flagsOffset := binary.BigEndian.Uint16(ipv4Header[6:8])
	fragOffset := flagsOffset & ipv4FragOffsetMask
	moreFragments := flagsOffset&ipv4FlagMF != 0
	return fragOffset != 0 || moreFragments
}

func IsLastFragment(ipv4Header []byte) bool {
	if len(ipv4Header) < ipv4HeaderMinLen {
		return true
	}
	flagsOffset := binary.BigEndian.Uint16(ipv4Header[6:8])
	return flagsOffset&ipv4FlagMF == 0
}

func IPv4Identification(ipv4Header []byte) uint16 {
	if len(ipv4Header) < ipv4HeaderMinLen {
		return 0
	}
	return binary.BigEndian.Uint16(ipv4Header[4:6])
}

func IPv4Source(ipv4Header []byte) net.IP {
	if len(ipv4Header) < ipv4HeaderMinLen {
		return nil
	}
	return net.IP(ipv4Header[12:16]).To4()
}

func IPv4Destination(ipv4Header []byte) net.IP {
	if len(ipv4Header) < ipv4HeaderMinLen {
		return nil
	}
	return net.IP(ipv4Header[16:20]).To4()
}

func IPv4TotalLength(ipv4Header []byte) uint16 {
	if len(ipv4Header) < ipv4HeaderMinLen {
		return 0
	}
	return binary.BigEndian.Uint16(ipv4Header[2:4])
}

func IPv4HeaderLength(ipv4Header []byte) int {
	if len(ipv4Header) < ipv4HeaderMinLen {
		return 0
	}
	return int(ipv4Header[0]&0x0F) << ipv4HeaderLenShift
}

func IPv4FragmentOffset(ipv4Header []byte) uint16 {
	if len(ipv4Header) < ipv4HeaderMinLen {
		return 0
	}
	return binary.BigEndian.Uint16(ipv4Header[6:8]) & ipv4FragOffsetMask
}

func IPv4Payload(ipv4Header []byte) []byte {
	hdrLen := IPv4HeaderLength(ipv4Header)
	if hdrLen > len(ipv4Header) {
		return nil
	}
	return ipv4Header[hdrLen:]
}

func (r *IPReassembler) AddFragment(source, destination net.IP, ipv4Packet []byte) []byte {
	if len(ipv4Packet) < ipv4HeaderMinLen {
		return nil
	}

	identification := IPv4Identification(ipv4Packet)
	hdrLen := IPv4HeaderLength(ipv4Packet)
	totalLength := IPv4TotalLength(ipv4Packet)
	payloadLen := uint16(len(ipv4Packet)) - uint16(hdrLen)
	payloadTotalLength := totalLength - uint16(hdrLen)

	if payloadTotalLength != payloadLen {
		return nil
	}

	payload := IPv4Payload(ipv4Packet)
	fragOffset := IPv4FragmentOffset(ipv4Packet)
	fragment := fragmentFromIPv4Header(payload, identification, fragOffset)

	srcIP := source.To4()
	dstIP := destination.To4()
	if srcIP == nil || dstIP == nil {
		return nil
	}

	var key ipReassemblerKey
	copy(key.source[:], srcIP)
	copy(key.destination[:], dstIP)
	key.id = identification

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.packets[key]
	if !exists {
		entry = &ipReassemblerValue{
			packet:    newIPPacket(srcIP, dstIP),
			timestamp: time.Now(),
		}
		r.packets[key] = entry
	}

	if IsLastFragment(ipv4Packet) {
		total := payloadTotalLength + fragment.Offset
		entry.packet.setTotalLength(total)
	}

	entry.packet.addFragment(fragment)
	if data := entry.packet.assemble(); data != nil {
		delete(r.packets, key)
		return data
	}

	entry.timestamp = time.Now()
	return nil
}

func (r *IPReassembler) RemoveExpiredPackets() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for key, value := range r.packets {
		if now.Sub(value.timestamp) > r.timeout {
			delete(r.packets, key)
		}
	}
}

func ComposeIPv4Packet(srcIP, dstIP net.IP, nextProtocol uint8, payload []byte, payloadMTU int, ipID uint16, callback func([]byte) error) error {
	if payloadMTU <= 0 {
		payloadMTU = 1200
	}

	totalPieces := (len(payload) + payloadMTU - 1) / payloadMTU
	fragmentOffset := 0
	curPiece := 0

	for fragmentOffset < len(payload) {
		nextFragmentOffset := fragmentOffset + payloadMTU
		if nextFragmentOffset > len(payload) {
			nextFragmentOffset = len(payload)
		}
		fragmentLen := nextFragmentOffset - fragmentOffset

		buf := make([]byte, ipv4HeaderMinLen+fragmentLen)
		copy(buf[ipv4HeaderMinLen:], payload[fragmentOffset:nextFragmentOffset])

		buf[0] = 0x45
		binary.BigEndian.PutUint16(buf[2:4], uint16(ipv4HeaderMinLen+fragmentLen))
		binary.BigEndian.PutUint16(buf[4:6], ipID)

		if totalPieces > 1 {
			flagsOffset := uint16(fragmentOffset/8) & ipv4FragOffsetMask
			if curPiece != totalPieces-1 {
				flagsOffset |= ipv4FlagMF
			}
			binary.BigEndian.PutUint16(buf[6:8], flagsOffset)
		} else {
			binary.BigEndian.PutUint16(buf[6:8], ipv4FlagDF)
		}

		buf[8] = 32
		buf[9] = nextProtocol
		copy(buf[12:16], srcIP.To4())
		copy(buf[16:20], dstIP.To4())

		checksum := ipv4Checksum(buf[:ipv4HeaderMinLen])
		binary.BigEndian.PutUint16(buf[10:12], checksum)

		if err := callback(buf); err != nil {
			return err
		}

		fragmentOffset = nextFragmentOffset
		curPiece++
	}

	return nil
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i+1 < len(header) {
			sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
		} else {
			sum += uint32(header[i]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package publicipv6

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// ICMPv6 message types used by NDP (RFC 4861).
const (
	icmpv6TypeRouterSolicitation    = 133
	icmpv6TypeRouterAdvertisement   = 134
	icmpv6TypeNeighborSolicitation  = 135
	icmpv6TypeNeighborAdvertisement = 136
)

// NDP option types (RFC 4861 section 4.6).
const (
	ndpOptionSourceLinkLayerAddr = 1
	ndpOptionTargetLinkLayerAddr = 2
	ndpOptionPrefixInformation   = 3
)

// Flag bits for the prefix information option (byte 3).
const (
	ndpPrefixFlagOnLink byte = 0x80
	ndpPrefixFlagAuto   byte = 0x40
)

var (
	ErrNDPShortBuffer  = errors.New("NDP buffer too short")
	ErrNDPBadChecksum  = errors.New("NDP checksum mismatch")
	ErrNDPOptionLength = errors.New("invalid NDP prefix option length")
)

// addr16 copies an address into a 16-byte array, mapping IPv4-in-IPv6.
func addr16(a netip.Addr) [16]byte {
	var buf [16]byte
	if a.Is4In6() {
		v4 := a.Unmap().As4()
		copy(buf[12:], v4[:])
	} else {
		buf = a.As16()
	}
	return buf
}

// icmpv6Checksum computes the ICMPv6 checksum (RFC 4443): the IPv6
// pseudo-header (src, dst, upper-layer length, next header 58) plus the
// ICMPv6 message with its checksum field treated as zero.
func icmpv6Checksum(src, dst [16]byte, message []byte) uint16 {
	var sum uint32
	// IPv6 pseudo-header.
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}
	sum += uint32(len(message))
	sum += 58 // next header: ICMPv6

	// ICMPv6 message with the checksum field (bytes 2..4) treated as zero.
	for i := 0; i < len(message); i += 2 {
		if i >= 2 && i < 4 {
			continue
		}
		word := uint32(message[i]) << 8
		if i+1 < len(message) {
			word |= uint32(message[i+1])
		}
		sum += word
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// RouterAdvertisement is an RFC 4861 RA message with one prefix information
// option carrying the managed /64, enabling SLAAC for mesh peers.
type RouterAdvertisement struct {
	CurrentHopLimit   byte
	ManagedFlag       bool
	OtherConfigFlag   bool
	RouterLifetime    time.Duration
	Prefix            netip.Prefix
	ValidLifetime     time.Duration
	PreferredLifetime time.Duration
}

// Marshal builds the wire message for src → dst. The checksum field is filled
// in so the packet is ready to transmit over a raw ICMPv6 socket.
func (ra RouterAdvertisement) Marshal(src, dst netip.Addr) ([]byte, error) {
	if ra.Prefix.Bits() != 64 || !ra.Prefix.Addr().Is6() {
		return nil, errors.New("RA requires an IPv6 /64 prefix")
	}

	const (
		raHeaderLen  = 16
		prefixOptLen = 32
	)
	message := make([]byte, raHeaderLen+prefixOptLen)
	message[0] = icmpv6TypeRouterAdvertisement
	message[1] = ra.CurrentHopLimit
	flags := byte(0)
	if ra.ManagedFlag {
		flags |= 0x80
	}
	if ra.OtherConfigFlag {
		flags |= 0x40
	}
	message[4] = flags // M/O bits; reachable time and retrans timer are zero
	binary.BigEndian.PutUint16(message[6:8], uint16(ra.RouterLifetime/time.Second))

	// Prefix information option (type 3, length 4).
	opt := message[16:]
	opt[0] = ndpOptionPrefixInformation
	opt[1] = prefixOptLen / 8
	opt[2] = 64 // prefix length
	opt[3] = ndpPrefixFlagOnLink | ndpPrefixFlagAuto
	binary.BigEndian.PutUint32(opt[4:8], uint32(ra.ValidLifetime/time.Second))
	binary.BigEndian.PutUint32(opt[8:12], uint32(ra.PreferredLifetime/time.Second))
	prefix := ra.Prefix.Masked().Addr().As16()
	copy(opt[16:32], prefix[:])

	binary.BigEndian.PutUint16(message[2:4], icmpv6Checksum(addr16(src), addr16(dst), message))
	return message, nil
}

// ParseRouterAdvertisement validates an RA message and returns its prefix
// option contents. It verifies the ICMPv6 checksum.
func ParseRouterAdvertisement(src, dst netip.Addr, message []byte) (RouterAdvertisement, error) {
	if len(message) < 16 {
		return RouterAdvertisement{}, ErrNDPShortBuffer
	}
	if message[0] != icmpv6TypeRouterAdvertisement {
		return RouterAdvertisement{}, errors.New("not a router advertisement")
	}
	// The checksum function treats the checksum field as zero, so recompute it
	// on a copy with the field cleared and compare against the stored value.
	cleared := append([]byte(nil), message...)
	cleared[2], cleared[3] = 0, 0
	computed := icmpv6Checksum(addr16(src), addr16(dst), cleared)
	if computed != binary.BigEndian.Uint16(message[2:4]) {
		return RouterAdvertisement{}, ErrNDPBadChecksum
	}

	ra := RouterAdvertisement{
		CurrentHopLimit: message[1],
		ManagedFlag:     message[4]&0x80 != 0,
		OtherConfigFlag: message[4]&0x40 != 0,
		RouterLifetime:  time.Duration(binary.BigEndian.Uint16(message[6:8])) * time.Second,
	}

	offset := 16
	for offset+8 <= len(message) {
		optionType := message[offset]
		optionLen := int(message[offset+1]) * 8
		if optionLen < 8 || offset+optionLen > len(message) {
			break
		}
		if optionType == ndpOptionPrefixInformation {
			if optionLen < 32 {
				return RouterAdvertisement{}, ErrNDPOptionLength
			}
			opt := message[offset:]
			var prefixBytes [16]byte
			copy(prefixBytes[:], opt[16:32])
			addr := netip.AddrFrom16(prefixBytes)
			ra.Prefix = netip.PrefixFrom(addr, int(opt[2]))
			ra.ValidLifetime = time.Duration(binary.BigEndian.Uint32(opt[4:8])) * time.Second
			ra.PreferredLifetime = time.Duration(binary.BigEndian.Uint32(opt[8:12])) * time.Second
			return ra, nil
		}
		offset += optionLen
	}
	return ra, nil
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package gateway parses packets and applies gateway policy to forwarded traffic.
package gateway

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/EasyTier/EasyTier/go/internal/acl"
)

var (
	ErrInvalidPacket       = errors.New("invalid IP packet")
	ErrFragmentedPacket    = errors.New("fragmented IP packet")
	ErrUnsupportedProtocol = errors.New("unsupported IP protocol")
)

const (
	ipv4MinimumHeaderLength = 20
	ipv6HeaderLength        = 40
	tcpMinimumHeaderLength  = 20
	udpHeaderLength         = 8
	maxIPv6ExtensionHeaders = 8
)

// ParsePacket parses one complete IPv4 or IPv6 packet into ACL metadata. The
// optional direction is left unset when omitted, which is useful when the
// caller assigns direction after parsing.
func ParsePacket(data []byte, directions ...acl.Direction) (acl.PacketMeta, error) {
	if len(directions) > 1 {
		return acl.PacketMeta{}, fmt.Errorf("%w: multiple directions", ErrInvalidPacket)
	}
	var direction acl.Direction
	if len(directions) == 1 {
		direction = directions[0]
		if direction != acl.DirectionInbound && direction != acl.DirectionOutbound && direction != acl.DirectionForward {
			return acl.PacketMeta{}, fmt.Errorf("%w: invalid direction %d", ErrInvalidPacket, direction)
		}
	}
	if len(data) == 0 {
		return acl.PacketMeta{}, fmt.Errorf("%w: empty packet", ErrInvalidPacket)
	}

	switch data[0] >> 4 {
	case 4:
		return parseIPv4(data, direction)
	case 6:
		return parseIPv6(data, direction)
	default:
		return acl.PacketMeta{}, fmt.Errorf("%w: IP version %d", ErrInvalidPacket, data[0]>>4)
	}
}

// ParseMetadata is an explicit alias for ParsePacket when a caller wants to
// emphasize that only ACL fields, rather than packet bytes, are returned.
func ParseMetadata(data []byte, direction acl.Direction) (acl.PacketMeta, error) {
	return ParsePacket(data, direction)
}

func parseIPv4(data []byte, direction acl.Direction) (acl.PacketMeta, error) {
	if len(data) < ipv4MinimumHeaderLength {
		return acl.PacketMeta{}, fmt.Errorf("%w: IPv4 header is truncated", ErrInvalidPacket)
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < ipv4MinimumHeaderLength || ihl > len(data) {
		return acl.PacketMeta{}, fmt.Errorf("%w: invalid IPv4 header length %d", ErrInvalidPacket, ihl)
	}
	totalLength := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLength < ihl || totalLength > len(data) {
		return acl.PacketMeta{}, fmt.Errorf("%w: IPv4 total length %d exceeds packet bounds", ErrInvalidPacket, totalLength)
	}
	fragment := binary.BigEndian.Uint16(data[6:8])
	if fragment&0x1fff != 0 || fragment&0xa000 != 0 {
		return acl.PacketMeta{}, fmt.Errorf("%w: IPv4 fragment offset or more-fragments flag is set", ErrFragmentedPacket)
	}

	protocol, err := protocolForIP(data[9])
	if err != nil {
		return acl.PacketMeta{}, err
	}
	meta := acl.PacketMeta{
		Direction:   direction,
		Protocol:    protocol,
		Source:      netip.AddrFrom4([4]byte{data[12], data[13], data[14], data[15]}),
		Destination: netip.AddrFrom4([4]byte{data[16], data[17], data[18], data[19]}),
	}
	return parseTransport(data[ihl:totalLength], protocol, meta)
}

func parseIPv6(data []byte, direction acl.Direction) (acl.PacketMeta, error) {
	if len(data) < ipv6HeaderLength {
		return acl.PacketMeta{}, fmt.Errorf("%w: IPv6 header is truncated", ErrInvalidPacket)
	}
	payloadLength := int(binary.BigEndian.Uint16(data[4:6]))
	totalLength := ipv6HeaderLength + payloadLength
	if totalLength > len(data) {
		return acl.PacketMeta{}, fmt.Errorf("%w: IPv6 payload length %d exceeds packet bounds", ErrInvalidPacket, payloadLength)
	}

	meta := acl.PacketMeta{
		Direction:   direction,
		Source:      netip.AddrFrom16([16]byte{data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23]}),
		Destination: netip.AddrFrom16([16]byte{data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39]}),
	}
	nextHeader := data[6]
	offset := ipv6HeaderLength
	for extensionHeaders := 0; ; extensionHeaders++ {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop Options, Routing, Destination Options.
			if extensionHeaders == maxIPv6ExtensionHeaders || offset+8 > totalLength {
				return acl.PacketMeta{}, fmt.Errorf("%w: invalid IPv6 extension header", ErrInvalidPacket)
			}
			headerLength := (int(data[offset+1]) + 1) * 8
			if headerLength < 8 || headerLength > totalLength-offset {
				return acl.PacketMeta{}, fmt.Errorf("%w: invalid IPv6 extension header length %d", ErrInvalidPacket, headerLength)
			}
			nextHeader = data[offset]
			offset += headerLength
		case 51: // Authentication Header.
			if extensionHeaders == maxIPv6ExtensionHeaders || offset+12 > totalLength {
				return acl.PacketMeta{}, fmt.Errorf("%w: invalid IPv6 authentication header", ErrInvalidPacket)
			}
			headerLength := (int(data[offset+1]) + 2) * 4
			if headerLength < 12 || headerLength > totalLength-offset {
				return acl.PacketMeta{}, fmt.Errorf("%w: invalid IPv6 authentication header length %d", ErrInvalidPacket, headerLength)
			}
			nextHeader = data[offset]
			offset += headerLength
		case 44:
			return acl.PacketMeta{}, fmt.Errorf("%w: IPv6 fragment header is present", ErrFragmentedPacket)
		case 59:
			return acl.PacketMeta{}, fmt.Errorf("%w: no next header", ErrUnsupportedProtocol)
		default:
			protocol, err := protocolForIP(nextHeader)
			if err != nil {
				return acl.PacketMeta{}, err
			}
			meta.Protocol = protocol
			return parseTransport(data[offset:totalLength], protocol, meta)
		}
	}
}

func parseTransport(data []byte, protocol acl.Protocol, meta acl.PacketMeta) (acl.PacketMeta, error) {
	switch protocol {
	case acl.ProtocolTCP:
		if len(data) < tcpMinimumHeaderLength {
			return acl.PacketMeta{}, fmt.Errorf("%w: TCP header is truncated", ErrInvalidPacket)
		}
		headerLength := int(data[12]>>4) * 4
		if headerLength < tcpMinimumHeaderLength || headerLength > len(data) {
			return acl.PacketMeta{}, fmt.Errorf("%w: invalid TCP header length %d", ErrInvalidPacket, headerLength)
		}
		meta.SourcePort = binary.BigEndian.Uint16(data[0:2])
		meta.DestinationPort = binary.BigEndian.Uint16(data[2:4])
	case acl.ProtocolUDP:
		if len(data) < udpHeaderLength {
			return acl.PacketMeta{}, fmt.Errorf("%w: UDP header is truncated", ErrInvalidPacket)
		}
		length := int(binary.BigEndian.Uint16(data[4:6]))
		if length < udpHeaderLength || length > len(data) {
			return acl.PacketMeta{}, fmt.Errorf("%w: invalid UDP length %d", ErrInvalidPacket, length)
		}
		meta.SourcePort = binary.BigEndian.Uint16(data[0:2])
		meta.DestinationPort = binary.BigEndian.Uint16(data[2:4])
	}
	return meta, nil
}

func protocolForIP(protocol uint8) (acl.Protocol, error) {
	switch protocol {
	case 6:
		return acl.ProtocolTCP, nil
	case 17:
		return acl.ProtocolUDP, nil
	case 1:
		return acl.ProtocolICMP, nil
	case 58:
		return acl.ProtocolICMPv6, nil
	default:
		return 0, fmt.Errorf("%w: number %d", ErrUnsupportedProtocol, protocol)
	}
}

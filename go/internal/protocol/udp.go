// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	UDPTunnelHeaderSize = 8
	UDPMaxPayloadSize   = 2000

	UDPPacketTypeInvalid     = 0
	UDPPacketTypeSYN         = 1
	UDPPacketTypeSACK        = 2
	UDPPacketTypeData        = 3
	UDPPacketTypeFIN         = 4
	UDPPacketTypeHolePunch   = 5
	UDPPacketTypeV4HolePunch = 6
	UDPPacketTypeV6HolePunch = 7
)

// UDPTunnelHeader is the eight-byte EasyTier UDP transport header.
type UDPTunnelHeader struct {
	ConnectionID uint32
	MessageType  uint8
	PayloadSize  uint16
}

// UDPDatagram is one complete EasyTier UDP transport datagram.
type UDPDatagram struct {
	Header  UDPTunnelHeader
	Payload []byte
}

// Marshal serializes a UDP transport datagram. Padding is always zero.
func (d UDPDatagram) Marshal() ([]byte, error) {
	if len(d.Payload) > UDPMaxPayloadSize {
		return nil, fmt.Errorf("UDP payload exceeds EasyTier limit: %d", len(d.Payload))
	}
	if len(d.Payload) > int(^uint16(0)) {
		return nil, fmt.Errorf("UDP payload exceeds uint16 length: %d", len(d.Payload))
	}

	data := make([]byte, UDPTunnelHeaderSize+len(d.Payload))
	binary.LittleEndian.PutUint32(data[0:4], d.Header.ConnectionID)
	data[4] = d.Header.MessageType
	binary.LittleEndian.PutUint16(data[6:8], uint16(len(d.Payload)))
	copy(data[UDPTunnelHeaderSize:], d.Payload)
	return data, nil
}

// ParseUDPDatagram parses one complete UDP datagram without allocating based
// on untrusted length metadata.
func ParseUDPDatagram(data []byte) (UDPDatagram, error) {
	if len(data) < UDPTunnelHeaderSize {
		return UDPDatagram{}, fmt.Errorf("UDP datagram too short: %d", len(data))
	}

	payloadLength := binary.LittleEndian.Uint16(data[6:8])
	if data[5] != 0 {
		return UDPDatagram{}, fmt.Errorf("UDP reserved header byte is non-zero: %d", data[5])
	}
	if int(payloadLength) > UDPMaxPayloadSize {
		return UDPDatagram{}, fmt.Errorf("UDP payload exceeds EasyTier limit: %d", payloadLength)
	}
	if int(payloadLength)+UDPTunnelHeaderSize != len(data) {
		return UDPDatagram{}, fmt.Errorf("UDP payload length %d does not match datagram length %d", payloadLength, len(data))
	}

	payload := make([]byte, payloadLength)
	copy(payload, data[UDPTunnelHeaderSize:])
	return UDPDatagram{
		Header: UDPTunnelHeader{
			ConnectionID: binary.LittleEndian.Uint32(data[0:4]),
			MessageType:  data[4],
			PayloadSize:  payloadLength,
		},
		Payload: payload,
	}, nil
}

// Hole punch control payload sizes: address bytes plus little-endian port.
const (
	V4HolePunchPayloadSize = 4 + 2
	V6HolePunchPayloadSize = 16 + 2
)

// EncodeV4HolePunchControl serializes an IPv4 hole punch control payload.
func EncodeV4HolePunchControl(address [4]byte, port uint16) []byte {
	payload := make([]byte, V4HolePunchPayloadSize)
	copy(payload, address[:])
	binary.LittleEndian.PutUint16(payload[4:], port)
	return payload
}

// EncodeV6HolePunchControl serializes an IPv6 hole punch control payload.
func EncodeV6HolePunchControl(address [16]byte, port uint16) []byte {
	payload := make([]byte, V6HolePunchPayloadSize)
	copy(payload, address[:])
	binary.LittleEndian.PutUint16(payload[16:], port)
	return payload
}

// DecodeHolePunchControl decodes a V4/V6 hole punch control payload into a
// UDP target address.
func DecodeHolePunchControl(messageType uint8, payload []byte) (*net.UDPAddr, error) {
	switch messageType {
	case UDPPacketTypeV4HolePunch:
		if len(payload) != V4HolePunchPayloadSize {
			return nil, fmt.Errorf("IPv4 hole punch control payload has length %d, want %d", len(payload), V4HolePunchPayloadSize)
		}
		return &net.UDPAddr{IP: net.IP(append([]byte(nil), payload[:4]...)), Port: int(binary.LittleEndian.Uint16(payload[4:]))}, nil
	case UDPPacketTypeV6HolePunch:
		if len(payload) != V6HolePunchPayloadSize {
			return nil, fmt.Errorf("IPv6 hole punch control payload has length %d, want %d", len(payload), V6HolePunchPayloadSize)
		}
		return &net.UDPAddr{IP: net.IP(append([]byte(nil), payload[:16]...)), Port: int(binary.LittleEndian.Uint16(payload[16:]))}, nil
	default:
		return nil, fmt.Errorf("message type %d is not a hole punch control", messageType)
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const ForeignNetworkHeaderSize = 10

// ForeignNetworkPacket wraps a peer packet routed through a shared node.
type ForeignNetworkPacket struct {
	DestinationPeerID uint32
	NetworkName       string
	NestedPacket      Packet
}

// Marshal serializes the EasyTier foreign-network header followed by a nested
// peer packet. The network name is UTF-8 and starts directly after the header.
func (p ForeignNetworkPacket) Marshal() ([]byte, error) {
	if !utf8.ValidString(p.NetworkName) {
		return nil, fmt.Errorf("foreign network name is not valid UTF-8")
	}
	if len(p.NetworkName) > int(^uint16(0))-ForeignNetworkHeaderSize {
		return nil, fmt.Errorf("foreign network name too long: %d", len(p.NetworkName))
	}
	nested, err := p.NestedPacket.MarshalBody()
	if err != nil {
		return nil, fmt.Errorf("marshal nested peer packet: %w", err)
	}

	headerLength := ForeignNetworkHeaderSize + len(p.NetworkName)
	data := make([]byte, headerLength+len(nested))
	binary.LittleEndian.PutUint16(data[0:2], uint16(headerLength))
	binary.LittleEndian.PutUint32(data[2:6], p.DestinationPeerID)
	binary.LittleEndian.PutUint16(data[6:8], ForeignNetworkHeaderSize)
	binary.LittleEndian.PutUint16(data[8:10], uint16(len(p.NetworkName)))
	copy(data[ForeignNetworkHeaderSize:headerLength], p.NetworkName)
	copy(data[headerLength:], nested)
	return data, nil
}

// ParseForeignNetworkPacket validates offsets before parsing the nested peer
// packet. The reference sender uses a ten-byte fixed header and places the
// network name immediately after it; accepting any bounded offset preserves
// the receiver's documented variable-header behavior.
func ParseForeignNetworkPacket(data []byte) (ForeignNetworkPacket, error) {
	if len(data) < ForeignNetworkHeaderSize {
		return ForeignNetworkPacket{}, fmt.Errorf("foreign network packet too short: %d", len(data))
	}

	headerLength := int(binary.LittleEndian.Uint16(data[0:2]))
	nameOffset := int(binary.LittleEndian.Uint16(data[6:8]))
	nameLength := int(binary.LittleEndian.Uint16(data[8:10]))
	nameEnd := nameOffset + nameLength
	if headerLength < ForeignNetworkHeaderSize || headerLength > len(data) {
		return ForeignNetworkPacket{}, fmt.Errorf("invalid foreign network header length: %d", headerLength)
	}
	if nameOffset < ForeignNetworkHeaderSize || nameEnd < nameOffset || nameEnd > headerLength {
		return ForeignNetworkPacket{}, fmt.Errorf("invalid foreign network name range: %d:%d", nameOffset, nameEnd)
	}
	if headerLength == len(data) {
		return ForeignNetworkPacket{}, fmt.Errorf("foreign network packet has no nested peer packet")
	}

	nameBytes := data[nameOffset:nameEnd]
	if !utf8.Valid(nameBytes) {
		return ForeignNetworkPacket{}, fmt.Errorf("foreign network name is not valid UTF-8")
	}
	nested, err := ParseBody(data[headerLength:])
	if err != nil {
		return ForeignNetworkPacket{}, fmt.Errorf("parse nested peer packet: %w", err)
	}
	return ForeignNetworkPacket{
		DestinationPeerID: binary.LittleEndian.Uint32(data[2:6]),
		NetworkName:       string(nameBytes),
		NestedPacket:      nested,
	}, nil
}

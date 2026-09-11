// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package protocol implements byte-level contracts shared with EasyTier 2.6.4.
package protocol

import (
	"encoding/binary"
	"fmt"
)

const (
	PeerManagerHeaderSize = 16

	PacketTypeInvalid            = 0
	PacketTypeData               = 1
	PacketTypeHandshake          = 2
	PacketTypePing               = 4
	PacketTypePong               = 5
	PacketTypeRPCRequest         = 8
	PacketTypeRPCResponse        = 9
	PacketTypeForeignNetwork     = 10
	PacketTypeKCPSrc             = 11
	PacketTypeKCPDst             = 12
	PacketTypeNoiseHandshakeMsg1 = 13
	PacketTypeNoiseHandshakeMsg2 = 14
	PacketTypeNoiseHandshakeMsg3 = 15
	PacketTypeQUICSrc            = 16
	PacketTypeQUICDst            = 17
	PacketTypeRelayHandshake     = 20
	PacketTypeRelayHandshakeAck  = 21

	FlagEncrypted    = 1 << 0
	FlagLatencyFirst = 1 << 1
	FlagExitNode     = 1 << 2
	FlagNoProxy      = 1 << 3
	FlagCompressed   = 1 << 4
	FlagNotSendToTUN = 1 << 6
)

// PeerManagerHeader is the 16-byte little-endian EasyTier peer packet header.
// Length is the payload length and is set by MarshalBody.
type PeerManagerHeader struct {
	FromPeerID     uint32
	ToPeerID       uint32
	PacketType     uint8
	Flags          uint8
	ForwardCounter uint8
	Length         uint32
}

func (h PeerManagerHeader) IsCompressed() bool { return h.Flags&FlagCompressed != 0 }

func (h *PeerManagerHeader) SetCompressed(compressed bool) {
	if compressed {
		h.Flags |= FlagCompressed
	} else {
		h.Flags &^= FlagCompressed
	}
}

// Packet is a complete EasyTier peer packet without a transport envelope.
type Packet struct {
	Header  PeerManagerHeader
	Payload []byte
}

// MarshalBody serializes the peer header followed by its payload.
func (p Packet) MarshalBody() ([]byte, error) {
	if uint64(len(p.Payload)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("peer payload exceeds uint32 length: %d", len(p.Payload))
	}
	if p.Header.Flags&FlagCompressed == 0 {
		p.Header.Length = uint32(len(p.Payload))
	} else if len(p.Payload) < CompressionTailSize {
		return nil, fmt.Errorf("compressed peer packet is missing algorithm tail")
	}

	body := make([]byte, PeerManagerHeaderSize+len(p.Payload))
	binary.LittleEndian.PutUint32(body[0:4], p.Header.FromPeerID)
	binary.LittleEndian.PutUint32(body[4:8], p.Header.ToPeerID)
	body[8] = p.Header.PacketType
	body[9] = p.Header.Flags
	body[10] = p.Header.ForwardCounter
	binary.LittleEndian.PutUint32(body[12:16], p.Header.Length)
	copy(body[PeerManagerHeaderSize:], p.Payload)
	return body, nil
}

// ParseBody parses and validates one peer header and its payload.
func ParseBody(body []byte) (Packet, error) {
	if len(body) < PeerManagerHeaderSize {
		return Packet{}, fmt.Errorf("peer packet too short: %d", len(body))
	}

	payloadLength := binary.LittleEndian.Uint32(body[12:16])
	wirePayloadLength := len(body) - PeerManagerHeaderSize
	if body[9]&FlagCompressed == 0 && payloadLength != uint32(wirePayloadLength) {
		return Packet{}, fmt.Errorf("uncompressed peer payload length %d does not match body length %d", payloadLength, len(body)-PeerManagerHeaderSize)
	}
	if body[9]&FlagCompressed != 0 && wirePayloadLength < CompressionTailSize {
		return Packet{}, fmt.Errorf("compressed peer packet is missing algorithm tail")
	}

	payload := make([]byte, wirePayloadLength)
	copy(payload, body[PeerManagerHeaderSize:])
	return Packet{
		Header: PeerManagerHeader{
			FromPeerID:     binary.LittleEndian.Uint32(body[0:4]),
			ToPeerID:       binary.LittleEndian.Uint32(body[4:8]),
			PacketType:     body[8],
			Flags:          body[9],
			ForwardCounter: body[10],
			Length:         payloadLength,
		},
		Payload: payload,
	}, nil
}

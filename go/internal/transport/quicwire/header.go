// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Version1 is QUIC v1 (RFC 9000).
	Version1 uint32 = 0x00000001

	// Packet types for Long Header
	PacketTypeInitial   byte = 0x00
	PacketType0RTT      byte = 0x01
	PacketTypeHandshake byte = 0x02
	PacketTypeRetry     byte = 0x03

	// TagLen is the 8-byte checksum length in quinn-plaintext
	TagLen = 8
)

var (
	ErrInvalidHeader    = errors.New("quic: invalid packet header")
	ErrChecksumMismatch = errors.New("quic: seahash checksum mismatch")
	ErrPacketTooShort   = errors.New("quic: packet too short")
)

// Header represents a parsed QUIC packet header.
type Header struct {
	IsLongHeader bool
	Type         byte // PacketTypeInitial, etc. for Long Header
	Version      uint32
	DestCID      []byte
	SrcCID       []byte
	Token        []byte // for Initial packets
	Length       uint64 // payload length (including PN and Tag)
	PacketNumber uint64
	PNLen        int
	HeaderLen    int // total byte length of header (up to start of payload)
}

// ParseHeader parses the header of a QUIC datagram packet.
// For short headers, destCIDLen must be provided from the connection state (default 8 if unknown).
func ParseHeader(b []byte, destCIDLen int, largestPN uint64) (*Header, []byte, error) {
	if len(b) < 1 {
		return nil, nil, io.ErrUnexpectedEOF
	}

	firstByte := b[0]
	isLong := (firstByte & 0x80) != 0

	h := &Header{
		IsLongHeader: isLong,
	}

	if isLong {
		// Long Header
		if len(b) < 5 {
			return nil, nil, io.ErrUnexpectedEOF
		}
		h.Type = (firstByte >> 4) & 0x03
		h.PNLen = int(firstByte&0x03) + 1
		h.Version = binary.BigEndian.Uint32(b[1:5])

		idx := 5
		if len(b) <= idx {
			return nil, nil, io.ErrUnexpectedEOF
		}
		dcil := int(b[idx])
		idx++
		if len(b) < idx+dcil {
			return nil, nil, io.ErrUnexpectedEOF
		}
		h.DestCID = append([]byte(nil), b[idx:idx+dcil]...)
		idx += dcil

		if len(b) <= idx {
			return nil, nil, io.ErrUnexpectedEOF
		}
		scil := int(b[idx])
		idx++
		if len(b) < idx+scil {
			return nil, nil, io.ErrUnexpectedEOF
		}
		h.SrcCID = append([]byte(nil), b[idx:idx+scil]...)
		idx += scil

		if h.Type == PacketTypeInitial {
			tokenLen, n, err := ReadVarint(b[idx:])
			if err != nil {
				return nil, nil, err
			}
			idx += n
			if len(b) < idx+int(tokenLen) {
				return nil, nil, io.ErrUnexpectedEOF
			}
			if tokenLen > 0 {
				h.Token = append([]byte(nil), b[idx:idx+int(tokenLen)]...)
				idx += int(tokenLen)
			}
		}

		length, n, err := ReadVarint(b[idx:])
		if err != nil {
			return nil, nil, err
		}
		idx += n
		h.Length = length

		// Read packet number
		truncPN, err := ReadPacketNumber(b[idx:], h.PNLen)
		if err != nil {
			return nil, nil, err
		}
		idx += h.PNLen
		h.PacketNumber = DecodePacketNumber(truncPN, h.PNLen, largestPN)
		h.HeaderLen = idx

		// In QUIC, h.Length covers PN + Payload + Tag.
		// Since we already read PN of h.PNLen, payload + tag is (h.Length - h.PNLen).
		if h.Length < uint64(h.PNLen)+TagLen {
			return nil, nil, fmt.Errorf("length (%d) too short for PN (%d) + Tag (%d)", h.Length, h.PNLen, TagLen)
		}
		totalPacketLen := h.HeaderLen + int(h.Length) - h.PNLen
		if len(b) < totalPacketLen {
			return nil, nil, fmt.Errorf("packet buffer len %d < totalPacketLen %d", len(b), totalPacketLen)
		}

		payloadWithTag := b[idx:totalPacketLen]
		return h, payloadWithTag, nil
	}

	// Short Header (1-RTT)
	h.PNLen = int(firstByte&0x03) + 1
	idx := 1
	if destCIDLen < 0 {
		destCIDLen = 8
	}
	if len(b) < idx+destCIDLen {
		return nil, nil, io.ErrUnexpectedEOF
	}
	h.DestCID = append([]byte(nil), b[idx:idx+destCIDLen]...)
	idx += destCIDLen

	truncPN, err := ReadPacketNumber(b[idx:], h.PNLen)
	if err != nil {
		return nil, nil, err
	}
	idx += h.PNLen
	h.PacketNumber = DecodePacketNumber(truncPN, h.PNLen, largestPN)
	h.HeaderLen = idx

	if len(b) < h.HeaderLen+TagLen {
		return nil, nil, ErrPacketTooShort
	}

	payloadWithTag := b[idx:]
	return h, payloadWithTag, nil
}

// VerifyAndSplitPayload checks the 8-byte SeaHash checksum in quinn-plaintext mode
// and returns the raw frames payload without tag.
func VerifyAndSplitPayload(headerBytes, payloadWithTag []byte) ([]byte, error) {
	if len(payloadWithTag) < TagLen {
		return nil, ErrPacketTooShort
	}
	payloadLen := len(payloadWithTag) - TagLen
	payload := payloadWithTag[:payloadLen]
	tag := payloadWithTag[payloadLen:]

	expectedChecksum := binary.BigEndian.Uint64(tag)
	actualChecksum := QuinnPlaintextChecksum(headerBytes, payload)
	if expectedChecksum != actualChecksum {
		return nil, fmt.Errorf("%w: got %x, expected %x", ErrChecksumMismatch, actualChecksum, expectedChecksum)
	}
	return payload, nil
}

// AppendLongHeader encodes a Long Header packet into dst.
// payloadLen is the length of frames (without PN and without Tag).
func AppendLongHeader(dst []byte, pktType byte, version uint32, destCID, srcCID, token []byte, pn uint64, pnLen int, payloadLen int) []byte {
	firstByte := byte(0xc0 | (pktType << 4) | byte(pnLen-1))
	dst = append(dst, firstByte)

	var vBuf [4]byte
	binary.BigEndian.PutUint32(vBuf[:], version)
	dst = append(dst, vBuf[:]...)

	dst = append(dst, byte(len(destCID)))
	dst = append(dst, destCID...)

	dst = append(dst, byte(len(srcCID)))
	dst = append(dst, srcCID...)

	if pktType == PacketTypeInitial {
		dst = AppendVarint(dst, uint64(len(token)))
		if len(token) > 0 {
			dst = append(dst, token...)
		}
	}

	// Length = PNLen + payloadLen + TagLen
	totalLen := uint64(pnLen + payloadLen + TagLen)
	dst = AppendVarint(dst, totalLen)

	pnStart := len(dst)
	dst = append(dst, make([]byte, pnLen)...)
	PutPacketNumber(dst[pnStart:], pn, pnLen)

	return dst
}

// AppendShortHeader encodes a 1-RTT Short Header packet into dst.
func AppendShortHeader(dst []byte, destCID []byte, pn uint64, pnLen int) []byte {
	firstByte := byte(0x40 | byte(pnLen-1))
	dst = append(dst, firstByte)
	dst = append(dst, destCID...)

	pnStart := len(dst)
	dst = append(dst, make([]byte, pnLen)...)
	PutPacketNumber(dst[pnStart:], pn, pnLen)

	return dst
}

// SealPacket appends payload frames and the 8-byte SeaHash checksum to headerBytes.
func SealPacket(headerBytes, payload []byte) []byte {
	checksum := QuinnPlaintextChecksum(headerBytes, payload)
	res := append(headerBytes, payload...)
	var tagBuf [TagLen]byte
	binary.BigEndian.PutUint64(tagBuf[:], checksum)
	return append(res, tagBuf[:]...)
}

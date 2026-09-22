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
	// MaxVarint is the maximum value representable as a QUIC variable-length integer (2^62 - 1).
	MaxVarint = (1 << 62) - 1
)

var (
	ErrVarintOverflow = errors.New("quic: variable-length integer overflow")
)

// VarintLen returns the number of bytes required to encode v as a QUIC varint.
func VarintLen(v uint64) int {
	if v < 64 {
		return 1
	}
	if v < 16384 {
		return 2
	}
	if v < 1073741824 {
		return 4
	}
	return 8
}

// AppendVarint appends the QUIC variable-length integer encoding of v to b and returns the extended slice.
func AppendVarint(b []byte, v uint64) []byte {
	if v < 64 {
		return append(b, byte(v))
	}
	if v < 16384 {
		return append(b, byte(0x40|(v>>8)), byte(v))
	}
	if v < 1073741824 {
		return append(b,
			byte(0x80|(v>>24)),
			byte(v>>16),
			byte(v>>8),
			byte(v),
		)
	}
	return append(b,
		byte(0xc0|(v>>56)),
		byte(v>>48),
		byte(v>>40),
		byte(v>>32),
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}

// ReadVarint reads a QUIC variable-length integer from b.
// It returns the decoded value, the number of bytes read, or an error if b is too short.
func ReadVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	first := b[0]
	tag := first >> 6
	switch tag {
	case 0:
		return uint64(first & 0x3f), 1, nil
	case 1:
		if len(b) < 2 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		val := uint64(first&0x3f)<<8 | uint64(b[1])
		return val, 2, nil
	case 2:
		if len(b) < 4 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		val := uint64(first&0x3f)<<24 |
			uint64(b[1])<<16 |
			uint64(b[2])<<8 |
			uint64(b[3])
		return val, 4, nil
	case 3:
		if len(b) < 8 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		val := uint64(first&0x3f)<<56 |
			uint64(b[1])<<48 |
			uint64(b[2])<<40 |
			uint64(b[3])<<32 |
			uint64(b[4])<<24 |
			uint64(b[5])<<16 |
			uint64(b[6])<<8 |
			uint64(b[7])
		return val, 8, nil
	}
	return 0, 0, fmt.Errorf("invalid varint tag %d", tag)
}

// ReadVarintU64 is a convenience wrapper when reading from a byte slice with bounds check.
func ReadVarintU64(b []byte) (val uint64, rest []byte, err error) {
	v, n, err := ReadVarint(b)
	if err != nil {
		return 0, nil, err
	}
	return v, b[n:], nil
}

// WriteVarint writes v to w as a QUIC varint.
func WriteVarint(w io.Writer, v uint64) error {
	var buf [8]byte
	s := AppendVarint(buf[:0], v)
	_, err := w.Write(s)
	return err
}

// PutVarint encodes v into b and returns the number of bytes written.
// Panics if b is too small.
func PutVarint(b []byte, v uint64) int {
	res := AppendVarint(b[:0], v)
	return len(res)
}

// DecodePacketNumber restores the full packet number from a truncated packet number
// given the largest acknowledged packet number, according to RFC 9000 Appendix A.
func DecodePacketNumber(truncatedPN uint64, pnLen int, largestPN uint64) uint64 {
	pnNbBits := uint(pnLen * 8)
	expectedPN := largestPN + 1
	pnWin := uint64(1) << pnNbBits
	pnHwin := pnWin / 2
	pnMask := pnWin - 1

	candidate := (expectedPN & ^pnMask) | truncatedPN
	if expectedPN >= pnHwin && candidate <= expectedPN-pnHwin && candidate < (1<<62)-pnWin {
		return candidate + pnWin
	}
	if candidate > expectedPN+pnHwin && candidate >= pnWin {
		return candidate - pnWin
	}
	return candidate
}

// EncodePacketNumber returns the smallest truncated packet number and its length (1..4)
// needed to convey packetNumber given largestAcked, per RFC 9000 Section 17.1.
func EncodePacketNumber(packetNumber, largestAcked uint64) (truncated uint64, length int) {
	var diff uint64
	if packetNumber > largestAcked {
		diff = (packetNumber - largestAcked) * 2
	} else {
		diff = (largestAcked - packetNumber) * 2
	}
	if diff < (1 << 8) {
		return packetNumber & 0xff, 1
	}
	if diff < (1 << 16) {
		return packetNumber & 0xffff, 2
	}
	if diff < (1 << 24) {
		return packetNumber & 0xffffff, 3
	}
	return packetNumber & 0xffffffff, 4
}

// PutPacketNumber writes a truncated packet number of pnLen bytes (1..4) in big-endian order.
func PutPacketNumber(b []byte, pn uint64, pnLen int) {
	switch pnLen {
	case 1:
		b[0] = byte(pn)
	case 2:
		binary.BigEndian.PutUint16(b[:2], uint16(pn))
	case 3:
		b[0] = byte(pn >> 16)
		b[1] = byte(pn >> 8)
		b[2] = byte(pn)
	case 4:
		binary.BigEndian.PutUint32(b[:4], uint32(pn))
	default:
		panic("invalid pnLen")
	}
}

// ReadPacketNumber reads a packet number of pnLen bytes (1..4) in big-endian order.
func ReadPacketNumber(b []byte, pnLen int) (uint64, error) {
	if len(b) < pnLen {
		return 0, io.ErrUnexpectedEOF
	}
	switch pnLen {
	case 1:
		return uint64(b[0]), nil
	case 2:
		return uint64(binary.BigEndian.Uint16(b[:2])), nil
	case 3:
		return uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2]), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(b[:4])), nil
	default:
		return 0, errors.New("invalid pnLen")
	}
}

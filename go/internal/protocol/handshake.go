// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"fmt"
	"unicode/utf8"
)

const (
	HandshakeMagic   uint32 = 0xd1e1a5e1
	HandshakeVersion uint32 = 1

	handshakeDigestSize = 32
)

// HandshakeRequest is the legacy direct-handshake peer_rpc message.
type HandshakeRequest struct {
	Magic               uint32
	MyPeerID            uint32
	Version             uint32
	Features            []string
	NetworkName         string
	NetworkSecretDigest []byte
}

// Marshal serializes a HandshakeRequest using the protobuf wire format. Zero
// scalar values and empty length-delimited values use protobuf's default-value
// omission rules.
func (r HandshakeRequest) Marshal() ([]byte, error) {
	if !utf8.ValidString(r.NetworkName) {
		return nil, fmt.Errorf("handshake network name is not valid UTF-8")
	}
	data := make([]byte, 0, 32+len(r.NetworkName)+len(r.NetworkSecretDigest))
	if r.Magic != 0 {
		data = appendVarintField(data, 1, uint64(r.Magic))
	}
	if r.MyPeerID != 0 {
		data = appendVarintField(data, 2, uint64(r.MyPeerID))
	}
	if r.Version != 0 {
		data = appendVarintField(data, 3, uint64(r.Version))
	}
	for _, feature := range r.Features {
		if !utf8.ValidString(feature) {
			return nil, fmt.Errorf("handshake feature is not valid UTF-8")
		}
		data = appendBytesField(data, 4, []byte(feature))
	}
	if r.NetworkName != "" {
		data = appendBytesField(data, 5, []byte(r.NetworkName))
	}
	if len(r.NetworkSecretDigest) != 0 {
		data = appendBytesField(data, 6, r.NetworkSecretDigest)
	}
	return data, nil
}

// ParseHandshakeRequest parses a legacy direct-handshake peer_rpc message.
// Unknown fields with protobuf wire types 0, 1, 2, and 5 are skipped.
func ParseHandshakeRequest(data []byte) (HandshakeRequest, error) {
	var request HandshakeRequest
	digestPresent := false
	for offset := 0; offset < len(data); {
		key, err := readHandshakeVarint(data, &offset)
		if err != nil {
			return HandshakeRequest{}, fmt.Errorf("read handshake field key: %w", err)
		}
		fieldNumber := key >> 3
		wireType := key & 7
		if fieldNumber == 0 {
			return HandshakeRequest{}, fmt.Errorf("handshake field number is zero")
		}

		switch fieldNumber {
		case 1, 2, 3:
			if wireType != 0 {
				return HandshakeRequest{}, fmt.Errorf("handshake field %d has wire type %d, want 0", fieldNumber, wireType)
			}
			value, err := readHandshakeVarint(data, &offset)
			if err != nil {
				return HandshakeRequest{}, fmt.Errorf("read handshake field %d: %w", fieldNumber, err)
			}
			if value > uint64(^uint32(0)) {
				return HandshakeRequest{}, fmt.Errorf("handshake field %d value %d exceeds uint32", fieldNumber, value)
			}
			switch fieldNumber {
			case 1:
				request.Magic = uint32(value)
			case 2:
				request.MyPeerID = uint32(value)
			case 3:
				request.Version = uint32(value)
			}
		case 4, 5, 6:
			if wireType != 2 {
				return HandshakeRequest{}, fmt.Errorf("handshake field %d has wire type %d, want 2", fieldNumber, wireType)
			}
			value, err := readHandshakeBytes(data, &offset)
			if err != nil {
				return HandshakeRequest{}, fmt.Errorf("read handshake field %d: %w", fieldNumber, err)
			}
			switch fieldNumber {
			case 4:
				if !utf8.Valid(value) {
					return HandshakeRequest{}, fmt.Errorf("handshake feature is not valid UTF-8")
				}
				request.Features = append(request.Features, string(value))
			case 5:
				if !utf8.Valid(value) {
					return HandshakeRequest{}, fmt.Errorf("handshake network name is not valid UTF-8")
				}
				request.NetworkName = string(value)
			case 6:
				digestPresent = true
				request.NetworkSecretDigest = append(request.NetworkSecretDigest[:0], value...)
			}
		default:
			if err := skipHandshakeField(data, &offset, wireType); err != nil {
				return HandshakeRequest{}, fmt.Errorf("skip handshake field %d: %w", fieldNumber, err)
			}
		}
	}
	if digestPresent && len(request.NetworkSecretDigest) != handshakeDigestSize {
		return HandshakeRequest{}, fmt.Errorf("handshake network secret digest length %d, want %d", len(request.NetworkSecretDigest), handshakeDigestSize)
	}
	return request, nil
}

func appendVarintField(data []byte, fieldNumber uint64, value uint64) []byte {
	data = appendHandshakeVarint(data, fieldNumber<<3)
	return appendHandshakeVarint(data, value)
}

func appendBytesField(data []byte, fieldNumber uint64, value []byte) []byte {
	data = appendHandshakeVarint(data, fieldNumber<<3|2)
	data = appendHandshakeVarint(data, uint64(len(value)))
	return append(data, value...)
}

func appendHandshakeVarint(data []byte, value uint64) []byte {
	for value >= 0x80 {
		data = append(data, byte(value)|0x80)
		value >>= 7
	}
	return append(data, byte(value))
}

func readHandshakeVarint(data []byte, offset *int) (uint64, error) {
	var value uint64
	for shift := uint(0); shift < 64; shift += 7 {
		if *offset == len(data) {
			return 0, fmt.Errorf("truncated varint")
		}
		b := data[*offset]
		*offset++
		if shift == 63 && b > 1 {
			return 0, fmt.Errorf("varint overflows uint64")
		}
		value |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("varint exceeds 10 bytes")
}

func readHandshakeBytes(data []byte, offset *int) ([]byte, error) {
	length, err := readHandshakeVarint(data, offset)
	if err != nil {
		return nil, err
	}
	remaining := len(data) - *offset
	if length > uint64(remaining) {
		return nil, fmt.Errorf("length %d exceeds remaining data %d", length, remaining)
	}
	end := *offset + int(length)
	value := data[*offset:end]
	*offset = end
	return value, nil
}

func skipHandshakeField(data []byte, offset *int, wireType uint64) error {
	switch wireType {
	case 0:
		_, err := readHandshakeVarint(data, offset)
		return err
	case 1:
		if len(data)-*offset < 8 {
			return fmt.Errorf("truncated fixed64")
		}
		*offset += 8
		return nil
	case 2:
		_, err := readHandshakeBytes(data, offset)
		return err
	case 5:
		if len(data)-*offset < 4 {
			return fmt.Errorf("truncated fixed32")
		}
		*offset += 4
		return nil
	default:
		return fmt.Errorf("unsupported wire type %d", wireType)
	}
}

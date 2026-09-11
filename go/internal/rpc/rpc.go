// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package rpc implements the EasyTier common RPC protobuf messages.
package rpc

import (
	"fmt"
	"math"
	"unicode/utf8"
)

const maxPieces = 32 * 1024

// RpcDescriptor identifies an EasyTier RPC method.
type RpcDescriptor struct {
	DomainName  string
	ProtoName   string
	ServiceName string
	MethodIndex uint32
}

// CompressionAlgo matches common.proto's CompressionAlgoPb values.
type CompressionAlgo uint32

const (
	CompressionAlgoInvalid CompressionAlgo = iota
	CompressionAlgoNone
	CompressionAlgoZstd
)

type RpcCompressionInfo struct {
	Algo         CompressionAlgo
	AcceptedAlgo CompressionAlgo
}

// RpcPacket is the wire representation of an EasyTier RPC request or response.
type RpcPacket struct {
	FromPeer        uint32
	ToPeer          uint32
	TransactionID   int64
	Descriptor      *RpcDescriptor
	Body            []byte
	IsRequest       bool
	TotalPieces     uint32
	PieceIdx        uint32
	TraceID         int32
	CompressionInfo *RpcCompressionInfo
}

func (c RpcCompressionInfo) Marshal() []byte {
	b := make([]byte, 0, 4)
	if c.Algo != CompressionAlgoInvalid {
		b = appendVarint(b, 1, uint64(c.Algo))
	}
	if c.AcceptedAlgo != CompressionAlgoInvalid {
		b = appendVarint(b, 2, uint64(c.AcceptedAlgo))
	}
	return b
}

func unmarshalRpcCompressionInfo(b []byte) (RpcCompressionInfo, error) {
	var info RpcCompressionInfo
	for len(b) > 0 {
		field, wire, n, err := readKey(b)
		if err != nil {
			return RpcCompressionInfo{}, err
		}
		b = b[n:]
		if field != 1 && field != 2 {
			used, err := skipField(wire, b)
			if err != nil {
				return RpcCompressionInfo{}, err
			}
			b = b[used:]
			continue
		}
		if wire != 0 {
			return RpcCompressionInfo{}, wireTypeError(field, wire)
		}
		value, used, err := readVarint(b)
		if err != nil {
			return RpcCompressionInfo{}, err
		}
		if field == 1 {
			info.Algo = CompressionAlgo(value)
		} else {
			info.AcceptedAlgo = CompressionAlgo(value)
		}
		b = b[used:]
	}
	return info, nil
}

// Validate verifies values whose Go representation can contain invalid protobuf
// data. An absent descriptor is valid because it is optional in RpcPacket.
func (d RpcDescriptor) Validate() error {
	if !utf8.ValidString(d.DomainName) || !utf8.ValidString(d.ProtoName) || !utf8.ValidString(d.ServiceName) {
		return fmt.Errorf("rpc descriptor contains invalid UTF-8")
	}
	return nil
}

// Validate verifies that the packet can be encoded as an RPC protobuf message.
func (p RpcPacket) Validate() error {
	if p.Descriptor != nil {
		return p.Descriptor.Validate()
	}
	return nil
}

// Marshal serializes a descriptor using the protobuf wire format.
func (d RpcDescriptor) Marshal() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 0, len(d.DomainName)+len(d.ProtoName)+len(d.ServiceName)+16)
	if d.DomainName != "" {
		b = appendBytes(b, 1, []byte(d.DomainName))
	}
	if d.ProtoName != "" {
		b = appendBytes(b, 2, []byte(d.ProtoName))
	}
	if d.ServiceName != "" {
		b = appendBytes(b, 3, []byte(d.ServiceName))
	}
	if d.MethodIndex != 0 {
		b = appendVarint(b, 4, uint64(d.MethodIndex))
	}
	return b, nil
}

// Marshal serializes a packet using the protobuf wire format in field-number order.
func (p RpcPacket) Marshal() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 0, len(p.Body)+64)
	if p.FromPeer != 0 {
		b = appendVarint(b, 1, uint64(p.FromPeer))
	}
	if p.ToPeer != 0 {
		b = appendVarint(b, 2, uint64(p.ToPeer))
	}
	if p.TransactionID != 0 {
		b = appendVarint(b, 3, uint64(p.TransactionID))
	}
	if p.Descriptor != nil {
		d, err := p.Descriptor.Marshal()
		if err != nil {
			return nil, err
		}
		b = appendBytes(b, 4, d)
	}
	if len(p.Body) != 0 {
		b = appendBytes(b, 5, p.Body)
	}
	if p.IsRequest {
		b = appendVarint(b, 6, 1)
	}
	if p.TotalPieces != 0 {
		b = appendVarint(b, 7, uint64(p.TotalPieces))
	}
	if p.PieceIdx != 0 {
		b = appendVarint(b, 8, uint64(p.PieceIdx))
	}
	if p.TraceID != 0 {
		b = appendVarint(b, 9, uint64(int64(p.TraceID)))
	}
	if p.CompressionInfo != nil {
		b = appendBytes(b, 10, p.CompressionInfo.Marshal())
	}
	return b, nil
}

// UnmarshalRpcDescriptor parses one complete, bounded protobuf descriptor.
func UnmarshalRpcDescriptor(b []byte) (RpcDescriptor, error) {
	var d RpcDescriptor
	for len(b) > 0 {
		field, wire, n, err := readKey(b)
		if err != nil {
			return RpcDescriptor{}, err
		}
		b = b[n:]
		switch field {
		case 1, 2, 3:
			if wire != 2 {
				return RpcDescriptor{}, wireTypeError(field, wire)
			}
			v, used, err := readBytes(b)
			if err != nil {
				return RpcDescriptor{}, err
			}
			if !utf8.Valid(v) {
				return RpcDescriptor{}, fmt.Errorf("rpc descriptor field %d contains invalid UTF-8", field)
			}
			switch field {
			case 1:
				d.DomainName = string(v)
			case 2:
				d.ProtoName = string(v)
			case 3:
				d.ServiceName = string(v)
			}
			b = b[used:]
		case 4:
			if wire != 0 {
				return RpcDescriptor{}, wireTypeError(field, wire)
			}
			v, used, err := readVarint(b)
			if err != nil {
				return RpcDescriptor{}, err
			}
			if v > math.MaxUint32 {
				return RpcDescriptor{}, fmt.Errorf("rpc descriptor method_index overflows uint32")
			}
			d.MethodIndex = uint32(v)
			b = b[used:]
		default:
			used, err := skipField(wire, b)
			if err != nil {
				return RpcDescriptor{}, err
			}
			b = b[used:]
		}
	}
	return d, nil
}

// UnmarshalRpcPacket parses one complete, bounded protobuf RPC packet.
func UnmarshalRpcPacket(b []byte) (RpcPacket, error) {
	var p RpcPacket
	for len(b) > 0 {
		field, wire, n, err := readKey(b)
		if err != nil {
			return RpcPacket{}, err
		}
		b = b[n:]
		switch field {
		case 1, 2, 3, 6, 7, 8, 9:
			if wire != 0 {
				return RpcPacket{}, wireTypeError(field, wire)
			}
			v, used, err := readVarint(b)
			if err != nil {
				return RpcPacket{}, err
			}
			switch field {
			case 1:
				if v > math.MaxUint32 {
					return RpcPacket{}, fmt.Errorf("rpc packet from_peer overflows uint32")
				}
				p.FromPeer = uint32(v)
			case 2:
				if v > math.MaxUint32 {
					return RpcPacket{}, fmt.Errorf("rpc packet to_peer overflows uint32")
				}
				p.ToPeer = uint32(v)
			case 3:
				p.TransactionID = int64(v)
			case 6:
				p.IsRequest = v != 0
			case 7:
				if v > math.MaxUint32 {
					return RpcPacket{}, fmt.Errorf("rpc packet total_pieces overflows uint32")
				}
				p.TotalPieces = uint32(v)
			case 8:
				if v > math.MaxUint32 {
					return RpcPacket{}, fmt.Errorf("rpc packet piece_idx overflows uint32")
				}
				p.PieceIdx = uint32(v)
			case 9:
				p.TraceID = int32(v)
			}
			b = b[used:]
		case 4:
			if wire != 2 {
				return RpcPacket{}, wireTypeError(field, wire)
			}
			v, used, err := readBytes(b)
			if err != nil {
				return RpcPacket{}, err
			}
			d, err := UnmarshalRpcDescriptor(v)
			if err != nil {
				return RpcPacket{}, fmt.Errorf("rpc packet descriptor: %w", err)
			}
			p.Descriptor = &d
			b = b[used:]
		case 5:
			if wire != 2 {
				return RpcPacket{}, wireTypeError(field, wire)
			}
			v, used, err := readBytes(b)
			if err != nil {
				return RpcPacket{}, err
			}
			p.Body = append(p.Body[:0], v...)
			b = b[used:]
		case 10:
			if wire != 2 {
				return RpcPacket{}, wireTypeError(field, wire)
			}
			v, used, err := readBytes(b)
			if err != nil {
				return RpcPacket{}, err
			}
			info, err := unmarshalRpcCompressionInfo(v)
			if err != nil {
				return RpcPacket{}, fmt.Errorf("rpc packet compression_info: %w", err)
			}
			p.CompressionInfo = &info
			b = b[used:]
		default:
			used, err := skipField(wire, b)
			if err != nil {
				return RpcPacket{}, err
			}
			b = b[used:]
		}
	}
	return p, nil
}

func appendVarint(b []byte, field uint64, value uint64) []byte {
	b = appendWireVarint(b, field<<3)
	return appendWireVarint(b, value)
}

func appendBytes(b []byte, field uint64, value []byte) []byte {
	b = appendWireVarint(b, field<<3|2)
	b = appendWireVarint(b, uint64(len(value)))
	return append(b, value...)
}

func appendWireVarint(b []byte, value uint64) []byte {
	for value >= 0x80 {
		b = append(b, byte(value)|0x80)
		value >>= 7
	}
	return append(b, byte(value))
}

func readKey(b []byte) (uint64, uint64, int, error) {
	v, n, err := readVarint(b)
	if err != nil {
		return 0, 0, 0, err
	}
	field, wire := v>>3, v&7
	if field == 0 {
		return 0, 0, 0, fmt.Errorf("protobuf field number is zero")
	}
	return field, wire, n, nil
}

func readVarint(b []byte) (uint64, int, error) {
	var value uint64
	for i := 0; i < 10; i++ {
		if i == len(b) {
			return 0, 0, fmt.Errorf("truncated protobuf varint")
		}
		c := b[i]
		if i == 9 && c > 1 {
			return 0, 0, fmt.Errorf("protobuf varint overflows uint64")
		}
		value |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return value, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("protobuf varint exceeds 10 bytes")
}

func readBytes(b []byte) ([]byte, int, error) {
	length, n, err := readVarint(b)
	if err != nil {
		return nil, 0, err
	}
	if length > uint64(len(b)-n) {
		return nil, 0, fmt.Errorf("truncated protobuf length-delimited field")
	}
	end := n + int(length)
	return b[n:end], end, nil
}

func skipField(wire uint64, b []byte) (int, error) {
	switch wire {
	case 0:
		_, n, err := readVarint(b)
		return n, err
	case 1:
		if len(b) < 8 {
			return 0, fmt.Errorf("truncated protobuf fixed64 field")
		}
		return 8, nil
	case 2:
		_, n, err := readBytes(b)
		return n, err
	case 5:
		if len(b) < 4 {
			return 0, fmt.Errorf("truncated protobuf fixed32 field")
		}
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported protobuf wire type %d", wire)
	}
}

func wireTypeError(field, wire uint64) error {
	return fmt.Errorf("rpc protobuf field %d has wire type %d", field, wire)
}

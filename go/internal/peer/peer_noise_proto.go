// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type peerUUID [16]byte

type peerConnNoiseMsg1 struct {
	Version                   uint32
	NetworkName               string
	SessionGeneration         uint32
	HasSessionGeneration      bool
	ConnID                    peerUUID
	ClientEncryptionAlgorithm string
}

type peerConnNoiseMsg2 struct {
	NetworkName               string
	RoleHint                  uint32
	Action                    uint32
	SessionGeneration         uint32
	RootKey                   []byte
	InitialEpoch              uint32
	BConnID                   peerUUID
	AConnIDEcho               peerUUID
	SecretProof               []byte
	ServerEncryptionAlgorithm string
}

type peerConnNoiseMsg3 struct {
	AConnIDEcho  peerUUID
	BConnIDEcho  peerUUID
	SecretProof  []byte
	SecretDigest []byte
}

func appendVarint(dst []byte, field int, value uint32) []byte {
	if field != 0 {
		dst = append(dst, byte(field<<3))
	}
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

func appendBytes(dst []byte, field int, value []byte) []byte {
	dst = append(dst, byte(field<<3|2))
	dst = appendVarint(dst, 0, uint32(len(value)))
	return append(dst, value...)
}

func appendString(dst []byte, field int, value string) []byte {
	return appendBytes(dst, field, []byte(value))
}

func marshalUUID(id peerUUID) []byte {
	var out []byte
	for i := 0; i < 4; i++ {
		value := binary.BigEndian.Uint32(id[i*4:])
		if value != 0 {
			out = appendVarint(out, i+1, value)
		}
	}
	return out
}

func appendUUID(dst []byte, field int, id peerUUID) []byte {
	return appendBytes(dst, field, marshalUUID(id))
}

func (m peerConnNoiseMsg1) marshal() []byte {
	var out []byte
	out = appendVarint(out, 1, m.Version)
	out = appendString(out, 2, m.NetworkName)
	if m.HasSessionGeneration {
		out = appendVarint(out, 3, m.SessionGeneration)
	}
	out = appendUUID(out, 4, m.ConnID)
	return appendString(out, 5, m.ClientEncryptionAlgorithm)
}

func (m peerConnNoiseMsg2) marshal() []byte {
	var out []byte
	out = appendString(out, 1, m.NetworkName)
	out = appendVarint(out, 2, m.RoleHint)
	out = appendVarint(out, 3, m.Action)
	out = appendVarint(out, 4, m.SessionGeneration)
	if m.RootKey != nil {
		out = appendBytes(out, 5, m.RootKey)
	}
	out = appendVarint(out, 6, m.InitialEpoch)
	out = appendUUID(out, 7, m.BConnID)
	out = appendUUID(out, 8, m.AConnIDEcho)
	if m.SecretProof != nil {
		out = appendBytes(out, 9, m.SecretProof)
	}
	return appendString(out, 10, m.ServerEncryptionAlgorithm)
}

func (m peerConnNoiseMsg3) marshal() []byte {
	var out []byte
	out = appendUUID(out, 1, m.AConnIDEcho)
	out = appendUUID(out, 2, m.BConnIDEcho)
	if m.SecretProof != nil {
		out = appendBytes(out, 3, m.SecretProof)
	}
	return appendBytes(out, 4, m.SecretDigest)
}

type protoReader struct {
	data []byte
	pos  int
}

func (r *protoReader) varint() (uint32, error) {
	var value uint32
	for i := 0; i < 5; i++ {
		if r.pos >= len(r.data) {
			return 0, errors.New("truncated varint")
		}
		b := r.data[r.pos]
		r.pos++
		// A uint32 varint may use up to four payload bits in its fifth byte.
		if i == 4 && b > 0x0f {
			return 0, errors.New("varint overflows uint32")
		}
		value |= uint32(b&0x7f) << (7 * i)
		if b < 0x80 {
			return value, nil
		}
	}
	return 0, errors.New("varint is too long")
}

func (r *protoReader) field() (int, int, error) {
	v, err := r.varint()
	if err != nil {
		return 0, 0, err
	}
	if v == 0 || v>>3 > 0x1fffffff {
		return 0, 0, errors.New("invalid protobuf field")
	}
	return int(v >> 3), int(v & 7), nil
}

func (r *protoReader) bytes() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(len(r.data)-r.pos) {
		return nil, errors.New("length exceeds protobuf payload")
	}
	v := r.data[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return v, nil
}

func skipProto(r *protoReader, wire int) error {
	switch wire {
	case 0:
		_, err := r.varint()
		return err
	case 1:
		if len(r.data)-r.pos < 8 {
			return errors.New("truncated fixed64")
		}
		r.pos += 8
	case 2:
		_, err := r.bytes()
		return err
	case 5:
		if len(r.data)-r.pos < 4 {
			return errors.New("truncated fixed32")
		}
		r.pos += 4
	default:
		return fmt.Errorf("unsupported protobuf wire type %d", wire)
	}
	return nil
}

func parseUUID(data []byte) (peerUUID, error) {
	var id peerUUID
	r := protoReader{data: data}
	var seen [4]bool
	for r.pos < len(r.data) {
		field, wire, err := r.field()
		if err != nil {
			return id, err
		}
		if field < 1 || field > 4 {
			if err := skipProto(&r, wire); err != nil {
				return id, err
			}
			continue
		}
		if wire != 0 {
			return id, errors.New("UUID part has invalid wire type")
		}
		v, err := r.varint()
		if err != nil {
			return id, err
		}
		binary.BigEndian.PutUint32(id[(field-1)*4:], v)
		seen[field-1] = true
	}
	return id, nil
}

func parseProto(data []byte, assign func(int, int, []byte, uint32) error) error {
	r := protoReader{data: data}
	for r.pos < len(r.data) {
		field, wire, err := r.field()
		if err != nil {
			return err
		}
		if wire == 0 {
			v, err := r.varint()
			if err != nil {
				return err
			}
			if err := assign(field, wire, nil, v); err != nil {
				return err
			}
			continue
		}
		if wire == 2 {
			b, err := r.bytes()
			if err != nil {
				return err
			}
			if err := assign(field, wire, b, 0); err != nil {
				return err
			}
			continue
		}
		if err := assign(field, wire, nil, 0); err != nil {
			return err
		}
		if err := skipProto(&r, wire); err != nil {
			return err
		}
	}
	return nil
}

func unmarshalPeerMsg1(data []byte) (peerConnNoiseMsg1, error) {
	var m peerConnNoiseMsg1
	err := parseProto(data, func(f, w int, b []byte, v uint32) error {
		switch f {
		case 1:
			if w != 0 {
				return errors.New("msg1 version wire type")
			}
			m.Version = v
		case 2:
			if w != 2 {
				return errors.New("msg1 network wire type")
			}
			m.NetworkName = string(b)
		case 3:
			if w != 0 {
				return errors.New("msg1 generation wire type")
			}
			m.SessionGeneration, m.HasSessionGeneration = v, true
		case 4:
			if w != 2 {
				return errors.New("msg1 UUID wire type")
			}
			id, err := parseUUID(b)
			if err != nil {
				return err
			}
			m.ConnID = id
		case 5:
			if w != 2 {
				return errors.New("msg1 algorithm wire type")
			}
			m.ClientEncryptionAlgorithm = string(b)
		}
		return nil
	})
	return m, err
}

func unmarshalPeerMsg2(data []byte) (peerConnNoiseMsg2, error) {
	var m peerConnNoiseMsg2
	err := parseProto(data, func(f, w int, b []byte, v uint32) error {
		switch f {
		case 1:
			if w != 2 {
				return errors.New("msg2 network wire type")
			}
			m.NetworkName = string(b)
		case 2:
			if w != 0 {
				return errors.New("msg2 role wire type")
			}
			m.RoleHint = v
		case 3:
			if w != 0 {
				return errors.New("msg2 action wire type")
			}
			m.Action = v
		case 4:
			if w != 0 {
				return errors.New("msg2 generation wire type")
			}
			m.SessionGeneration = v
		case 5:
			if w != 2 {
				return errors.New("msg2 root wire type")
			}
			if len(b) != directRootKeySize {
				return errors.New("root key is not 32 bytes")
			}
			m.RootKey = append([]byte(nil), b...)
		case 6:
			if w != 0 {
				return errors.New("msg2 epoch wire type")
			}
			m.InitialEpoch = v
		case 7:
			if w != 2 {
				return errors.New("msg2 b UUID wire type")
			}
			id, err := parseUUID(b)
			if err != nil {
				return err
			}
			m.BConnID = id
		case 8:
			if w != 2 {
				return errors.New("msg2 echo UUID wire type")
			}
			id, err := parseUUID(b)
			if err != nil {
				return err
			}
			m.AConnIDEcho = id
		case 9:
			if w != 2 {
				return errors.New("msg2 proof wire type")
			}
			if len(b) != directProofSize {
				return errors.New("proof is not 32 bytes")
			}
			m.SecretProof = append([]byte(nil), b...)
		case 10:
			if w != 2 {
				return errors.New("msg2 algorithm wire type")
			}
			m.ServerEncryptionAlgorithm = string(b)
		}
		return nil
	})
	if err == nil && m.RootKey == nil {
		return m, errors.New("root key is missing")
	}
	return m, err
}

func unmarshalPeerMsg3(data []byte) (peerConnNoiseMsg3, error) {
	var m peerConnNoiseMsg3
	err := parseProto(data, func(f, w int, b []byte, v uint32) error {
		switch f {
		case 1:
			if w != 2 {
				return errors.New("msg3 a UUID wire type")
			}
			id, err := parseUUID(b)
			if err != nil {
				return err
			}
			m.AConnIDEcho = id
		case 2:
			if w != 2 {
				return errors.New("msg3 b UUID wire type")
			}
			id, err := parseUUID(b)
			if err != nil {
				return err
			}
			m.BConnIDEcho = id
		case 3:
			if w != 2 {
				return errors.New("msg3 proof wire type")
			}
			if len(b) != directProofSize {
				return errors.New("proof is not 32 bytes")
			}
			m.SecretProof = append([]byte(nil), b...)
		case 4:
			if w != 2 {
				return errors.New("msg3 digest wire type")
			}
			m.SecretDigest = append([]byte(nil), b...)
		}
		return nil
	})
	if err == nil && m.SecretDigest == nil {
		return m, errors.New("secret digest is missing")
	}
	return m, err
}

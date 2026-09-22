// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"fmt"
	"io"
)

// Frame types defined in RFC 9000
const (
	FrameTypePadding         uint64 = 0x00
	FrameTypePing            uint64 = 0x01
	FrameTypeAck             uint64 = 0x02
	FrameTypeAckECN          uint64 = 0x03
	FrameTypeResetStream     uint64 = 0x04
	FrameTypeStopSending     uint64 = 0x05
	FrameTypeCrypto          uint64 = 0x06
	FrameTypeNewToken        uint64 = 0x07
	FrameTypeStreamBase      uint64 = 0x08
	FrameTypeMaxData         uint64 = 0x10
	FrameTypeMaxStreamData   uint64 = 0x11
	FrameTypeMaxStreamsBidi  uint64 = 0x12
	FrameTypeMaxStreamsUni   uint64 = 0x13
	FrameTypeDataBlocked     uint64 = 0x14
	FrameTypeStreamDataBlock uint64 = 0x15
	FrameTypeStreamsBlocked  uint64 = 0x16
	FrameTypeNewConnID       uint64 = 0x18
	FrameTypeRetireConnID    uint64 = 0x19
	FrameTypePathChallenge   uint64 = 0x1a
	FrameTypePathResponse    uint64 = 0x1b
	FrameTypeConnClose       uint64 = 0x1c
	FrameTypeAppClose        uint64 = 0x1d
	FrameTypeHandshakeDone   uint64 = 0x1e
)

// Frame represents a parsed QUIC frame.
type Frame interface {
	Type() uint64
	Append(dst []byte) []byte
}

// PaddingFrame is a sequence of zero or more padding bytes.
type PaddingFrame struct {
	Length int
}

func (f PaddingFrame) Type() uint64 { return FrameTypePadding }
func (f PaddingFrame) Append(dst []byte) []byte {
	for i := 0; i < f.Length; i++ {
		dst = append(dst, 0x00)
	}
	return dst
}

// PingFrame represents a PING frame.
type PingFrame struct{}

func (f PingFrame) Type() uint64 { return FrameTypePing }
func (f PingFrame) Append(dst []byte) []byte {
	return append(dst, byte(FrameTypePing))
}

// AckRange represents an acknowledgement range in an ACK frame.
type AckRange struct {
	Gap    uint64
	Length uint64
}

// AckFrame represents an ACK frame.
type AckFrame struct {
	LargestAcked uint64
	AckDelay     uint64
	FirstRange   uint64
	Ranges       []AckRange
}

func (f AckFrame) Type() uint64 { return FrameTypeAck }
func (f AckFrame) Append(dst []byte) []byte {
	dst = AppendVarint(dst, FrameTypeAck)
	dst = AppendVarint(dst, f.LargestAcked)
	dst = AppendVarint(dst, f.AckDelay)
	dst = AppendVarint(dst, uint64(len(f.Ranges)))
	dst = AppendVarint(dst, f.FirstRange)
	for _, r := range f.Ranges {
		dst = AppendVarint(dst, r.Gap)
		dst = AppendVarint(dst, r.Length)
	}
	return dst
}

// CryptoFrame represents a CRYPTO frame carrying handshake data.
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

func (f CryptoFrame) Type() uint64 { return FrameTypeCrypto }
func (f CryptoFrame) Append(dst []byte) []byte {
	dst = AppendVarint(dst, FrameTypeCrypto)
	dst = AppendVarint(dst, f.Offset)
	dst = AppendVarint(dst, uint64(len(f.Data)))
	return append(dst, f.Data...)
}

// StreamFrame represents a STREAM frame carrying user data.
type StreamFrame struct {
	StreamID uint64
	Offset   uint64
	Fin      bool
	Data     []byte
}

func (f StreamFrame) Type() uint64 {
	typ := FrameTypeStreamBase | 0x02 // always include LEN bit
	if f.Offset > 0 {
		typ |= 0x04 // OFF bit
	}
	if f.Fin {
		typ |= 0x01 // FIN bit
	}
	return typ
}

func (f StreamFrame) Append(dst []byte) []byte {
	typ := f.Type()
	dst = AppendVarint(dst, typ)
	dst = AppendVarint(dst, f.StreamID)
	if f.Offset > 0 {
		dst = AppendVarint(dst, f.Offset)
	}
	dst = AppendVarint(dst, uint64(len(f.Data)))
	return append(dst, f.Data...)
}

// MaxDataFrame represents a MAX_DATA flow control frame.
type MaxDataFrame struct {
	MaxData uint64
}

func (f MaxDataFrame) Type() uint64 { return FrameTypeMaxData }
func (f MaxDataFrame) Append(dst []byte) []byte {
	dst = AppendVarint(dst, FrameTypeMaxData)
	return AppendVarint(dst, f.MaxData)
}

// MaxStreamDataFrame represents a MAX_STREAM_DATA flow control frame.
type MaxStreamDataFrame struct {
	StreamID      uint64
	MaxStreamData uint64
}

func (f MaxStreamDataFrame) Type() uint64 { return FrameTypeMaxStreamData }
func (f MaxStreamDataFrame) Append(dst []byte) []byte {
	dst = AppendVarint(dst, FrameTypeMaxStreamData)
	dst = AppendVarint(dst, f.StreamID)
	return AppendVarint(dst, f.MaxStreamData)
}

// ConnectionCloseFrame represents a CONNECTION_CLOSE frame.
type ConnectionCloseFrame struct {
	ErrorCode    uint64
	FrameType    uint64
	ReasonPhrase string
}

func (f ConnectionCloseFrame) Type() uint64 { return FrameTypeConnClose }
func (f ConnectionCloseFrame) Append(dst []byte) []byte {
	dst = AppendVarint(dst, FrameTypeConnClose)
	dst = AppendVarint(dst, f.ErrorCode)
	dst = AppendVarint(dst, f.FrameType)
	dst = AppendVarint(dst, uint64(len(f.ReasonPhrase)))
	return append(dst, []byte(f.ReasonPhrase)...)
}

// HandshakeDoneFrame represents a HANDSHAKE_DONE frame.
type HandshakeDoneFrame struct{}

func (f HandshakeDoneFrame) Type() uint64 { return FrameTypeHandshakeDone }
func (f HandshakeDoneFrame) Append(dst []byte) []byte {
	return AppendVarint(dst, FrameTypeHandshakeDone)
}

// ParseFrames parses all frames from payload.
func ParseFrames(payload []byte) ([]Frame, error) {
	var frames []Frame
	for len(payload) > 0 {
		if payload[0] == 0x00 {
			// Fast path for PADDING
			padLen := 0
			for padLen < len(payload) && payload[padLen] == 0x00 {
				padLen++
			}
			frames = append(frames, PaddingFrame{Length: padLen})
			payload = payload[padLen:]
			continue
		}

		frameType, n, err := ReadVarint(payload)
		if err != nil {
			return nil, err
		}
		payload = payload[n:]

		switch {
		case frameType == FrameTypePing:
			frames = append(frames, PingFrame{})

		case frameType == FrameTypeAck || frameType == FrameTypeAckECN:
			largestAcked, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]

			ackDelay, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]

			rangeCount, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]

			firstRange, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]

			var ranges []AckRange
			for i := uint64(0); i < rangeCount; i++ {
				gap, n, err := ReadVarint(payload)
				if err != nil {
					return nil, err
				}
				payload = payload[n:]

				ackLen, n, err := ReadVarint(payload)
				if err != nil {
					return nil, err
				}
				payload = payload[n:]
				ranges = append(ranges, AckRange{Gap: gap, Length: ackLen})
			}

			if frameType == FrameTypeAckECN {
				// skip ECN counts (ECT0, ECT1, CE)
				for i := 0; i < 3; i++ {
					_, n, err := ReadVarint(payload)
					if err != nil {
						return nil, err
					}
					payload = payload[n:]
				}
			}

			frames = append(frames, AckFrame{
				LargestAcked: largestAcked,
				AckDelay:     ackDelay,
				FirstRange:   firstRange,
				Ranges:       ranges,
			})

		case frameType == FrameTypeCrypto:
			offset, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]

			dataLen, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]

			if uint64(len(payload)) < dataLen {
				return nil, io.ErrUnexpectedEOF
			}
			data := append([]byte(nil), payload[:dataLen]...)
			payload = payload[dataLen:]
			frames = append(frames, CryptoFrame{Offset: offset, Data: data})

		case frameType >= 0x08 && frameType <= 0x0f:
			// STREAM frame
			hasOff := (frameType & 0x04) != 0
			hasLen := (frameType & 0x02) != 0
			hasFin := (frameType & 0x01) != 0

			streamID, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]

			var offset uint64
			if hasOff {
				offset, n, err = ReadVarint(payload)
				if err != nil {
					return nil, err
				}
				payload = payload[n:]
			}

			var data []byte
			if hasLen {
				dataLen, n, err := ReadVarint(payload)
				if err != nil {
					return nil, err
				}
				payload = payload[n:]
				if uint64(len(payload)) < dataLen {
					return nil, io.ErrUnexpectedEOF
				}
				data = append([]byte(nil), payload[:dataLen]...)
				payload = payload[dataLen:]
			} else {
				// extends to end of packet
				data = append([]byte(nil), payload...)
				payload = nil
			}

			frames = append(frames, StreamFrame{
				StreamID: streamID,
				Offset:   offset,
				Fin:      hasFin,
				Data:     data,
			})

		case frameType == FrameTypeMaxData:
			maxData, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]
			frames = append(frames, MaxDataFrame{MaxData: maxData})

		case frameType == FrameTypeMaxStreamData:
			streamID, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]
			maxStreamData, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]
			frames = append(frames, MaxStreamDataFrame{
				StreamID:      streamID,
				MaxStreamData: maxStreamData,
			})

		case frameType == FrameTypeConnClose || frameType == FrameTypeAppClose:
			errCode, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]

			var triggerFrame uint64
			if frameType == FrameTypeConnClose {
				triggerFrame, n, err = ReadVarint(payload)
				if err != nil {
					return nil, err
				}
				payload = payload[n:]
			}

			reasonLen, n, err := ReadVarint(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]
			if uint64(len(payload)) < reasonLen {
				return nil, io.ErrUnexpectedEOF
			}
			reason := string(payload[:reasonLen])
			payload = payload[reasonLen:]

			frames = append(frames, ConnectionCloseFrame{
				ErrorCode:    errCode,
				FrameType:    triggerFrame,
				ReasonPhrase: reason,
			})

		case frameType == FrameTypeHandshakeDone:
			frames = append(frames, HandshakeDoneFrame{})

		default:
			// For unknown/unhandled frames, if we don't know their layout, error
			return nil, fmt.Errorf("unsupported frame type 0x%x", frameType)
		}
	}
	return frames, nil
}

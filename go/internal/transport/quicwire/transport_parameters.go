// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"io"
)

// Transport Parameter IDs (RFC 9000 Section 18.2)
const (
	ParamOriginalDestCID             uint64 = 0x00
	ParamMaxIdleTimeout              uint64 = 0x01
	ParamStatelessResetToken         uint64 = 0x02
	ParamMaxUDPPayloadSize           uint64 = 0x03
	ParamInitialMaxData              uint64 = 0x04
	ParamInitialMaxStreamDataBidiLoc uint64 = 0x05
	ParamInitialMaxStreamDataBidiRem uint64 = 0x06
	ParamInitialMaxStreamDataUni     uint64 = 0x07
	ParamInitialMaxStreamsBidi       uint64 = 0x08
	ParamInitialMaxStreamsUni        uint64 = 0x09
	ParamAckDelayExponent            uint64 = 0x0a
	ParamMaxAckDelay                 uint64 = 0x0b
	ParamDisableActiveMigration      uint64 = 0x0c
	ParamPreferredAddress            uint64 = 0x0d
	ParamActiveConnIDLimit           uint64 = 0x0e
	ParamInitialSourceCID            uint64 = 0x0f
	ParamRetrySourceCID              uint64 = 0x10
)

// TransportParameters contains QUIC transport parameters exchanged in CRYPTO frames.
type TransportParameters struct {
	OriginalDestCID             []byte
	InitialSourceCID            []byte
	MaxIdleTimeout              uint64
	MaxUDPPayloadSize           uint64
	InitialMaxData              uint64
	InitialMaxStreamDataBidiLoc uint64
	InitialMaxStreamDataBidiRem uint64
	InitialMaxStreamDataUni     uint64
	InitialMaxStreamsBidi       uint64
	InitialMaxStreamsUni        uint64
	AckDelayExponent            uint64
	MaxAckDelay                 uint64
	DisableActiveMigration      bool
	ActiveConnIDLimit           uint64
	UnknownParams               map[uint64][]byte
}

// DefaultTransportParameters returns sensible defaults matching EasyTier / Quinn configuration.
func DefaultTransportParameters(sourceCID []byte) *TransportParameters {
	return &TransportParameters{
		InitialSourceCID:            append([]byte(nil), sourceCID...),
		MaxIdleTimeout:              600000, // 600 seconds in ms
		MaxUDPPayloadSize:           1200,
		InitialMaxData:              16 * 1024 * 1024, // 16 MB
		InitialMaxStreamDataBidiLoc: 8 * 1024 * 1024,  // 8 MB
		InitialMaxStreamDataBidiRem: 8 * 1024 * 1024,  // 8 MB
		InitialMaxStreamDataUni:     0,
		InitialMaxStreamsBidi:       255, // matches quinn max_concurrent_bidi_streams(255)
		InitialMaxStreamsUni:        0,
		AckDelayExponent:            3,
		MaxAckDelay:                 25,
		DisableActiveMigration:      true,
		ActiveConnIDLimit:           2,
		UnknownParams:               make(map[uint64][]byte),
	}
}

// Marshal encodes the transport parameters into a byte slice.
func (tp *TransportParameters) Marshal() []byte {
	var buf []byte

	appendParamBytes := func(id uint64, val []byte) {
		buf = AppendVarint(buf, id)
		buf = AppendVarint(buf, uint64(len(val)))
		buf = append(buf, val...)
	}

	appendParamVarint := func(id uint64, val uint64) {
		var vBuf [8]byte
		vBytes := AppendVarint(vBuf[:0], val)
		appendParamBytes(id, vBytes)
	}

	if len(tp.OriginalDestCID) > 0 {
		appendParamBytes(ParamOriginalDestCID, tp.OriginalDestCID)
	}
	if len(tp.InitialSourceCID) > 0 {
		appendParamBytes(ParamInitialSourceCID, tp.InitialSourceCID)
	}
	if tp.MaxIdleTimeout > 0 {
		appendParamVarint(ParamMaxIdleTimeout, tp.MaxIdleTimeout)
	}
	if tp.MaxUDPPayloadSize > 0 {
		appendParamVarint(ParamMaxUDPPayloadSize, tp.MaxUDPPayloadSize)
	}
	if tp.InitialMaxData > 0 {
		appendParamVarint(ParamInitialMaxData, tp.InitialMaxData)
	}
	if tp.InitialMaxStreamDataBidiLoc > 0 {
		appendParamVarint(ParamInitialMaxStreamDataBidiLoc, tp.InitialMaxStreamDataBidiLoc)
	}
	if tp.InitialMaxStreamDataBidiRem > 0 {
		appendParamVarint(ParamInitialMaxStreamDataBidiRem, tp.InitialMaxStreamDataBidiRem)
	}
	if tp.InitialMaxStreamDataUni > 0 {
		appendParamVarint(ParamInitialMaxStreamDataUni, tp.InitialMaxStreamDataUni)
	}
	if tp.InitialMaxStreamsBidi > 0 {
		appendParamVarint(ParamInitialMaxStreamsBidi, tp.InitialMaxStreamsBidi)
	}
	if tp.InitialMaxStreamsUni > 0 {
		appendParamVarint(ParamInitialMaxStreamsUni, tp.InitialMaxStreamsUni)
	}
	if tp.AckDelayExponent > 0 {
		appendParamVarint(ParamAckDelayExponent, tp.AckDelayExponent)
	}
	if tp.MaxAckDelay > 0 {
		appendParamVarint(ParamMaxAckDelay, tp.MaxAckDelay)
	}
	if tp.DisableActiveMigration {
		appendParamBytes(ParamDisableActiveMigration, nil)
	}
	if tp.ActiveConnIDLimit > 0 {
		appendParamVarint(ParamActiveConnIDLimit, tp.ActiveConnIDLimit)
	}

	for id, val := range tp.UnknownParams {
		appendParamBytes(id, val)
	}

	return buf
}

// UnmarshalTransportParameters decodes transport parameters from b.
func UnmarshalTransportParameters(b []byte) (*TransportParameters, error) {
	tp := &TransportParameters{
		MaxUDPPayloadSize: 65527,
		AckDelayExponent:  3,
		MaxAckDelay:       25,
		ActiveConnIDLimit: 2,
		UnknownParams:     make(map[uint64][]byte),
	}

	for len(b) > 0 {
		id, n, err := ReadVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]

		valLen, n, err := ReadVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]

		if uint64(len(b)) < valLen {
			return nil, io.ErrUnexpectedEOF
		}
		valBytes := b[:valLen]
		b = b[valLen:]

		readV := func() (uint64, error) {
			v, _, err := ReadVarint(valBytes)
			return v, err
		}

		switch id {
		case ParamOriginalDestCID:
			tp.OriginalDestCID = append([]byte(nil), valBytes...)
		case ParamInitialSourceCID:
			tp.InitialSourceCID = append([]byte(nil), valBytes...)
		case ParamMaxIdleTimeout:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.MaxIdleTimeout = v
		case ParamMaxUDPPayloadSize:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.MaxUDPPayloadSize = v
		case ParamInitialMaxData:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.InitialMaxData = v
		case ParamInitialMaxStreamDataBidiLoc:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.InitialMaxStreamDataBidiLoc = v
		case ParamInitialMaxStreamDataBidiRem:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.InitialMaxStreamDataBidiRem = v
		case ParamInitialMaxStreamDataUni:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.InitialMaxStreamDataUni = v
		case ParamInitialMaxStreamsBidi:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.InitialMaxStreamsBidi = v
		case ParamInitialMaxStreamsUni:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.InitialMaxStreamsUni = v
		case ParamAckDelayExponent:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.AckDelayExponent = v
		case ParamMaxAckDelay:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.MaxAckDelay = v
		case ParamDisableActiveMigration:
			tp.DisableActiveMigration = true
		case ParamActiveConnIDLimit:
			v, err := readV()
			if err != nil {
				return nil, err
			}
			tp.ActiveConnIDLimit = v
		default:
			tp.UnknownParams[id] = append([]byte(nil), valBytes...)
		}
	}

	return tp, nil
}

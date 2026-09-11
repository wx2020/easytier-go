// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// CompressionAlgorithm is the algorithm identifier stored in a compressed
// peer packet's one-byte tail.
type CompressionAlgorithm uint8

const (
	CompressionNone CompressionAlgorithm = iota
	CompressionZstd
)

const CompressionTailSize = 1

var (
	zstdEncoder  *zstd.Encoder
	zstdDecoder  *zstd.Decoder
	zstdInitOnce sync.Once
	zstdInitErr  error
)

func initZstd() {
	zstdEncoder, zstdInitErr = zstd.NewWriter(nil)
	if zstdInitErr != nil {
		return
	}
	zstdDecoder, zstdInitErr = zstd.NewReader(nil)
}

func zstdCodecs() (*zstd.Encoder, *zstd.Decoder, error) {
	zstdInitOnce.Do(initZstd)
	if zstdInitErr != nil {
		return nil, nil, zstdInitErr
	}
	return zstdEncoder, zstdDecoder, nil
}

// CompressData compresses data without adding a packet tail.
func CompressData(data []byte, algorithm CompressionAlgorithm) ([]byte, error) {
	switch algorithm {
	case CompressionNone:
		return append([]byte(nil), data...), nil
	case CompressionZstd:
		encoder, _, err := zstdCodecs()
		if err != nil {
			return nil, fmt.Errorf("initialize zstd compressor: %w", err)
		}
		return encoder.EncodeAll(data, nil), nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm %d", algorithm)
	}
}

// DecompressData decompresses data without interpreting a packet tail.
func DecompressData(data []byte, algorithm CompressionAlgorithm) ([]byte, error) {
	switch algorithm {
	case CompressionNone:
		return append([]byte(nil), data...), nil
	case CompressionZstd:
		_, decoder, err := zstdCodecs()
		if err != nil {
			return nil, fmt.Errorf("initialize zstd decompressor: %w", err)
		}
		decoded, err := decoder.DecodeAll(data, nil)
		if err != nil {
			return nil, fmt.Errorf("decompress zstd data: %w", err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm %d", algorithm)
	}
}

// CompressPacket applies the peer packet compression contract. Compression is
// skipped when it would not save space, leaving the packet uncompressed.
func CompressPacket(packet *Packet, algorithm CompressionAlgorithm) error {
	if packet == nil {
		return fmt.Errorf("packet is nil")
	}
	if packet.Header.Flags&FlagCompressed != 0 {
		return nil
	}
	if uint64(len(packet.Payload)) > uint64(^uint32(0)) {
		return fmt.Errorf("peer payload exceeds uint32 length: %d", len(packet.Payload))
	}
	packet.Header.Length = uint32(len(packet.Payload))
	if algorithm == CompressionNone {
		return nil
	}
	compressed, err := CompressData(packet.Payload, algorithm)
	if err != nil {
		return err
	}
	if len(compressed)+CompressionTailSize > len(packet.Payload) {
		return nil
	}
	packet.Payload = append(compressed, byte(algorithm))
	packet.Header.Flags |= FlagCompressed
	return nil
}

// DecompressPacket removes the compression tail and restores the original
// payload length recorded in the peer header.
func DecompressPacket(packet *Packet) error {
	if packet == nil {
		return fmt.Errorf("packet is nil")
	}
	if packet.Header.Flags&FlagCompressed == 0 {
		return nil
	}
	if len(packet.Payload) < CompressionTailSize {
		return fmt.Errorf("compressed peer packet is missing algorithm tail")
	}
	algorithm := CompressionAlgorithm(packet.Payload[len(packet.Payload)-CompressionTailSize])
	if algorithm == CompressionNone {
		return fmt.Errorf("compressed peer packet has no compression algorithm")
	}
	decoded, err := DecompressData(packet.Payload[:len(packet.Payload)-CompressionTailSize], algorithm)
	if err != nil {
		return err
	}
	if uint64(len(decoded)) != uint64(packet.Header.Length) {
		return fmt.Errorf("decompressed payload length %d does not match header length %d", len(decoded), packet.Header.Length)
	}
	packet.Payload = decoded
	packet.Header.Flags &^= FlagCompressed
	return nil
}

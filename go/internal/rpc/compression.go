// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"fmt"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// CompressRPCContent compresses content with the requested response/request
// algorithm and returns the algorithm actually used on the wire.
func CompressRPCContent(algorithm CompressionAlgo, content []byte) ([]byte, CompressionAlgo, error) {
	if algorithm != CompressionAlgoZstd {
		return append([]byte(nil), content...), CompressionAlgoNone, nil
	}
	compressed, err := protocol.CompressData(content, protocol.CompressionZstd)
	if err != nil {
		return nil, CompressionAlgoInvalid, err
	}
	if len(compressed) >= len(content) {
		return append([]byte(nil), content...), CompressionAlgoNone, nil
	}
	return compressed, CompressionAlgoZstd, nil
}

// DecompressRPCContent decompresses one RPC body using its advertised
// algorithm. Invalid algorithm values are rejected rather than treated as
// uncompressed data.
func DecompressRPCContent(algorithm CompressionAlgo, content []byte) ([]byte, error) {
	switch algorithm {
	case CompressionAlgoNone:
		return append([]byte(nil), content...), nil
	case CompressionAlgoZstd:
		return protocol.DecompressData(content, protocol.CompressionZstd)
	default:
		return nil, fmt.Errorf("unsupported RPC compression algorithm %d", algorithm)
	}
}

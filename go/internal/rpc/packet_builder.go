// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"fmt"
	"math"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// RPCUDPPayloadBudget is the conservative final EasyTier UDP payload budget
// used for peer RPC. It leaves room for tunnel, peer, and encryption tails.
const RPCUDPPayloadBudget = 1300

const rpcTailReservedSize = 16 + 12 // AEAD tag and nonce

type BuildRPCPacketArgs struct {
	FromPeer        uint32
	ToPeer          uint32
	RPCDesc         RpcDescriptor
	TransactionID   int64
	IsRequest       bool
	Content         []byte
	TraceID         int32
	CompressionInfo RpcCompressionInfo
}

// BuildRpcPacketArgs is kept in the repository's existing Rpc naming style.
type BuildRpcPacketArgs = BuildRPCPacketArgs

func rpcPacketForPiece(args BuildRPCPacketArgs, totalPieces, pieceIndex uint32, body []byte) RpcPacket {
	var compressionInfo *RpcCompressionInfo
	if pieceIndex == 0 && (args.CompressionInfo.Algo != CompressionAlgoInvalid || args.CompressionInfo.AcceptedAlgo != CompressionAlgoInvalid) {
		info := args.CompressionInfo
		compressionInfo = &info
	}
	return RpcPacket{
		FromPeer:        args.FromPeer,
		ToPeer:          args.ToPeer,
		Descriptor:      descriptorForPiece(args, pieceIndex),
		Body:            body,
		IsRequest:       args.IsRequest,
		TotalPieces:     totalPieces,
		PieceIdx:        pieceIndex,
		TransactionID:   args.TransactionID,
		TraceID:         args.TraceID,
		CompressionInfo: compressionInfo,
	}
}

func descriptorForPiece(args BuildRPCPacketArgs, pieceIndex uint32) *RpcDescriptor {
	if pieceIndex == 0 || args.CompressionInfo.Algo == CompressionAlgoNone {
		descriptor := args.RPCDesc
		return &descriptor
	}
	return nil
}

func encodedRPCPacketLen(packet RpcPacket) (int, error) {
	encoded, err := packet.Marshal()
	if err != nil {
		return 0, err
	}
	return len(encoded), nil
}

func maxRPCEncodedLen() int {
	return RPCUDPPayloadBudget - protocol.UDPTunnelHeaderSize - protocol.PeerManagerHeaderSize - rpcTailReservedSize
}

func largestPiece(args BuildRPCPacketArgs, offset, remaining int, first bool) (int, error) {
	maxEncoded := maxRPCEncodedLen()
	if maxEncoded <= 0 {
		return 0, fmt.Errorf("RPC UDP payload budget is too small")
	}
	// The maximum varint widths make the split safe even before the final
	// total_pieces value is known.
	pieceIndex := uint32(math.MaxUint32)
	if first {
		pieceIndex = 0
	}
	template := rpcPacketForPiece(args, math.MaxUint32, pieceIndex, nil)
	base, err := encodedRPCPacketLen(template)
	if err != nil {
		return 0, err
	}
	if remaining == 0 {
		return 0, nil
	}
	low, high := 1, remaining
	best := 0
	for low <= high {
		middle := low + (high-low)/2
		packet := rpcPacketForPiece(args, math.MaxUint32, pieceIndex, args.Content[offset:offset+middle])
		encoded, err := encodedRPCPacketLen(packet)
		if err != nil {
			return 0, err
		}
		if encoded <= maxEncoded {
			best = middle
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("RPC metadata exceeds UDP payload budget (base %d, limit %d)", base, maxEncoded)
	}
	return best, nil
}

// BuildRPCPackets splits an RPC body into bounded peer packets. Content is
// expected to already reflect CompressionInfo.Algo, matching the Rust RPC
// packet builder contract.
func BuildRPCPackets(args BuildRPCPacketArgs) ([]protocol.Packet, error) {
	if err := args.RPCDesc.Validate(); err != nil {
		return nil, err
	}
	if len(args.Content) == 0 {
		args.Content = nil
	}
	offsets := make([][2]int, 0, 1)
	offset := 0
	for {
		length, err := largestPiece(args, offset, len(args.Content)-offset, len(offsets) == 0)
		if err != nil {
			return nil, err
		}
		offsets = append(offsets, [2]int{offset, length})
		offset += length
		if offset == len(args.Content) {
			break
		}
		if len(offsets) >= 32*1024 {
			return nil, fmt.Errorf("RPC packet has too many pieces")
		}
	}

	totalPieces := uint32(len(offsets))
	packets := make([]protocol.Packet, 0, len(offsets))
	packetType := uint8(protocol.PacketTypeRPCResponse)
	if args.IsRequest {
		packetType = uint8(protocol.PacketTypeRPCRequest)
	}
	for index, part := range offsets {
		rpcPacket := rpcPacketForPiece(args, totalPieces, uint32(index), args.Content[part[0]:part[0]+part[1]])
		body, err := rpcPacket.Marshal()
		if err != nil {
			return nil, err
		}
		packet := protocol.Packet{
			Header: protocol.PeerManagerHeader{
				FromPeerID: args.FromPeer,
				ToPeerID:   args.ToPeer,
				PacketType: packetType,
			},
			Payload: body,
		}
		if _, err := packet.MarshalBody(); err != nil {
			return nil, err
		}
		packets = append(packets, packet)
	}
	return packets, nil
}

// BuildRpcPacket is the singular-name alias used by the Rust function.
func BuildRpcPacket(args BuildRpcPacketArgs) ([]protocol.Packet, error) {
	return BuildRPCPackets(args)
}

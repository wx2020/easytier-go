// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"bytes"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestBuildRPCPacketsRespectsUDPPayloadBudget(t *testing.T) {
	content := bytes.Repeat([]byte{0x5a}, 4096)
	packets, err := BuildRPCPackets(BuildRPCPacketArgs{
		FromPeer:        11,
		ToPeer:          22,
		RPCDesc:         RpcDescriptor{DomainName: "domain", ProtoName: "proto", ServiceName: "service", MethodIndex: 7},
		TransactionID:   33,
		IsRequest:       true,
		Content:         content,
		CompressionInfo: RpcCompressionInfo{Algo: CompressionAlgoNone},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) < 2 {
		t.Fatal("RPC content was not fragmented")
	}
	for _, packet := range packets {
		body, err := packet.MarshalBody()
		if err != nil {
			t.Fatal(err)
		}
		if len(body)+protocol.UDPTunnelHeaderSize+rpcTailReservedSize > RPCUDPPayloadBudget {
			t.Fatalf("packet size %d exceeds budget", len(body)+protocol.UDPTunnelHeaderSize+rpcTailReservedSize)
		}
	}
}

func TestBuildRPCPacketsPreservesContentAndMetadataRules(t *testing.T) {
	content := bytes.Repeat([]byte("x"), 3000)
	packets, err := BuildRPCPackets(BuildRPCPacketArgs{
		FromPeer:        1,
		ToPeer:          2,
		RPCDesc:         RpcDescriptor{ServiceName: "svc"},
		TransactionID:   3,
		Content:         content,
		CompressionInfo: RpcCompressionInfo{Algo: CompressionAlgoZstd},
	})
	if err != nil {
		t.Fatal(err)
	}
	var merged []byte
	for index, packet := range packets {
		decoded, err := UnmarshalRpcPacket(packet.Payload)
		if err != nil {
			t.Fatal(err)
		}
		merged = append(merged, decoded.Body...)
		if index == 0 && decoded.Descriptor == nil {
			t.Fatal("first piece has no descriptor")
		}
		if index > 0 && decoded.Descriptor != nil {
			t.Fatal("compressed later piece unexpectedly has descriptor")
		}
	}
	if !bytes.Equal(merged, content) {
		t.Fatal("fragmented RPC content changed")
	}
}

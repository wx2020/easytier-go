// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"bytes"
	"context"
	"testing"

	commonpb "github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"google.golang.org/protobuf/proto"
)

// packetCapture records outgoing RPC packets after wire encoding.
type packetCapture struct {
	packets []protocol.Packet
}

func (c *packetCapture) MyPeerID() uint32 { return 1 }

func (c *packetCapture) Send(_ context.Context, _ uint32, packet protocol.Packet) error {
	c.packets = append(c.packets, packet)
	return nil
}

// TestSendResponseFragmentsLargeBodies pins the 2026-10-27 web-console fix:
// CollectNetworkInfo responses with many peers exceed the UDP payload budget
// (2000 bytes). The reference fragments every response the same way as
// requests (build_rpc_packet → split_rpc_content_for_udp_budget); a
// single-piece response makes the remote UDP transport reject the datagram
// and drop the whole tunnel session.
func TestSendResponseFragmentsLargeBodies(t *testing.T) {
	transport := &packetCapture{}
	manager, err := NewPeerRpcManager(transport)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}

	body := bytes.Repeat([]byte("f50-collect-network-info-"), 400) // ~10 KB
	request := RpcPacket{
		FromPeer:      2,
		TransactionID: 77,
		Descriptor: &RpcDescriptor{
			DomainName:  "wx2020",
			ServiceName: "WebClientService",
			ProtoName:   "WebClientService",
			MethodIndex: 4,
		},
	}
	if err := manager.sendResponse(context.Background(), request, body); err != nil {
		t.Fatalf("sendResponse: %v", err)
	}

	if len(transport.packets) < 2 {
		t.Fatalf("large response sent as %d packet(s), want fragmentation", len(transport.packets))
	}

	var merged []byte
	for i, packet := range transport.packets {
		// Every piece must fit the UDP peer budget including the 16-byte
		// peer-manager header (transport/udp.go rejects larger datagrams).
		if total := len(packet.Payload) + protocol.PeerManagerHeaderSize; total > protocol.UDPMaxPayloadSize {
			t.Fatalf("piece %d is %d bytes, exceeds UDP budget %d", i, total, protocol.UDPMaxPayloadSize)
		}
		decoded, err := UnmarshalRpcPacket(packet.Payload)
		if err != nil {
			t.Fatalf("decode piece %d: %v", i, err)
		}
		if decoded.TotalPieces != uint32(len(transport.packets)) {
			t.Fatalf("piece %d total_pieces = %d, want %d", i, decoded.TotalPieces, len(transport.packets))
		}
		if decoded.PieceIdx != uint32(i) {
			t.Fatalf("piece %d piece_idx = %d", i, decoded.PieceIdx)
		}
		if decoded.IsRequest {
			t.Fatalf("piece %d marked as request", i)
		}
		if i > 0 && decoded.Descriptor != nil {
			t.Fatalf("piece %d carries a descriptor; only the first piece may", i)
		}
		merged = append(merged, decoded.Body...)
	}

	// The concatenated pieces must decode back to the exact response envelope.
	response := &commonpb.RpcResponse{}
	if err := proto.Unmarshal(merged, response); err != nil {
		t.Fatalf("reassembly: %v", err)
	}
	if envelope := response.GetResponse(); !bytes.Equal(envelope, body) {
		t.Fatalf("reassembled body mismatch: got %d bytes, want %d", len(envelope), len(body))
	}
}

// TestSendResponseSinglePieceUnderMTU keeps small responses on the legacy
// single-piece wire shape (total_pieces = 1, compatibility path).
func TestSendResponseSinglePieceUnderMTU(t *testing.T) {
	transport := &packetCapture{}
	manager, err := NewPeerRpcManager(transport)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	request := RpcPacket{
		FromPeer:      2,
		TransactionID: 9,
		Descriptor: &RpcDescriptor{
			DomainName:  "wx2020",
			ServiceName: "WebClientService",
			ProtoName:   "WebClientService",
			MethodIndex: 8,
		},
	}
	if err := manager.sendResponse(context.Background(), request, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("sendResponse: %v", err)
	}
	if len(transport.packets) != 1 {
		t.Fatalf("small response sent as %d packets, want 1", len(transport.packets))
	}
	decoded, err := UnmarshalRpcPacket(transport.packets[0].Payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.TotalPieces != 1 || decoded.PieceIdx != 0 {
		t.Fatalf("single-piece shape broken: total=%d idx=%d", decoded.TotalPieces, decoded.PieceIdx)
	}
	if decoded.Descriptor == nil {
		t.Fatalf("single-piece response lost its descriptor")
	}
}

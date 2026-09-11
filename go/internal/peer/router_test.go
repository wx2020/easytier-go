// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"reflect"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestPacketRouterProcess(t *testing.T) {
	router, err := NewPacketRouter(2, map[uint32]uint32{3: 4})
	if err != nil {
		t.Fatal(err)
	}

	packet := protocol.Packet{Header: protocol.PeerManagerHeader{
		FromPeerID:     1,
		ToPeerID:       3,
		PacketType:     protocol.PacketTypeData,
		Flags:          protocol.FlagNoProxy | protocol.FlagNotSendToTUN,
		ForwardCounter: MaxForwardCounter,
	}}
	original := packet
	decision, err := router.Process(packet)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != RouteActionForward || decision.NextHop != 4 {
		t.Fatalf("decision = %#v, want forward to 4", decision)
	}
	if decision.Packet.Header.ForwardCounter != MaxForwardCounter+1 {
		t.Fatalf("forward counter = %d, want %d", decision.Packet.Header.ForwardCounter, MaxForwardCounter+1)
	}
	if !decision.NoProxy || !decision.NotSendToTUN {
		t.Fatalf("flags were not exposed: %#v", decision)
	}
	if !reflect.DeepEqual(packet, original) {
		t.Fatalf("Process mutated packet: got %#v, want %#v", packet, original)
	}
}

func TestPacketRouterProcessLocalAndBroadcastControl(t *testing.T) {
	router, err := NewPacketRouter(2, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, packet := range []protocol.Packet{
		{Header: protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData}},
		{Header: protocol.PeerManagerHeader{FromPeerID: 1, PacketType: protocol.PacketTypeHandshake}},
	} {
		decision, err := router.Process(packet)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Action != RouteActionLocal || decision.NextHop != 0 {
			t.Fatalf("decision = %#v, want local delivery", decision)
		}
	}
}

func TestPacketRouterProcessRejectsInvalidPackets(t *testing.T) {
	router, err := NewPacketRouter(2, map[uint32]uint32{3: 4})
	if err != nil {
		t.Fatal(err)
	}

	tests := []protocol.Packet{
		{Header: protocol.PeerManagerHeader{ToPeerID: 2, PacketType: protocol.PacketTypeData}},
		{Header: protocol.PeerManagerHeader{FromPeerID: 1, PacketType: protocol.PacketTypeData}},
		{Header: protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 3, PacketType: protocol.PacketTypeData, ForwardCounter: MaxForwardCounter + 1}},
		{Header: protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 5, PacketType: protocol.PacketTypeData}},
	}
	for _, packet := range tests {
		if _, err := router.Process(packet); err == nil {
			t.Fatalf("Process(%#v) succeeded", packet)
		}
	}
}

func TestNewPacketRouterRejectsInvalidIDs(t *testing.T) {
	tests := []struct {
		localPeerID uint32
		routes      map[uint32]uint32
	}{
		{localPeerID: 0},
		{localPeerID: 1, routes: map[uint32]uint32{0: 2}},
		{localPeerID: 1, routes: map[uint32]uint32{2: 0}},
	}
	for _, test := range tests {
		if _, err := NewPacketRouter(test.localPeerID, test.routes); err == nil {
			t.Fatalf("NewPacketRouter(%d, %#v) succeeded", test.localPeerID, test.routes)
		}
	}
}

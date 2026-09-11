// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestUDPLoopbackSessionAndUnknownConnectionID(t *testing.T) {
	service, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopServe := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- service.Serve(serveCtx) }()

	clientCtx, cancelClient := context.WithTimeout(context.Background(), time.Second)
	defer cancelClient()
	client, err := DialUDP(clientCtx, service.Address().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	acceptCtx, cancelAccept := context.WithTimeout(context.Background(), time.Second)
	defer cancelAccept()
	server, err := service.Accept(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	fromClient := protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 11, ToPeerID: 22, PacketType: protocol.PacketTypeData},
		Payload: []byte("from client"),
	}
	if err := client.Send(context.Background(), fromClient); err != nil {
		t.Fatal(err)
	}
	received, err := server.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if received.Header.FromPeerID != fromClient.Header.FromPeerID || received.Header.ToPeerID != fromClient.Header.ToPeerID || string(received.Payload) != string(fromClient.Payload) {
		t.Fatalf("server received %#v, want %#v", received, fromClient)
	}

	body, err := fromClient.MarshalBody()
	if err != nil {
		t.Fatal(err)
	}
	wrongID, err := (protocol.UDPDatagram{
		Header:  protocol.UDPTunnelHeader{ConnectionID: client.connID + 1, MessageType: protocol.UDPPacketTypeData},
		Payload: body,
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.socket.WriteToUDP(wrongID, client.remote); err != nil {
		t.Fatal(err)
	}
	noPacketCtx, cancelNoPacket := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelNoPacket()
	if _, err := server.Receive(noPacketCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive after bad connection ID = %v, want deadline exceeded", err)
	}

	fromServer := protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 22, ToPeerID: 11, PacketType: protocol.PacketTypeData},
		Payload: []byte("from server"),
	}
	if err := server.Send(context.Background(), fromServer); err != nil {
		t.Fatal(err)
	}
	received, err = client.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if received.Header.FromPeerID != fromServer.Header.FromPeerID || received.Header.ToPeerID != fromServer.Header.ToPeerID || string(received.Payload) != string(fromServer.Payload) {
		t.Fatalf("client received %#v, want %#v", received, fromServer)
	}

	stopServe()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP service did not stop after context cancellation")
	}
}

func TestUDPSendRejectsPeerPacketOverUDPLimit(t *testing.T) {
	session := newUDPSession(nil, nil, 1, nil)
	defer session.Close()
	packet := protocol.Packet{Payload: make([]byte, protocol.UDPMaxPayloadSize-protocol.PeerManagerHeaderSize+1)}
	if err := session.Send(context.Background(), packet); err == nil {
		t.Fatal("Send accepted a peer packet larger than the UDP payload limit")
	}
}

func TestUDPServiceRejectsSYNWhenPendingLimitIsReached(t *testing.T) {
	service, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	service.mu.Lock()
	for i := 0; i < maximumPendingSessions; i++ {
		service.pending[udpSessionKey{remote: "127.0.0.1:1", connID: uint32(i)}] = time.Now().Add(time.Second)
	}
	service.mu.Unlock()

	service.handleSYN(udpSessionKey{remote: "127.0.0.1:2", connID: 999}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}, protocol.UDPDatagram{
		Header:  protocol.UDPTunnelHeader{ConnectionID: 999, MessageType: protocol.UDPPacketTypeSYN},
		Payload: make([]byte, 8),
	})
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.sessions) != 0 {
		t.Fatal("service created a session after its pending limit was reached")
	}
}

func TestUDPDatagramRejectsNonZeroReservedHeaderByte(t *testing.T) {
	data := make([]byte, protocol.UDPTunnelHeaderSize)
	data[5] = 1
	if _, err := protocol.ParseUDPDatagram(data); err == nil {
		t.Fatal("UDP parser accepted a non-zero reserved header byte")
	}
}

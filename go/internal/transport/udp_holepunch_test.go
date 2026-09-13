// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestAdoptUDPWithSocketDial(t *testing.T) {
	service, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer service.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.Serve(ctx) }()

	accepted := make(chan *UDPSession, 1)
	go func() {
		session, err := service.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	local := service.Address().(*net.UDPAddr)
	session, err := DialUDPWithSocket(ctx, socket, local)
	if err != nil {
		t.Fatalf("dial with socket: %v", err)
	}
	defer session.Close()

	packet := protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: []byte("punched"),
	}
	if err := session.Send(context.Background(), packet); err != nil {
		t.Fatalf("send: %v", err)
	}

	serverSession := <-accepted
	defer serverSession.Close()
	received, err := serverSession.Receive(ctx)
	if err != nil {
		t.Fatalf("server receive: %v", err)
	}
	if string(received.Payload) != "punched" {
		t.Fatalf("payload = %q", received.Payload)
	}
	if err := serverSession.Send(ctx, received); err != nil {
		t.Fatalf("server echo: %v", err)
	}

	echoed, err := session.Receive(ctx)
	if err != nil {
		t.Fatalf("client receive: %v", err)
	}
	if string(echoed.Payload) != "punched" {
		t.Fatalf("echo payload = %q", echoed.Payload)
	}
}

func TestUDPServiceAnswersLoopbackHolePunchControl(t *testing.T) {
	service, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer service.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.Serve(ctx) }()

	// A bystander socket plays the punch target and waits for the burst.
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind target: %v", err)
	}
	defer target.Close()
	targetAddr := target.LocalAddr().(*net.UDPAddr)
	var targetIP [4]byte
	copy(targetIP[:], targetAddr.IP.To4())

	listenerAddr := service.Address().(*net.UDPAddr)
	control := protocol.UDPDatagram{
		Header: protocol.UDPTunnelHeader{
			ConnectionID: uint32(listenerAddr.Port),
			MessageType:  protocol.UDPPacketTypeV4HolePunch,
			PayloadSize:  protocol.V4HolePunchPayloadSize,
		},
		Payload: protocol.EncodeV4HolePunchControl(targetIP, uint16(targetAddr.Port)),
	}
	wire, err := control.Marshal()
	if err != nil {
		t.Fatalf("marshal control: %v", err)
	}
	injector, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind injector: %v", err)
	}
	defer injector.Close()
	if _, err := injector.WriteToUDP(wire, listenerAddr); err != nil {
		t.Fatalf("send control: %v", err)
	}

	buffer := make([]byte, 128)
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := target.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read punch burst: %v", err)
	}
	datagram, err := protocol.ParseUDPDatagram(buffer[:n])
	if err != nil {
		t.Fatalf("parse punch burst: %v", err)
	}
	if datagram.Header.MessageType != protocol.UDPPacketTypeHolePunch {
		t.Fatalf("message type = %d, want hole punch", datagram.Header.MessageType)
	}
	if datagram.Header.ConnectionID != holePunchControlTID {
		t.Fatalf("tid = %d, want %d", datagram.Header.ConnectionID, holePunchControlTID)
	}
}

func TestEncodeDecodeHolePunchControl(t *testing.T) {
	encoded := protocol.EncodeV4HolePunchControl([4]byte{127, 0, 0, 1}, 40144)
	decoded, err := protocol.DecodeHolePunchControl(protocol.UDPPacketTypeV4HolePunch, encoded)
	if err != nil {
		t.Fatalf("decode v4: %v", err)
	}
	if got := binary.BigEndian.Uint32(decoded.IP.To4()); got != 0x7F000001 || decoded.Port != 40144 {
		t.Fatalf("decoded = %v:%d", decoded.IP, decoded.Port)
	}

	encodedV6 := protocol.EncodeV6HolePunchControl([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 41000)
	decodedV6, err := protocol.DecodeHolePunchControl(protocol.UDPPacketTypeV6HolePunch, encodedV6)
	if err != nil {
		t.Fatalf("decode v6: %v", err)
	}
	if decodedV6.Port != 41000 {
		t.Fatalf("decoded port = %d", decodedV6.Port)
	}

	if _, err := protocol.DecodeHolePunchControl(protocol.UDPPacketTypeV4HolePunch, []byte{1, 2, 3}); err == nil {
		t.Error("short payload should fail")
	}
}

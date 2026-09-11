// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package nat

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestHolePunchPayloadVectors(t *testing.T) {
	tests := []struct {
		name    string
		address netip.AddrPort
		encode  func(netip.AddrPort) ([]byte, error)
		decode  func([]byte) (netip.AddrPort, error)
		want    []byte
	}{
		{
			name:    "IPv4",
			address: netip.MustParseAddrPort("192.0.2.1:4660"),
			encode:  EncodeV4HolePunchPayload,
			decode:  DecodeV4HolePunchPayload,
			want:    []byte{192, 0, 2, 1, 0x34, 0x12},
		},
		{
			name:    "IPv6",
			address: netip.MustParseAddrPort("[2001:db8::1]:4660"),
			encode:  EncodeV6HolePunchPayload,
			decode:  DecodeV6HolePunchPayload,
			want:    []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x34, 0x12},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := test.encode(test.address)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, test.want) {
				t.Fatalf("payload = %x, want %x", payload, test.want)
			}
			decoded, err := test.decode(payload)
			if err != nil {
				t.Fatal(err)
			}
			if decoded != test.address {
				t.Fatalf("decoded address = %s, want %s", decoded, test.address)
			}
		})
	}
}

func TestHolePunchPayloadRejectsInvalidLengths(t *testing.T) {
	for _, decode := range []func([]byte) (netip.AddrPort, error){
		DecodeV4HolePunchPayload,
		DecodeV6HolePunchPayload,
	} {
		for _, length := range []int{0, 1, V4HolePunchPayloadSize - 1, V4HolePunchPayloadSize + 1, V6HolePunchPayloadSize - 1, V6HolePunchPayloadSize + 1} {
			if _, err := decode(make([]byte, length)); err == nil {
				t.Fatalf("decode accepted payload length %d", length)
			}
		}
	}
}

func TestSendBurstOnLoopback(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	packet := []byte("hole punch")
	if err := SendBurst(context.Background(), sender, receiver.LocalAddr().(*net.UDPAddr), packet, 3, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		buffer := make([]byte, 64)
		n, _, err := receiver.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:n], packet) {
			t.Fatalf("packet %d = %q, want %q", i, buffer[:n], packet)
		}
	}
}

func TestSendBurstHonorsCancellation(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	err = SendBurst(ctx, conn, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, []byte{1}, 100, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SendBurst error = %v, want context.Canceled", err)
	}
}

func TestListenerAcceptsOnlyMatchingLoopbackControl(t *testing.T) {
	control, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	targetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer targetConn.Close()

	target := netip.MustParseAddrPort(targetConn.LocalAddr().String())
	listener, err := NewListener(control, target)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- listener.Serve(ctx) }()

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	wrongTarget := netip.MustParseAddrPort("127.0.0.1:1")
	payload, err := EncodeV4HolePunchPayload(wrongTarget)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := (protocol.UDPDatagram{
		Header:  protocol.UDPTunnelHeader{MessageType: protocol.UDPPacketTypeV4HolePunch},
		Payload: payload,
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.WriteToUDP(wrong, control.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	payload, err = EncodeV4HolePunchPayload(target)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := (protocol.UDPDatagram{
		Header:  protocol.UDPTunnelHeader{MessageType: protocol.UDPPacketTypeV4HolePunch},
		Payload: payload,
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.WriteToUDP(valid, control.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	if err := targetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 256)
	n, _, err := targetConn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ParseUDPDatagram(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.MessageType != protocol.UDPPacketTypeHolePunch {
		t.Fatalf("response type = %d, want %d", response.Header.MessageType, protocol.UDPPacketTypeHolePunch)
	}

	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("listener error = %v, want context.Canceled", err)
	}
}

func TestPredictPortsIsBounded(t *testing.T) {
	if got, want := PredictPorts(65534, 4, true), []uint16{65535}; !equalPorts(got, want) {
		t.Fatalf("increasing ports = %v, want %v", got, want)
	}
	if got, want := PredictPorts(3, 8, false), []uint16{1, 2}; !equalPorts(got, want) {
		t.Fatalf("decreasing ports = %v, want %v", got, want)
	}
}

func equalPorts(got, want []uint16) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestHolePunchPayloadUsesLittleEndianPort(t *testing.T) {
	payload, err := EncodeV4HolePunchPayload(netip.MustParseAddrPort("192.0.2.1:4660"))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(payload[4:]); got != 4660 {
		t.Fatalf("port = %d, want %d", got, 4660)
	}
}

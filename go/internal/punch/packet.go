// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package punch implements EasyTier UDP hole punching: the socket array,
// punch listener pool, the UdpHolePunchRpc service, the cone / symmetric
// client strategies, and the coordinator that drives them.
package punch

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// HolePunchBodyLen is the payload length of a punch datagram. The socket
// array validates this length exactly, so it must stay in sync with the
// reference implementation.
const HolePunchBodyLen = 16

// NewHolePunchPacket builds one punch datagram carrying a random body.
func NewHolePunchPacket(transactionID uint32, bodyLen int) ([]byte, error) {
	if bodyLen < 0 || bodyLen > protocol.UDPMaxPayloadSize {
		return nil, fmt.Errorf("hole punch body length %d is out of range", bodyLen)
	}
	body := make([]byte, bodyLen)
	if _, err := cryptorand.Read(body); err != nil {
		return nil, fmt.Errorf("generate hole punch body: %w", err)
	}
	return (protocol.UDPDatagram{
		Header: protocol.UDPTunnelHeader{
			ConnectionID: transactionID,
			MessageType:  protocol.UDPPacketTypeHolePunch,
			PayloadSize:  uint16(bodyLen),
		},
		Payload: body,
	}).Marshal()
}

// punchDatagram is a validated hole punch datagram.
type punchDatagram struct {
	tid uint32
}

// parsePunchDatagram validates one received datagram as a punch packet with
// the exact reference body length.
func parsePunchDatagram(data []byte) (punchDatagram, error) {
	datagram, err := protocol.ParseUDPDatagram(data)
	if err != nil {
		return punchDatagram{}, err
	}
	if datagram.Header.MessageType != protocol.UDPPacketTypeHolePunch || len(datagram.Payload) != HolePunchBodyLen {
		return punchDatagram{}, fmt.Errorf("datagram is not a hole punch packet")
	}
	return punchDatagram{tid: datagram.Header.ConnectionID}, nil
}

// addrPortToProto converts a Go address into the proto SocketAddr shape.
func addrPortToProto(addr netip.AddrPort) (*common.SocketAddr, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("socket address is invalid")
	}
	if addr.Addr().Is4() {
		raw := addr.Addr().As4()
		return &common.SocketAddr{
			Ip:   &common.SocketAddr_Ipv4{Ipv4: &common.Ipv4Addr{Addr: binary.BigEndian.Uint32(raw[:])}},
			Port: uint32(addr.Port()),
		}, nil
	}
	raw := addr.Addr().As16()
	return &common.SocketAddr{
		Ip: &common.SocketAddr_Ipv6{Ipv6: &common.Ipv6Addr{
			Part1: binary.BigEndian.Uint32(raw[0:4]),
			Part2: binary.BigEndian.Uint32(raw[4:8]),
			Part3: binary.BigEndian.Uint32(raw[8:12]),
			Part4: binary.BigEndian.Uint32(raw[12:16]),
		}},
		Port: uint32(addr.Port()),
	}, nil
}

// protoToAddrPort converts a proto SocketAddr into a Go address.
func protoToAddrPort(addr *common.SocketAddr) (netip.AddrPort, error) {
	if addr == nil {
		return netip.AddrPort{}, fmt.Errorf("socket address is missing")
	}
	switch value := addr.Ip.(type) {
	case *common.SocketAddr_Ipv4:
		if value.Ipv4 == nil {
			return netip.AddrPort{}, fmt.Errorf("IPv4 socket address is empty")
		}
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], value.Ipv4.Addr)
		return netip.AddrPortFrom(netip.AddrFrom4(raw), uint16(addr.Port)), nil
	case *common.SocketAddr_Ipv6:
		if value.Ipv6 == nil {
			return netip.AddrPort{}, fmt.Errorf("IPv6 socket address is empty")
		}
		var raw [16]byte
		binary.BigEndian.PutUint32(raw[0:4], value.Ipv6.Part1)
		binary.BigEndian.PutUint32(raw[4:8], value.Ipv6.Part2)
		binary.BigEndian.PutUint32(raw[8:12], value.Ipv6.Part3)
		binary.BigEndian.PutUint32(raw[12:16], value.Ipv6.Part4)
		return netip.AddrPortFrom(netip.AddrFrom16(raw), uint16(addr.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("socket address has no IP")
	}
}

// ipv4ToProto converts a Go IPv4 address into the proto Ipv4Addr shape.
func ipv4ToProto(addr netip.Addr) (*common.Ipv4Addr, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("address %s is not IPv4", addr)
	}
	raw := addr.As4()
	return &common.Ipv4Addr{Addr: binary.BigEndian.Uint32(raw[:])}, nil
}

// protoToIPv4 converts a proto Ipv4Addr into a Go address.
func protoToIPv4(addr *common.Ipv4Addr) (netip.Addr, error) {
	if addr == nil {
		return netip.Addr{}, fmt.Errorf("IPv4 address is missing")
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], addr.Addr)
	return netip.AddrFrom4(raw), nil
}

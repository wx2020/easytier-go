// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package directconn implements the direct connector: address discovery via
// the DirectConnectorRpc service, UDP punch assistance, the dial loop that
// upgrades routed peers into direct connections, and manual connector
// management.
package directconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/stun"
	"google.golang.org/protobuf/encoding/protojson"
)

// ServiceName is the proto service name for direct connection assistance.
const ServiceName = "DirectConnectorRpc"

// Method indices follow the proto service declaration order.
const (
	MethodGetIpList              uint32 = 0
	MethodSendUdpHolePunchPacket uint32 = 1
)

// punchAssistPackets is how many loopback control datagrams the responder
// injects per request, and their pacing.
const (
	punchAssistPackets     = 3
	punchAssistInterval    = 30 * time.Millisecond
	punchAssistCallTimeout = 3 * time.Second
)

// ListenerURLs supplies the local tunnel listener URLs (mapped listeners
// first, then running listeners).
type ListenerURLs func() []string

// IPListService implements the DirectConnectorRpc responder side.
type IPListService struct {
	stun      stun.Source
	listeners ListenerURLs
}

// NewIPListService builds the responder.
func NewIPListService(stunSource stun.Source, listeners ListenerURLs) *IPListService {
	return &IPListService{stun: stunSource, listeners: listeners}
}

// ServiceName implements rpc.RpcService.
func (s *IPListService) ServiceName() string { return ServiceName }

// HandleMethod implements rpc.RpcService with protojson bodies.
func (s *IPListService) HandleMethod(methodIndex uint32, ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
	switch methodIndex {
	case MethodGetIpList:
		response, err := s.getIPList(ctx)
		if err != nil {
			return nil, err
		}
		body, err := protojson.Marshal(response)
		if err != nil {
			return nil, fmt.Errorf("encode ip list response: %w", err)
		}
		return body, nil
	case MethodSendUdpHolePunchPacket:
		var request peer_rpc.SendUdpHolePunchPacketRequest
		if len(requestBody) > 0 {
			if err := (protojson.UnmarshalOptions{}).Unmarshal(requestBody, &request); err != nil {
				return nil, fmt.Errorf("decode send udp hole punch packet request: %w", err)
			}
		}
		if err := s.sendUdpHolePunchPacket(ctx, &request); err != nil {
			return nil, err
		}
		return protojson.Marshal(&common.Void{})
	default:
		return nil, fmt.Errorf("unknown %s method %d", ServiceName, methodIndex)
	}
}

// getIPList assembles interface addresses, public addresses, and listeners.
func (s *IPListService) getIPList(ctx context.Context) (*peer_rpc.GetIpListResponse, error) {
	response := &peer_rpc.GetIpListResponse{}

	interfaceV4, interfaceV6, err := localInterfaceIPs()
	if err != nil {
		return nil, err
	}
	for _, ip := range interfaceV4 {
		response.InterfaceIpv4S = append(response.InterfaceIpv4S, mustIPv4ToProto(ip))
	}
	for _, ip := range interfaceV6 {
		response.InterfaceIpv6S = append(response.InterfaceIpv6S, mustIPv6ToProto(ip))
	}

	info := s.stun.GetStunInfo()
	for _, raw := range info.GetPublicIp() {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		switch {
		case addr.Is4():
			response.PublicIpv4 = mustIPv4ToProto(addr)
		case addr.Is6() && !addr.Is4In6():
			response.PublicIpv6 = mustIPv6ToProto(addr)
		}
		if response.PublicIpv4 != nil && response.PublicIpv6 != nil {
			break
		}
	}

	if s.listeners != nil {
		for _, raw := range s.listeners() {
			response.Listeners = append(response.Listeners, &common.Url{Url: raw})
		}
	}
	return response, nil
}

// sendUdpHolePunchPacket injects loopback control datagrams into the local
// UDP listener on listenerPort so it emits punch bursts toward connectorAddr
// from its public socket.
func (s *IPListService) sendUdpHolePunchPacket(ctx context.Context, request *peer_rpc.SendUdpHolePunchPacketRequest) error {
	listenerPort := request.GetListenerPort()
	if listenerPort == 0 || listenerPort > 0xFFFF {
		return errors.New("listener port is invalid")
	}
	connectorAddr, err := protoToAddrPort(request.GetConnectorAddr())
	if err != nil {
		return err
	}

	var messageType uint8
	var payload []byte
	var network string
	var loopback netip.Addr
	if connectorAddr.Addr().Is4() {
		messageType = protocol.UDPPacketTypeV4HolePunch
		payload = protocol.EncodeV4HolePunchControl(connectorAddr.Addr().As4(), connectorAddr.Port())
		network, loopback = "udp4", netip.MustParseAddr("127.0.0.1")
	} else {
		messageType = protocol.UDPPacketTypeV6HolePunch
		payload = protocol.EncodeV6HolePunchControl(connectorAddr.Addr().As16(), connectorAddr.Port())
		network, loopback = "udp6", netip.MustParseAddr("::1")
	}
	socket, err := net.ListenUDP(network, &net.UDPAddr{IP: nil})
	if err != nil {
		return fmt.Errorf("bind punch assist socket: %w", err)
	}
	defer socket.Close()
	target := &net.UDPAddr{IP: net.IP(loopback.AsSlice()), Port: int(listenerPort)}

	datagram, err := (protocol.UDPDatagram{
		Header: protocol.UDPTunnelHeader{
			ConnectionID: listenerPort,
			MessageType:  messageType,
			PayloadSize:  uint16(len(payload)),
		},
		Payload: payload,
	}).Marshal()
	if err != nil {
		return err
	}

	for i := 0; i < punchAssistPackets; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := socket.WriteToUDP(datagram, target); err != nil {
			return fmt.Errorf("send punch assist control: %w", err)
		}
		if i+1 < punchAssistPackets {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(punchAssistInterval):
			}
		}
	}
	return nil
}

// localInterfaceIPs returns the host's non-loopback interface addresses.
func localInterfaceIPs() ([]netip.Addr, []netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("list network interfaces: %w", err)
	}
	var v4, v6 []netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ipNet, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
				continue
			}
			if addr.Is4In6() {
				addr = addr.Unmap()
			}
			if addr.Is4() {
				v4 = append(v4, addr)
			} else {
				v6 = append(v6, addr)
			}
		}
	}
	return dedupAddrs(v4), dedupAddrs(v6), nil
}

func dedupAddrs(addrs []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(addrs))
	out := addrs[:0]
	for _, addr := range addrs {
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func mustIPv4ToProto(addr netip.Addr) *common.Ipv4Addr {
	if !addr.Is4() {
		return nil
	}
	raw := addr.As4()
	return &common.Ipv4Addr{Addr: uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])}
}

func mustIPv6ToProto(addr netip.Addr) *common.Ipv6Addr {
	if !addr.Is6() {
		return nil
	}
	raw := addr.As16()
	word := func(i int) uint32 {
		return uint32(raw[i])<<24 | uint32(raw[i+1])<<16 | uint32(raw[i+2])<<8 | uint32(raw[i+3])
	}
	return &common.Ipv6Addr{Part1: word(0), Part2: word(4), Part3: word(8), Part4: word(12)}
}

func protoToAddrPort(addr *common.SocketAddr) (netip.AddrPort, error) {
	if addr == nil {
		return netip.AddrPort{}, errors.New("socket address is missing")
	}
	switch value := addr.Ip.(type) {
	case *common.SocketAddr_Ipv4:
		if value.Ipv4 == nil {
			return netip.AddrPort{}, errors.New("IPv4 socket address is empty")
		}
		raw := [4]byte{
			byte(value.Ipv4.Addr >> 24), byte(value.Ipv4.Addr >> 16), byte(value.Ipv4.Addr >> 8), byte(value.Ipv4.Addr),
		}
		return netip.AddrPortFrom(netip.AddrFrom4(raw), uint16(addr.Port)), nil
	case *common.SocketAddr_Ipv6:
		if value.Ipv6 == nil {
			return netip.AddrPort{}, errors.New("IPv6 socket address is empty")
		}
		raw := [16]byte{
			byte(value.Ipv6.Part1 >> 24), byte(value.Ipv6.Part1 >> 16), byte(value.Ipv6.Part1 >> 8), byte(value.Ipv6.Part1),
			byte(value.Ipv6.Part2 >> 24), byte(value.Ipv6.Part2 >> 16), byte(value.Ipv6.Part2 >> 8), byte(value.Ipv6.Part2),
			byte(value.Ipv6.Part3 >> 24), byte(value.Ipv6.Part3 >> 16), byte(value.Ipv6.Part3 >> 8), byte(value.Ipv6.Part3),
			byte(value.Ipv6.Part4 >> 24), byte(value.Ipv6.Part4 >> 16), byte(value.Ipv6.Part4 >> 8), byte(value.Ipv6.Part4),
		}
		return netip.AddrPortFrom(netip.AddrFrom16(raw), uint16(addr.Port)), nil
	default:
		return netip.AddrPort{}, errors.New("socket address has no IP")
	}
}

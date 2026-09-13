// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package stun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func response(source netip.AddrPort) BindResponse {
	return BindResponse{
		LocalAddr:    netip.MustParseAddrPort("0.0.0.0:40000"),
		ServerAddr:   source,
		RecvFromAddr: source,
		MappedAddr:   netip.MustParseAddrPort("203.0.113.7:55555"),
		MappedValid:  true,
	}
}

func TestNATTypeClassificationTables(t *testing.T) {
	serverA := netip.MustParseAddrPort("198.51.100.1:3478")
	serverB := netip.MustParseAddrPort("198.51.100.2:3478")
	serverBAlt := netip.MustParseAddrPort("198.51.100.2:3479")

	cases := []struct {
		name      string
		transport string
		responses []BindResponse
		extra     *BindResponse
		want      int
	}{
		{
			name:      "too few servers is unknown",
			transport: TransportUDP,
			responses: []BindResponse{response(serverA), response(serverA)},
			want:      NatTypeUnknown,
		},
		{
			name:      "no change honored is port restricted",
			transport: TransportUDP,
			responses: []BindResponse{response(serverA), response(serverB)},
			want:      NatTypePortRestricted,
		},
		{
			name:      "port change honored is restricted",
			transport: TransportUDP,
			responses: []BindResponse{response(serverA), {ServerAddr: serverB, RecvFromAddr: serverBAlt, MappedAddr: netip.MustParseAddrPort("203.0.113.7:55555"), MappedValid: true, RealPortChanged: true}},
			want:      NatTypeRestricted,
		},
		{
			name:      "same port across servers is no PAT",
			transport: TransportUDP,
			responses: []BindResponse{
				{LocalAddr: netip.MustParseAddrPort("0.0.0.0:40000"), ServerAddr: serverA, RecvFromAddr: serverA, MappedAddr: netip.MustParseAddrPort("203.0.113.7:40000"), MappedValid: true, RealIPChanged: true},
				{LocalAddr: netip.MustParseAddrPort("0.0.0.0:40000"), ServerAddr: serverB, RecvFromAddr: serverB, MappedAddr: netip.MustParseAddrPort("203.0.113.7:40000"), MappedValid: true, RealIPChanged: true},
			},
			want: NatTypeNoPAT,
		},
		{
			name:      "varying ports is symmetric",
			transport: TransportUDP,
			responses: []BindResponse{
				{ServerAddr: serverA, RecvFromAddr: serverA, MappedAddr: netip.MustParseAddrPort("203.0.113.7:40001"), MappedValid: true},
				{ServerAddr: serverB, RecvFromAddr: serverB, MappedAddr: netip.MustParseAddrPort("203.0.113.7:40200"), MappedValid: true},
			},
			want: NatTypeSymmetric,
		},
		{
			name:      "narrow increment is easy symmetric",
			transport: TransportUDP,
			responses: []BindResponse{
				{ServerAddr: serverA, RecvFromAddr: serverA, MappedAddr: netip.MustParseAddrPort("203.0.113.7:40100"), MappedValid: true},
				{ServerAddr: serverB, RecvFromAddr: serverB, MappedAddr: netip.MustParseAddrPort("203.0.113.7:40102"), MappedValid: true},
			},
			extra: &BindResponse{MappedAddr: netip.MustParseAddrPort("203.0.113.7:40103"), MappedValid: true},
			want:  NatTypeSymmetricEasyInc,
		},
		{
			name:      "narrow decrement is easy symmetric dec",
			transport: TransportUDP,
			responses: []BindResponse{
				{ServerAddr: serverA, RecvFromAddr: serverA, MappedAddr: netip.MustParseAddrPort("203.0.113.7:40100"), MappedValid: true},
				{ServerAddr: serverB, RecvFromAddr: serverB, MappedAddr: netip.MustParseAddrPort("203.0.113.7:40102"), MappedValid: true},
			},
			extra: &BindResponse{MappedAddr: netip.MustParseAddrPort("203.0.113.7:40099"), MappedValid: true},
			want:  NatTypeSymmetricEasyDec,
		},
		{
			name:      "tcp cone",
			transport: TransportTCP,
			responses: []BindResponse{response(serverA), response(serverB)},
			want:      NatTypeFullCone,
		},
		{
			name:      "tcp symmetric",
			transport: TransportTCP,
			responses: []BindResponse{
				{ServerAddr: serverA, RecvFromAddr: serverA, MappedAddr: netip.MustParseAddrPort("203.0.113.7:40001"), MappedValid: true},
				{ServerAddr: serverB, RecvFromAddr: serverB, MappedAddr: netip.MustParseAddrPort("203.0.113.7:40200"), MappedValid: true},
			},
			want: NatTypeSymmetric,
		},
	}
	for _, c := range cases {
		result := &DetectResult{Transport: c.transport, Responses: c.responses, ExtraBind: c.extra}
		if got := result.NATType(); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// fakeSTUNServer answers binding requests over loopback, optionally honoring
// a change-port request by replying from an alternate socket.
type fakeSTUNServer struct {
	mu        sync.Mutex
	socket    *net.UDPConn
	alternate *net.UDPConn
	stop      chan struct{}
	wg        sync.WaitGroup
}

func newFakeSTUNServer(t *testing.T, withAlternate bool) *fakeSTUNServer {
	t.Helper()
	server := &fakeSTUNServer{stop: make(chan struct{})}
	var err error
	server.socket, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind fake stun server: %v", err)
	}
	if withAlternate {
		server.alternate, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("bind fake stun alternate: %v", err)
		}
	}
	server.wg.Add(1)
	go server.serve()
	t.Cleanup(func() {
		close(server.stop)
		_ = server.socket.Close()
		if server.alternate != nil {
			_ = server.alternate.Close()
		}
		server.wg.Wait()
	})
	return server
}

func (s *fakeSTUNServer) addr() netip.AddrPort {
	local := s.socket.LocalAddr().(*net.UDPAddr)
	ip, _ := netip.AddrFromSlice(local.IP.To4())
	return netip.AddrPortFrom(ip, uint16(local.Port))
}

func (s *fakeSTUNServer) serve() {
	defer s.wg.Done()
	buffer := make([]byte, 1024)
	for {
		n, from, err := s.socket.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		request := append([]byte(nil), buffer[:n]...)
		changePort := false
		if n >= 28 && binary.BigEndian.Uint16(request[0:2]) == stunBindingRequest {
			offset := 20
			length := int(binary.BigEndian.Uint16(request[2:4]))
			for offset+4 <= 20+length && offset+4 <= len(request) {
				attrType := binary.BigEndian.Uint16(request[offset : offset+2])
				attrLen := int(binary.BigEndian.Uint16(request[offset+2 : offset+4]))
				if attrType == attrChangeRequest && attrLen == 4 && offset+8 <= len(request) {
					flags := binary.BigEndian.Uint32(request[offset+4 : offset+8])
					changePort = flags&changeRequestFlagPT != 0
				}
				offset += 4 + (attrLen+3)&^3
			}
		}

		var tid [12]byte
		copy(tid[:], request[8:20])
		reply := buildTestSuccessResponse(tid, from)
		target := s.socket
		if changePort && s.alternate != nil {
			target = s.alternate
		}
		if _, err := target.WriteToUDP(reply, from); err != nil {
			select {
			case <-s.stop:
				return
			default:
			}
		}
	}
}

func extractTID(message []byte) [12]byte {
	var tid [12]byte
	if len(message) >= 20 {
		copy(tid[:], message[8:20])
	}
	return tid
}

// buildTestSuccessResponse answers with XOR-MAPPED-ADDRESS of from.
func buildTestSuccessResponse(tid [12]byte, from *net.UDPAddr) []byte {
	ip := from.IP.To4()
	port := from.Port
	xorPort := uint16(port) ^ uint16(magicCookie>>16)
	var xorIP [4]byte
	cookie := [4]byte{0x21, 0x12, 0xA4, 0x42}
	for i := range xorIP {
		xorIP[i] = ip[i] ^ cookie[i]
	}

	attr := make([]byte, 12)
	binary.BigEndian.PutUint16(attr[0:2], attrXORMappedAddr)
	binary.BigEndian.PutUint16(attr[2:4], 8)
	attr[4] = 0
	attr[5] = 0x01
	binary.BigEndian.PutUint16(attr[6:8], xorPort)
	copy(attr[8:12], xorIP[:])

	message := make([]byte, 20+len(attr))
	binary.BigEndian.PutUint16(message[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint16(message[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(message[4:8], magicCookie)
	copy(message[8:20], tid[:])
	copy(message[20:], attr)
	return message
}

func TestUdpDetectRestrictedOverLoopback(t *testing.T) {
	server1 := newFakeSTUNServer(t, true)
	server2 := newFakeSTUNServer(t, true)

	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatalf("bind probe socket: %v", err)
	}
	defer socket.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := udpDetect(ctx, socket, []netip.AddrPort{server1.addr(), server2.addr()})
	if err != nil {
		t.Fatalf("udpDetect: %v", err)
	}
	// The change-port probe answers from the alternate socket, so the NAT
	// behaves like a restricted cone in this setup.
	if got := result.NATType(); got != NatTypeRestricted {
		t.Fatalf("nat type = %d, want restricted (%d responses)", got, len(result.Responses))
	}
	if len(result.AvailableServers()) != 2 {
		t.Errorf("available servers = %d, want 2", len(result.AvailableServers()))
	}
	if len(result.PublicIPs()) != 1 {
		t.Errorf("public ips = %v, want one", result.PublicIPs())
	}
}

func TestCollectorPortMappingOverLoopback(t *testing.T) {
	server := newFakeSTUNServer(t, false)
	collector := NewCollector([]string{server.addr().String()}, []string{server.addr().String()}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mapped, err := collector.GetUDPPortMapping(ctx, 0)
	if err != nil {
		t.Fatalf("GetUDPPortMapping: %v", err)
	}
	if !mapped.Addr().IsLoopback() {
		t.Errorf("mapped address %s is not loopback", mapped)
	}

	info := collector.GetStunInfo()
	if info == nil {
		t.Fatal("GetStunInfo returned nil")
	}
}

func TestBindingRequestWireFormat(t *testing.T) {
	var tid [12]byte
	for i := range tid {
		tid[i] = byte(i)
	}
	request := buildBindingRequest(tid, true, true)
	if len(request) != 28 {
		t.Fatalf("request length = %d, want 28", len(request))
	}
	if binary.BigEndian.Uint16(request[0:2]) != stunBindingRequest {
		t.Error("request message type is wrong")
	}
	if binary.BigEndian.Uint16(request[20:22]) != attrChangeRequest {
		t.Error("change request attribute missing")
	}
	flags := binary.BigEndian.Uint32(request[24:28])
	if flags != changeRequestFlagIP|changeRequestFlagPT {
		t.Errorf("change flags = %#x", flags)
	}
}

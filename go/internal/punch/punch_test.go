// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package punch

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"google.golang.org/protobuf/encoding/protojson"
)

// loopbackTransport connects two peer RPC managers in memory. The peer
// pointer is filled in after both endpoints exist.
type loopbackTransport struct {
	peerID uint32
	peer   *rpc.PeerRpcManager
}

func (t *loopbackTransport) MyPeerID() uint32 { return t.peerID }

func (t *loopbackTransport) Send(ctx context.Context, dstPeerID uint32, packet protocol.Packet) error {
	return t.peer.HandlePacket(ctx, packet)
}

// newRPCPair builds two connected peer RPC managers.
func newRPCPair(t *testing.T, aID, bID uint32) (a, b *rpc.PeerRpcManager) {
	t.Helper()
	transportA := &loopbackTransport{peerID: aID}
	transportB := &loopbackTransport{peerID: bID}
	a, b = newRPCEndpoint(t, transportA), newRPCEndpoint(t, transportB)
	transportA.peer, transportB.peer = b, a
	return a, b
}

func newRPCEndpoint(t *testing.T, transport *loopbackTransport) *rpc.PeerRpcManager {
	t.Helper()
	manager, err := rpc.NewPeerRpcManager(transport)
	if err != nil {
		t.Fatalf("create peer rpc manager: %v", err)
	}
	return manager
}

func TestNewHolePunchPacketRoundtrip(t *testing.T) {
	packet, err := NewHolePunchPacket(0x1234, HolePunchBodyLen)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	datagram, err := parsePunchDatagram(packet)
	if err != nil {
		t.Fatalf("parse packet: %v", err)
	}
	if datagram.tid != 0x1234 {
		t.Fatalf("tid = %x, want 1234", datagram.tid)
	}
	if len(packet) != protocol.UDPTunnelHeaderSize+HolePunchBodyLen {
		t.Fatalf("packet size = %d", len(packet))
	}
	if _, err := parsePunchDatagram([]byte{1, 2, 3}); err == nil {
		t.Error("short datagram should not parse")
	}
}

func TestAddrPortProtoRoundtrip(t *testing.T) {
	addrs := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:40144"),
		netip.MustParseAddrPort("[2001:db8::1]:40145"),
	}
	for _, addr := range addrs {
		proto, err := addrPortToProto(addr)
		if err != nil {
			t.Fatalf("encode %s: %v", addr, err)
		}
		decoded, err := protoToAddrPort(proto)
		if err != nil {
			t.Fatalf("decode %s: %v", addr, err)
		}
		if decoded != addr {
			t.Fatalf("roundtrip = %s, want %s", decoded, addr)
		}
	}
}

func TestUdpSocketArrayCapturesPunchedSocket(t *testing.T) {
	array := NewUdpSocketArray(2)
	defer array.Close()
	if err := array.Start(); err != nil {
		t.Fatalf("start array: %v", err)
	}
	if !array.Started() || array.SocketCount() != 2 {
		t.Fatalf("array sockets = %d", array.SocketCount())
	}

	// The sender is an outside socket punching toward the first array socket.
	sockets := array.snapshotSockets()
	var target *net.UDPConn
	for _, conn := range sockets {
		target = conn
		break
	}
	targetAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: target.LocalAddr().(*net.UDPAddr).Port,
	}

	injector, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind injector: %v", err)
	}
	defer injector.Close()

	const tid = 0xdeadbeef
	array.AddInterestTID(tid)
	packet, err := NewHolePunchPacket(tid, HolePunchBodyLen)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	if _, err := injector.WriteToUDP(packet, targetAddr); err != nil {
		t.Fatalf("send punch: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := array.TryFetchPunchedSocket(tid); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("punched socket was never captured")
		}
		time.Sleep(20 * time.Millisecond)
	}
	array.RemoveInterestTID(tid)
	if _, ok := array.TryFetchPunchedSocket(tid); ok {
		t.Error("removed interest should drop captures")
	}
}

func TestBackOffLadder(t *testing.T) {
	backoff := NewBackOff([]int{100, 200, 400})
	if got := backoff.Next(); got != 100*time.Millisecond {
		t.Errorf("first = %s", got)
	}
	if got := backoff.Next(); got != 200*time.Millisecond {
		t.Errorf("second = %s", got)
	}
	backoff.Rollback()
	if got := backoff.Next(); got != 200*time.Millisecond {
		t.Errorf("after rollback = %s", got)
	}
	if got := backoff.Next(); got != 400*time.Millisecond {
		t.Errorf("third = %s", got)
	}
	if got := backoff.Next(); got != 400*time.Millisecond {
		t.Errorf("capped = %s", got)
	}
}

func TestTimedSetExpiry(t *testing.T) {
	set := NewTimedSet(50 * time.Millisecond)
	set.Insert(7)
	if !set.Contains(7) {
		t.Fatal("entry should be present")
	}
	time.Sleep(80 * time.Millisecond)
	if set.Contains(7) {
		t.Fatal("entry should have expired")
	}
}

// mockStun reports loopback mappings so punching works without a real NAT.
type mockStun struct{}

func (mockStun) GetStunInfo() *common.StunInfo {
	return &common.StunInfo{
		UdpNatType: common.NatType_PortRestricted,
		TcpNatType: common.NatType_PortRestricted,
		PublicIp:   []string{"127.0.0.1"},
	}
}

func (mockStun) GetUDPPortMapping(ctx context.Context, localPort uint16) (netip.AddrPort, error) {
	if localPort == 0 {
		localPort = 40144
	}
	return netip.AddrPortFrom(loopbackV4, localPort), nil
}

func (mockStun) GetUDPPortMappingWithSocket(ctx context.Context, socket *net.UDPConn) (netip.AddrPort, error) {
	local, err := netip.ParseAddrPort(socket.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(loopbackV4, local.Port()), nil
}

func (mockStun) GetTCPPortMapping(ctx context.Context, localPort uint16) (netip.AddrPort, error) {
	if localPort == 0 {
		localPort = 40144
	}
	return netip.AddrPortFrom(loopbackV4, localPort), nil
}

// TestConePunchEndToEnd punches between two in-process nodes over loopback:
// the client discovers the server's punch listener via RPC, both sides send
// punch datagrams, and the punched socket upgrades into a UDP tunnel session.
func TestConePunchEndToEnd(t *testing.T) {
	const domain = "test-net"
	rpcA, rpcB := newRPCPair(t, 1, 2)

	accepted := make(chan *transport.UDPSession, 8)
	serverPool := NewListenerPool(mockStun{}, nil, func(session *transport.UDPSession) {
		accepted <- session
	})
	serverService := NewService(serverPool, mockStun{})
	if err := rpcB.Register(domain, serverService); err != nil {
		t.Fatalf("register server service: %v", err)
	}

	serverPool.Start(context.Background())

	clients := &Clients{
		RPC:       rpcA,
		Domain:    domain,
		MyPeerID:  1,
		Stun:      mockStun{},
		Blacklist: NewTimedSet(time.Hour),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := clients.ConePunch(ctx, 2)
	if err != nil {
		t.Fatalf("cone punch: %v", err)
	}
	if session == nil {
		t.Fatal("cone punch returned no session")
	}
	defer session.Close()

	// The punched session must carry data end to end.
	var serverSession *transport.UDPSession
	select {
	case serverSession = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("server never accepted the punched session")
	}
	defer serverSession.Close()

	payload := protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: []byte("over-the-punch"),
	}
	if err := session.Send(ctx, payload); err != nil {
		t.Fatalf("send over punched session: %v", err)
	}
	received, err := serverSession.Receive(ctx)
	if err != nil {
		t.Fatalf("server receive: %v", err)
	}
	if string(received.Payload) != "over-the-punch" {
		t.Fatalf("payload = %q", received.Payload)
	}
}

// TestServiceEasySymHitsPredictedPorts verifies that the easy symmetric
// responder sends punch datagrams to every port in the predicted range.
func TestServiceEasySymHitsPredictedPorts(t *testing.T) {
	pool := NewListenerPool(mockStun{}, nil, nil)
	service := NewService(pool, mockStun{})

	// Base port and the ports to hit above it.
	baseSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind base: %v", err)
	}
	defer baseSocket.Close()
	basePort := uint32(baseSocket.LocalAddr().(*net.UDPAddr).Port)

	const span = 4
	var targets []*net.UDPConn
	for i := 1; i <= span; i++ {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(basePort) + i})
		if err != nil {
			t.Skipf("cannot bind predicted port %d: %v", basePort+uint32(i), err)
		}
		targets = append(targets, conn)
		defer conn.Close()
	}

	// The responder needs one of its own listeners to send from.
	if _, err := pool.SelectListener(context.Background(), false, false); err != nil {
		t.Fatalf("select listener: %v", err)
	}

	request := &peer_rpc.SendPunchPacketEasySymRequest{
		ListenerMappedAddr: nil,
		PublicIps:          []*common.Ipv4Addr{mustIPv4ToProto(loopbackV4)},
		TransactionId:      99,
		BasePortNum:        basePort,
		MaxPortNum:         span,
		IsIncremental:      true,
	}
	listenerMapped, err := pool.SelectListener(context.Background(), false, false)
	if err != nil {
		t.Fatalf("listener mapped: %v", err)
	}
	request.ListenerMappedAddr = mustAddrPortToProto(listenerMapped)

	body, err := protojson.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := service.HandleMethod(MethodSendPunchPacketEasySym, ctx, 1, body); err != nil {
		t.Fatalf("handle easy sym: %v", err)
	}

	buffer := make([]byte, 128)
	deadline := time.Now().Add(5 * time.Second)
	hits := 0
	for _, conn := range targets {
		_ = conn.SetReadDeadline(deadline)
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		datagram, err := protocol.ParseUDPDatagram(buffer[:n])
		if err == nil && datagram.Header.MessageType == protocol.UDPPacketTypeHolePunch && datagram.Header.ConnectionID == 99 {
			hits++
		}
	}
	if hits != span {
		t.Fatalf("predicted ports hit = %d, want %d", hits, span)
	}
}

func TestServiceSelectListenerRejectsUnknownMethod(t *testing.T) {
	pool := NewListenerPool(mockStun{}, nil, nil)
	service := NewService(pool, mockStun{})
	if _, err := service.HandleMethod(99, context.Background(), 1, nil); err == nil {
		t.Fatal("unknown method should fail")
	}
}

// loopbackV4 is the loopback address used across loopback punch tests.
var loopbackV4 = netip.MustParseAddr("127.0.0.1")

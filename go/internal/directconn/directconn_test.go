// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package directconn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/stun"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func ipListResponse() *peer_rpc.GetIpListResponse {
	return &peer_rpc.GetIpListResponse{
		InterfaceIpv4S: []*common.Ipv4Addr{mustIPv4ToProto(netip.MustParseAddr("192.0.2.10"))},
		PublicIpv4:     mustIPv4ToProto(netip.MustParseAddr("203.0.113.5")),
		InterfaceIpv6S: []*common.Ipv6Addr{mustIPv6ToProto(netip.MustParseAddr("2001:db8::10"))},
		Listeners: []*common.Url{
			{Url: "udp://0.0.0.0:11010"},
			{Url: "tcp://0.0.0.0:11011"},
			{Url: "ring://127.0.0.1:1"},
			{Url: "wss://example.internal:0"},
		},
	}
}

func TestExpandListenersFiltersAndOrders(t *testing.T) {
	entries := expandListeners(ipListResponse(), "tcp", true)
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	// Default protocol sorts last (processed first); ring is dropped; wss
	// without a port is dropped by the zero-port filter.
	last := entries[len(entries)-1]
	if last.scheme != "tcp" {
		t.Fatalf("last scheme = %s, want tcp", last.scheme)
	}
	var hasUDP bool
	for _, entry := range entries {
		if entry.scheme == "udp" {
			hasUDP = true
		}
	}
	if !hasUDP {
		t.Fatal("udp listener missing")
	}
}

func TestExpandListenersGatesIPv6(t *testing.T) {
	response := ipListResponse()
	response.Listeners = append(response.Listeners, &common.Url{Url: "tcp://[::]:11012"})
	entries := expandListeners(response, "tcp", false)
	for _, entry := range entries {
		if isV6Host(entry.host) {
			t.Fatalf("ipv6 listener leaked: %+v", entry)
		}
	}
}

func TestExpandAddrsUnspecifiedHost(t *testing.T) {
	c := NewConnector(ConnectorConfig{DefaultProtocol: "tcp"})
	entry := listenerEntry{url: "udp://0.0.0.0:11010", scheme: "udp", host: "0.0.0.0", port: 11010}
	targets := c.expandAddrs(ipListResponse(), entry, 2)
	if len(targets) != 2 {
		t.Fatalf("targets = %v", targets)
	}
	seen := map[string]bool{}
	for _, target := range targets {
		seen[target] = true
	}
	if !seen["udp://192.0.2.10:11010"] || !seen["udp://203.0.113.5:11010"] {
		t.Fatalf("expanded targets = %v", targets)
	}
}

func TestExpandAddrsSkipsSelfListener(t *testing.T) {
	c := NewConnector(ConnectorConfig{
		DefaultProtocol: "tcp",
		IsSelfListener: func(ip netip.Addr, port uint16, udp bool) bool {
			return ip == netip.MustParseAddr("203.0.113.5") && port == 11010
		},
	})
	entry := listenerEntry{url: "udp://0.0.0.0:11010", scheme: "udp", host: "0.0.0.0", port: 11010}
	targets := c.expandAddrs(ipListResponse(), entry, 2)
	if len(targets) != 1 || targets[0] != "udp://192.0.2.10:11010" {
		t.Fatalf("targets = %v", targets)
	}
}

func TestReplaceHost(t *testing.T) {
	if got := replaceHost("udp://0.0.0.0:11010", "203.0.113.5"); got != "udp://203.0.113.5:11010" {
		t.Fatalf("v4 replace = %s", got)
	}
	if got := replaceHost("tcp://[::]:11011", "2001:db8::1"); got != "tcp://[2001:db8::1]:11011" {
		t.Fatalf("v6 replace = %s", got)
	}
}

func TestIPListServiceGetIPList(t *testing.T) {
	called := false
	service := NewIPListService(&stun.MockSource{Info: &common.StunInfo{PublicIp: []string{"203.0.113.5"}}}, func() []string {
		called = true
		return []string{"tcp://0.0.0.0:11011"}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	body, err := service.HandleMethod(MethodGetIpList, ctx, 2, nil)
	if err != nil {
		t.Fatalf("get ip list: %v", err)
	}
	var response peer_rpc.GetIpListResponse
	if err := protojsonUnmarshal(body, &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(response.InterfaceIpv4S) == 0 {
		t.Fatal("interface ipv4 list is empty")
	}
	if response.PublicIpv4 == nil {
		t.Fatal("public ipv4 missing")
	}
	if !called || len(response.Listeners) != 1 {
		t.Fatalf("listeners = %v (called=%v)", response.Listeners, called)
	}
}

// TestSendUdpHolePunchControl verifies the loopback control injection: the
// request causes the local listener socket to emit a punch burst toward the
// connector address.
func TestSendUdpHolePunchControl(t *testing.T) {
	service := NewIPListService(&stun.MockSource{}, nil)

	listener, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = listener.Serve(ctx) }()
	listenerPort := uint32(listener.Address().(*net.UDPAddr).Port)

	bystander, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind bystander: %v", err)
	}
	defer bystander.Close()
	bystanderAddr := bystander.LocalAddr().(*net.UDPAddr)
	var bystanderIP [4]byte
	copy(bystanderIP[:], bystanderAddr.IP.To4())

	connectorAddrProto, err := addrPortToProto(netip.AddrPortFrom(netip.AddrFrom4(bystanderIP), uint16(bystanderAddr.Port)))
	if err != nil {
		t.Fatalf("encode connector addr: %v", err)
	}

	request, err := protojsonMarshal(&peer_rpc.SendUdpHolePunchPacketRequest{
		ConnectorAddr: connectorAddrProto,
		ListenerPort:  listenerPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.HandleMethod(MethodSendUdpHolePunchPacket, ctx, 2, request); err != nil {
		t.Fatalf("handle punch assist: %v", err)
	}

	buffer := make([]byte, 128)
	_ = bystander.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := bystander.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read punch burst: %v", err)
	}
	datagram, err := protocol.ParseUDPDatagram(buffer[:n])
	if err != nil {
		t.Fatalf("parse punch burst: %v", err)
	}
	if datagram.Header.MessageType != protocol.UDPPacketTypeHolePunch {
		t.Fatalf("message type = %d", datagram.Header.MessageType)
	}
}

// fakeChannel is a peer.PacketChannel used by manual manager tests.
type fakeChannel struct {
	closed chan struct{}
}

func newFakeChannel() *fakeChannel { return &fakeChannel{closed: make(chan struct{})} }

func (c *fakeChannel) Send(ctx context.Context, packet protocol.Packet) error {
	<-c.closed
	return errors.New("closed")
}

func (c *fakeChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	<-c.closed
	return protocol.Packet{}, errors.New("closed")
}

func (c *fakeChannel) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func TestManualManagerLifecycle(t *testing.T) {
	dialDelay := 20 * time.Millisecond
	failDial := false
	channeled := newFakeChannel()

	manager := NewManualManager(ManualConfig{
		Dial: func(ctx context.Context, rawURL string) (peer.PacketChannel, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(dialDelay):
			}
			if failDial {
				return nil, errors.New("dial failed")
			}
			return channeled, nil
		},
		Handoff: func(ctx context.Context, channel peer.PacketChannel) error {
			return nil
		},
		ReconnectInterval: 20 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)

	if err := manager.AddConnector("tcp://127.0.0.1:11010"); err != nil {
		t.Fatalf("add connector: %v", err)
	}
	if err := manager.AddConnector("tcp://127.0.0.1:11010"); err != nil {
		t.Fatalf("duplicate add should succeed: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		list := manager.ListConnectors()
		if len(list) == 1 && list[0].Status == StatusConnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connector never connected: %v", list)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Kill the connection; the manager must reconnect.
	_ = channeled.Close()
	deadline = time.Now().Add(3 * time.Second)
	for {
		list := manager.ListConnectors()
		if len(list) == 1 && list[0].Status == StatusConnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connector never reconnected: %v", list)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Removing the connector leaves the list empty.
	if err := manager.RemoveConnector("tcp://127.0.0.1:11010"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := manager.RemoveConnector("tcp://127.0.0.1:9999"); err == nil {
		t.Fatal("removing unknown connector should fail")
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		if len(manager.ListConnectors()) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("connector list never emptied")
		}
		time.Sleep(10 * time.Millisecond)
	}
	manager.Stop()
}

func TestNormalizeConnectorURL(t *testing.T) {
	normalized, err := normalizeConnectorURL("127.0.0.1:11010")
	if err != nil || normalized != "tcp://127.0.0.1:11010" {
		t.Fatalf("normalized = %q err = %v", normalized, err)
	}
	if _, err := normalizeConnectorURL(""); err == nil {
		t.Fatal("empty URL should fail")
	}
}

func protojsonUnmarshal(body []byte, message proto.Message) error {
	return protojson.UnmarshalOptions{}.Unmarshal(body, message)
}

func protojsonMarshal(message proto.Message) ([]byte, error) {
	return protojson.Marshal(message)
}

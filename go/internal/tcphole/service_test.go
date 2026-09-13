// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package tcphole

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/stun"
	"google.golang.org/protobuf/encoding/protojson"
)

// loopbackTransport connects two peer RPC managers in memory.
type loopbackTransport struct {
	peerID uint32
	peer   *rpc.PeerRpcManager
}

func (t *loopbackTransport) MyPeerID() uint32 { return t.peerID }

func (t *loopbackTransport) Send(ctx context.Context, dstPeerID uint32, packet protocol.Packet) error {
	return t.peer.HandlePacket(ctx, packet)
}

func newRPCPair(t *testing.T, aID, bID uint32) (a, b *rpc.PeerRpcManager) {
	t.Helper()
	transportA := &loopbackTransport{peerID: aID}
	transportB := &loopbackTransport{peerID: bID}
	a = newRPCEndpoint(t, transportA)
	b = newRPCEndpoint(t, transportB)
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

// TestTCPHolePunchEndToEnd punches a TCP connection between two in-process
// nodes: the initiator exchanges mapped addresses via RPC, simultaneous
// connect fails against the unbound predicted port, and the initiator's
// fallback listener accepts the responder's dial.
func TestTCPHolePunchEndToEnd(t *testing.T) {
	const domain = "tcp-punch-net"
	rpcA, rpcB := newRPCPair(t, 1, 2)

	serverConns := make(chan net.Conn, 1)
	initiatorConns := make(chan net.Conn, 1)

	service := NewService(punchStun(), Handoff{
		OnClientConn: func(ctx context.Context, conn net.Conn) error {
			serverConns <- conn
			return nil
		},
	})
	if err := rpcB.Register(domain, service); err != nil {
		t.Fatalf("register service: %v", err)
	}

	initiator := NewInitiator(rpcA, domain, punchStun(), Handoff{
		OnServerConn: func(ctx context.Context, conn net.Conn) error {
			initiatorConns <- conn
			return nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go initiator.PunchPeer(ctx, 2)

	select {
	case conn := <-initiatorConns:
		defer conn.Close()
		_, _ = conn.Write([]byte("punched-tcp"))
	case <-time.After(10 * time.Second):
		t.Fatal("initiator never accepted the punched connection")
	}

	select {
	case conn := <-serverConns:
		defer conn.Close()
		buffer := make([]byte, 16)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil && err != io.EOF {
			t.Fatalf("server read: %v", err)
		}
		if string(buffer[:n]) != "punched-tcp" {
			t.Fatalf("payload = %q", buffer[:n])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("responder never obtained its connection")
	}
}

// unknownNatSource reports unknown NAT types.
type unknownNatSource struct{}

func (unknownNatSource) GetStunInfo() *common.StunInfo {
	return &common.StunInfo{}
}

func (unknownNatSource) GetUDPPortMapping(ctx context.Context, localPort uint16) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("not available")
}

func (unknownNatSource) GetUDPPortMappingWithSocket(ctx context.Context, socket *net.UDPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("not available")
}

func (unknownNatSource) GetTCPPortMapping(ctx context.Context, localPort uint16) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("not available")
}

func TestExchangeMappedAddrRejectsUnknownNAT(t *testing.T) {
	service := NewService(unknownNatSource{}, Handoff{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	body, err := protojson.Marshal(&peer_rpc.TcpHolePunchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// An unknown TCP NAT must be rejected before touching sockets.
	if _, err := service.HandleMethod(MethodExchangeMappedAddr, ctx, 1, body); err == nil {
		t.Fatal("unknown tcp nat should be rejected")
	}
}

// punchStun reports known NAT types with loopback mappings.
func punchStun() *stun.MockSource {
	return &stun.MockSource{Info: &common.StunInfo{
		UdpNatType: common.NatType_PortRestricted,
		TcpNatType: common.NatType_PortRestricted,
	}}
}

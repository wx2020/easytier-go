// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package directconn

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
)

// captureTransport records the RPC packets a client emits, so the wire
// identity of a call (domain, service name, proto name, method index) can be
// asserted. The reference registry keys services by
// (domain, service name, proto name) and numbers methods from one, so both
// must match exactly or a reference peer never finds the service.
type captureTransport struct {
	packets []protocol.Packet
}

func (c *captureTransport) MyPeerID() uint32 { return 1 }

func (c *captureTransport) Send(_ context.Context, _ uint32, packet protocol.Packet) error {
	c.packets = append(c.packets, packet)
	return nil
}

// descriptor decodes the descriptor of the first captured request.
func (c *captureTransport) descriptor(t *testing.T) *rpc.RpcDescriptor {
	t.Helper()
	if len(c.packets) == 0 {
		t.Fatal("no rpc packet was sent")
	}
	packet, err := rpc.UnmarshalRpcPacket(c.packets[0].Payload)
	if err != nil {
		t.Fatalf("decode rpc packet: %v", err)
	}
	if packet.Descriptor == nil {
		t.Fatal("rpc packet has no descriptor")
	}
	return packet.Descriptor
}

// TestDirectConnectorRpcWireIdentity pins the RPC identity of the
// DirectConnectorRpc calls against the reference service definition:
//
//	service DirectConnectorRpc {
//	  rpc GetIpList(...) ...;              // index 1
//	  rpc SendUdpHolePunchPacket(...) ...;  // index 2
//	}
func TestDirectConnectorRpcWireIdentity(t *testing.T) {
	if MethodGetIpList != 1 {
		t.Fatalf("MethodGetIpList = %d, want 1 (reference numbers methods from one)", MethodGetIpList)
	}
	if MethodSendUdpHolePunchPacket != 2 {
		t.Fatalf("MethodSendUdpHolePunchPacket = %d, want 2", MethodSendUdpHolePunchPacket)
	}
	if ServiceName != "DirectConnectorRpc" {
		t.Fatalf("ServiceName = %q", ServiceName)
	}

	transport := &captureTransport{}
	manager, err := rpc.NewPeerRpcManager(transport)
	if err != nil {
		t.Fatalf("rpc manager: %v", err)
	}
	connector := &Connector{cfg: ConnectorConfig{RPC: manager, Domain: "wx2020"}}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// The call cannot complete without a peer, but the request identity is
	// already on the wire.
	_, _ = connector.getIPList(ctx, 42)

	descriptor := transport.descriptor(t)
	if descriptor.DomainName != "wx2020" {
		t.Fatalf("domain = %q, want wx2020", descriptor.DomainName)
	}
	if descriptor.ServiceName != "DirectConnectorRpc" {
		t.Fatalf("service name = %q", descriptor.ServiceName)
	}
	if descriptor.ProtoName != "DirectConnectorRpc" {
		t.Fatalf("proto name = %q, want DirectConnectorRpc (the reference registry keys on it)", descriptor.ProtoName)
	}
	if descriptor.MethodIndex != MethodGetIpList {
		t.Fatalf("method index = %d, want %d", descriptor.MethodIndex, MethodGetIpList)
	}
}

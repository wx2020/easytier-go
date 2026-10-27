// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"context"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// descriptorCapture records the descriptors of outgoing RPC requests.
type descriptorCapture struct {
	descriptors []*RpcDescriptor
}

func (c *descriptorCapture) MyPeerID() uint32 { return 1 }

func (c *descriptorCapture) Send(_ context.Context, _ uint32, packet protocol.Packet) error {
	decoded, err := UnmarshalRpcPacket(packet.Payload)
	if err != nil {
		return err
	}
	c.descriptors = append(c.descriptors, decoded.Descriptor)
	return nil
}

// TestCallServiceUsesServiceNameAsProtoName documents why CallService exists:
// the reference registry keys services by (domain, service name, proto name),
// and for the peer_rpc family the proto name equals the service name.
func TestCallServiceUsesServiceNameAsProtoName(t *testing.T) {
	transport := &descriptorCapture{}
	manager, err := NewPeerRpcManager(transport)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = manager.CallService(ctx, 2, "wx2020", "UdpHolePunchRpc", 1, []byte("{}"))
	if len(transport.descriptors) != 1 {
		t.Fatalf("captured %d descriptors", len(transport.descriptors))
	}
	descriptor := transport.descriptors[0]
	if descriptor.ProtoName != "UdpHolePunchRpc" {
		t.Fatalf("proto name = %q", descriptor.ProtoName)
	}
	if descriptor.ServiceName != "UdpHolePunchRpc" {
		t.Fatalf("service name = %q", descriptor.ServiceName)
	}
	if descriptor.DomainName != "wx2020" {
		t.Fatalf("domain = %q", descriptor.DomainName)
	}
	if descriptor.MethodIndex != 1 {
		t.Fatalf("method index = %d", descriptor.MethodIndex)
	}
}

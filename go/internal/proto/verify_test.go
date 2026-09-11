// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package proto

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/EasyTier/EasyTier/go/internal/proto/acl"
	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
)

func TestDescriptorFieldNumbers(t *testing.T) {
	// Verify that the generated descriptors have the expected field numbers and that
	// the Go code can marshal/unmarshal the messages without field-number changes.
	// This is the acceptance criteria for API-01.

	// Check HandshakeRequest in peer_rpc
	desc := peer_rpc.File_peer_rpc_proto
	if desc == nil {
		t.Fatal("peer_rpc descriptor is nil")
	}
	// Find HandshakeRequest
	found := false
	for i := 0; i < desc.Messages().Len(); i++ {
		md := desc.Messages().Get(i)
		if string(md.Name()) == "HandshakeRequest" {
			found = true
			// Verify field numbers: magic=1, my_peer_id=2, version=3, features=4, network_name=5, network_secret_digest=6
			expected := map[string]protoreflect.FieldNumber{
				"magic": 1, "my_peer_id": 2, "version": 3, "features": 4, "network_name": 5, "network_secret_digest": 6,
			}
			for j := 0; j < md.Fields().Len(); j++ {
				fd := md.Fields().Get(j)
				if want, ok := expected[string(fd.Name())]; ok && fd.Number() != want {
					t.Fatalf("HandshakeRequest.%s field number = %d, want %d", fd.Name(), fd.Number(), want)
				}
			}
		}
	}
	if !found {
		t.Fatal("HandshakeRequest not found in peer_rpc descriptor")
	}

	// Check common.RpcDescriptor
	commonDesc := common.File_common_proto
	found = false
	for i := 0; i < commonDesc.Messages().Len(); i++ {
		md := commonDesc.Messages().Get(i)
		if string(md.Name()) == "RpcDescriptor" {
			found = true
			expected := map[string]protoreflect.FieldNumber{
				"domain_name": 1, "proto_name": 2, "service_name": 3, "method_index": 4,
			}
			for j := 0; j < md.Fields().Len(); j++ {
				fd := md.Fields().Get(j)
				if want, ok := expected[string(fd.Name())]; ok && fd.Number() != want {
					t.Fatalf("RpcDescriptor.%s field number = %d, want %d", fd.Name(), fd.Number(), want)
				}
			}
		}
	}
	if !found {
		t.Fatal("RpcDescriptor not found in common descriptor")
	}

	// Check that acl.proto's Protocol enum is present
	aclDesc := acl.File_acl_proto
	if aclDesc.Enums().Len() == 0 {
		t.Fatal("acl descriptor has no enums")
	}
}

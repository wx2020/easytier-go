// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func compatPath(t *testing.T, rel string) string {
	t.Helper()
	for _, p := range []string{
		filepath.Join("..", "..", "testdata", "compat", rel),
		filepath.Join("testdata", "compat", rel),
		filepath.Join("go", "testdata", "compat", rel),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatalf("fixture %q not found", rel)
	return ""
}

func TestGoldenRpcDescriptors(t *testing.T) {
	path := compatPath(t, "rpc/descriptors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rpc descriptors: %v", err)
	}
	var fixtures []struct {
		Name        string `json:"name"`
		DomainName  string `json:"domain_name"`
		ProtoName   string `json:"proto_name"`
		ServiceName string `json:"service_name"`
		MethodIndex uint32 `json:"method_index"`
		WireHex     string `json:"wire_hex"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("unmarshal rpc descriptors: %v", err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(f.WireHex)
			if err != nil {
				t.Fatalf("decode wire hex: %v", err)
			}
			got, err := UnmarshalRpcDescriptor(wire)
			if err != nil {
				t.Fatalf("UnmarshalRpcDescriptor failed: %v", err)
			}
			if got.DomainName != f.DomainName || got.ProtoName != f.ProtoName || got.ServiceName != f.ServiceName || got.MethodIndex != f.MethodIndex {
				t.Fatalf("field mismatch: got %+v want %+v", got, f)
			}
			encoded, err := got.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if hex.EncodeToString(encoded) != f.WireHex {
				t.Fatalf("marshal mismatch: got %s want %s", hex.EncodeToString(encoded), f.WireHex)
			}
		})
	}
}

func TestGoldenRpcPackets(t *testing.T) {
	path := compatPath(t, "rpc/fixtures.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rpc fixtures: %v", err)
	}
	var fixtures []struct {
		Name          string `json:"name"`
		FromPeer      uint32 `json:"from_peer"`
		ToPeer        uint32 `json:"to_peer"`
		TransactionID int64  `json:"transaction_id"`
		Descriptor    *struct {
			DomainName  string `json:"domain_name"`
			ProtoName   string `json:"proto_name"`
			ServiceName string `json:"service_name"`
			MethodIndex uint32 `json:"method_index"`
			WireHex     string `json:"wire_hex"`
		} `json:"descriptor"`
		BodyHex     string `json:"body_hex"`
		IsRequest   bool   `json:"is_request"`
		TotalPieces uint32 `json:"total_pieces"`
		PieceIdx    uint32 `json:"piece_idx"`
		TraceID     int32  `json:"trace_id"`
		WireHex     string `json:"wire_hex"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("unmarshal rpc fixtures: %v", err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(f.WireHex)
			if err != nil {
				t.Fatalf("decode wire hex: %v", err)
			}
			got, err := UnmarshalRpcPacket(wire)
			if err != nil {
				t.Fatalf("UnmarshalRpcPacket failed: %v", err)
			}
			if got.FromPeer != f.FromPeer || got.ToPeer != f.ToPeer || got.TransactionID != f.TransactionID || got.IsRequest != f.IsRequest || got.TotalPieces != f.TotalPieces || got.PieceIdx != f.PieceIdx || got.TraceID != f.TraceID {
				t.Fatalf("field mismatch: got %+v want %+v", got, f)
			}
			bodyWant, _ := hex.DecodeString(f.BodyHex)
			if !reflect.DeepEqual(got.Body, bodyWant) {
				t.Fatalf("body mismatch: got %x want %x", got.Body, bodyWant)
			}
			if f.Descriptor != nil {
				if got.Descriptor == nil {
					t.Fatalf("descriptor missing")
				}
				if got.Descriptor.DomainName != f.Descriptor.DomainName || got.Descriptor.ProtoName != f.Descriptor.ProtoName || got.Descriptor.ServiceName != f.Descriptor.ServiceName || got.Descriptor.MethodIndex != f.Descriptor.MethodIndex {
					t.Fatalf("descriptor mismatch: got %+v want %+v", *got.Descriptor, *f.Descriptor)
				}
			} else if got.Descriptor != nil {
				t.Fatalf("unexpected descriptor: %+v", *got.Descriptor)
			}
			encoded, err := got.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if hex.EncodeToString(encoded) != f.WireHex {
				t.Fatalf("marshal mismatch: got %s want %s", hex.EncodeToString(encoded), f.WireHex)
			}
		})
	}
}

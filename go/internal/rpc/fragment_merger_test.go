// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"strings"
	"testing"
	"time"
)

func TestFragmentMergerExpiresIncompleteTransactions(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewFragmentMerger()
	m.now = func() time.Time { return now }
	descriptor := &RpcDescriptor{ServiceName: "svc"}
	first := RpcPacket{FromPeer: 1, TransactionID: 1, Descriptor: descriptor, Body: []byte("a"), TotalPieces: 2}
	second := RpcPacket{FromPeer: 1, TransactionID: 1, Body: []byte("b"), TotalPieces: 2, PieceIdx: 1}

	if got, err := m.Add(second); err != nil || got != nil {
		t.Fatalf("initial fragment = %#v, %v", got, err)
	}
	now = now.Add(fragmentSetExpiry)
	if got, err := m.Add(first); err != nil || got != nil {
		t.Fatalf("fragment after expiry = %#v, %v", got, err)
	}
	got, err := m.Add(second)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || string(got.Body) != "ab" {
		t.Fatalf("merged packet after expiry = %#v", got)
	}
}

func TestFragmentMergerRejectsConflictingDuplicate(t *testing.T) {
	m := NewFragmentMerger()
	descriptor := &RpcDescriptor{ServiceName: "svc"}
	first := RpcPacket{FromPeer: 1, TransactionID: 2, Descriptor: descriptor, Body: []byte("a"), TotalPieces: 3}
	second := RpcPacket{FromPeer: 1, TransactionID: 2, Body: []byte("b"), TotalPieces: 3, PieceIdx: 1}
	third := RpcPacket{FromPeer: 1, TransactionID: 2, Body: []byte("c"), TotalPieces: 3, PieceIdx: 2}

	for _, packet := range []RpcPacket{first, second} {
		if _, err := m.Add(packet); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Add(second); err != nil {
		t.Fatalf("identical duplicate rejected: %v", err)
	}
	conflicting := second
	conflicting.Body = []byte("different")
	if _, err := m.Add(conflicting); err == nil || !strings.Contains(err.Error(), "conflicting duplicate") {
		t.Fatalf("conflicting duplicate error = %v", err)
	}
	got, err := m.Add(third)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || string(got.Body) != "abc" {
		t.Fatalf("merged packet after duplicate = %#v", got)
	}
}

func TestFragmentMergerBoundsPendingTransactions(t *testing.T) {
	m := NewFragmentMerger()
	for i := 0; i < maxPendingTransactions; i++ {
		packet := RpcPacket{
			FromPeer:      1,
			TransactionID: int64(i),
			Descriptor:    &RpcDescriptor{ServiceName: "svc"},
			TotalPieces:   2,
		}
		if _, err := m.Add(packet); err != nil {
			t.Fatalf("transaction %d: %v", i, err)
		}
	}
	packet := RpcPacket{
		FromPeer:      1,
		TransactionID: maxPendingTransactions,
		Descriptor:    &RpcDescriptor{ServiceName: "svc"},
		TotalPieces:   2,
	}
	if _, err := m.Add(packet); err == nil || !strings.Contains(err.Error(), "too many pending") {
		t.Fatalf("pending transaction limit error = %v", err)
	}
}

func TestFragmentMergerBoundsAggregateBodySize(t *testing.T) {
	m := NewFragmentMerger()
	first := RpcPacket{
		FromPeer:      1,
		TransactionID: 3,
		Descriptor:    &RpcDescriptor{ServiceName: "svc"},
		Body:          make([]byte, maxAggregateBodySize-1),
		TotalPieces:   2,
	}
	if _, err := m.Add(first); err != nil {
		t.Fatal(err)
	}
	second := RpcPacket{FromPeer: 1, TransactionID: 3, Body: []byte("ab"), TotalPieces: 2, PieceIdx: 1}
	if _, err := m.Add(second); err == nil || !strings.Contains(err.Error(), "body is too large") {
		t.Fatalf("aggregate body limit error = %v", err)
	}
}

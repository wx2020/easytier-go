// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"fmt"
	"reflect"
	"time"
)

const (
	fragmentSetExpiry      = 10 * time.Second
	maxPendingTransactions = 128
	maxAggregateBodySize   = 32 * 1024 * 1024
)

type fragmentKey struct {
	fromPeer      uint32
	transactionID int64
}

type fragmentSet struct {
	totalPieces uint32
	pieces      map[uint32]RpcPacket
	received    uint32
	bodySize    int
	lastUpdated time.Time
}

// FragmentMerger reassembles interleaved RPC packet fragments. Fragments are
// isolated by both their sender and transaction ID.
type FragmentMerger struct {
	sets map[fragmentKey]*fragmentSet
	now  func() time.Time
}

// NewFragmentMerger creates an empty fragment merger.
func NewFragmentMerger() *FragmentMerger {
	return &FragmentMerger{sets: make(map[fragmentKey]*fragmentSet)}
}

func (m *FragmentMerger) currentTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *FragmentMerger) expire(now time.Time) {
	for key, set := range m.sets {
		if !now.Before(set.lastUpdated.Add(fragmentSetExpiry)) {
			delete(m.sets, key)
		}
	}
}

// Add adds one packet. It returns a complete logical packet after every piece
// for its sender and transaction has arrived.
func (m *FragmentMerger) Add(packet RpcPacket) (*RpcPacket, error) {
	if m == nil {
		return nil, fmt.Errorf("nil fragment merger")
	}
	if m.sets == nil {
		m.sets = make(map[fragmentKey]*fragmentSet)
	}
	now := m.currentTime()
	m.expire(now)
	if err := packet.Validate(); err != nil {
		return nil, err
	}
	if packet.TotalPieces == 0 && packet.PieceIdx == 0 {
		return &packet, nil
	}
	if packet.TotalPieces == 0 || packet.TotalPieces > maxPieces {
		return nil, fmt.Errorf("rpc packet total_pieces is invalid: %d", packet.TotalPieces)
	}
	if packet.PieceIdx >= packet.TotalPieces {
		return nil, fmt.Errorf("rpc packet piece_idx %d is outside %d pieces", packet.PieceIdx, packet.TotalPieces)
	}
	if packet.PieceIdx == 0 && packet.Descriptor == nil {
		return nil, fmt.Errorf("initial rpc packet is missing a descriptor")
	}
	if len(packet.Body) > maxAggregateBodySize {
		return nil, fmt.Errorf("rpc fragment body is too large: %d", len(packet.Body))
	}

	key := fragmentKey{fromPeer: packet.FromPeer, transactionID: packet.TransactionID}
	set := m.sets[key]
	if set == nil {
		if len(m.sets) >= maxPendingTransactions {
			return nil, fmt.Errorf("too many pending rpc transactions")
		}
		set = &fragmentSet{
			totalPieces: packet.TotalPieces,
			pieces:      make(map[uint32]RpcPacket),
			lastUpdated: now,
		}
		m.sets[key] = set
	} else if set.totalPieces != packet.TotalPieces {
		return nil, fmt.Errorf("rpc packet total_pieces changed within a transaction")
	}

	if existing, ok := set.pieces[packet.PieceIdx]; ok {
		if !reflect.DeepEqual(existing, packet) {
			return nil, fmt.Errorf("conflicting duplicate rpc fragment at piece %d", packet.PieceIdx)
		}
		set.lastUpdated = now
	} else {
		if len(packet.Body) > maxAggregateBodySize-set.bodySize {
			return nil, fmt.Errorf("merged rpc body is too large")
		}
		set.pieces[packet.PieceIdx] = packet
		set.received++
		set.bodySize += len(packet.Body)
		set.lastUpdated = now
	}
	if set.received != set.totalPieces {
		return nil, nil
	}

	first := set.pieces[0]
	if first.Descriptor == nil {
		return nil, fmt.Errorf("initial rpc packet is missing a descriptor")
	}
	body := make([]byte, 0, set.bodySize)
	for i := uint32(0); i < set.totalPieces; i++ {
		body = append(body, set.pieces[i].Body...)
	}
	first.Body = body
	first.TotalPieces = 1
	first.PieceIdx = 0
	delete(m.sets, key)
	return &first, nil
}

// Feed is an alias for Add.
func (m *FragmentMerger) Feed(packet RpcPacket) (*RpcPacket, error) { return m.Add(packet) }

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package gateway provides TCP conversion proxies over KCP/QUIC with loss simulation.
package gateway

import (
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// TransportType identifies the proxy transport.
type TransportType string

const (
	TransportTCP  TransportType = "TCP"
	TransportKCP  TransportType = "KCP"
	TransportQUIC TransportType = "QUIC"
)

// ProxyState describes the lifecycle of a proxied TCP connection.
type ProxyState string

const (
	StateSynReceived ProxyState = "SynReceived"
	StateConnecting  ProxyState = "ConnectingDst"
	StateConnected   ProxyState = "Connected"
	StateClosingSrc  ProxyState = "ClosingSrc"
	StateClosingDst  ProxyState = "ClosingDst"
	StateClosed      ProxyState = "Closed"
)

// ProxyEntry mirrors Rust TcpProxyEntry for status/RPC reporting.
type ProxyEntry struct {
	Src           string        `json:"src"`
	Dst           string        `json:"dst"`
	StartTime     int64         `json:"start_time"`
	State         ProxyState    `json:"state"`
	TransportType TransportType `json:"transport_type"`
}

// packet is the internal reliable datagram for loss simulation.
type packet struct {
	seq  uint32
	data []byte
}

// ReliableChannel provides ordered reliable delivery over a lossy in-memory link.
// It uses stop-and-wait ARQ with retransmission to survive simulated packet loss.
// Each channel is unidirectional; a bidirectional connection uses two channels.
type ReliableChannel struct {
	lossRate float64
	randSrc  *rand.Rand
	mu       sync.Mutex

	sendCh     chan packet
	ackCh      chan uint32
	deliveryCh chan []byte

	nextSeq     uint32
	expectedSeq uint32

	done   chan struct{}
	once   sync.Once
	closed atomic.Bool
}

// NewReliableChannel creates a reliable channel that drops packets with probability lossRate.
// lossRate must be in [0,1). Seed controls determinism for tests.
func NewReliableChannel(lossRate float64, seed int64) *ReliableChannel {
	if lossRate < 0 {
		lossRate = 0
	}
	if lossRate >= 1 {
		lossRate = 0.99
	}
	ch := &ReliableChannel{
		lossRate:    lossRate,
		randSrc:     rand.New(rand.NewSource(seed)), //nolint:gosec
		sendCh:      make(chan packet, 256),
		ackCh:       make(chan uint32, 256),
		deliveryCh:  make(chan []byte, 256),
		done:        make(chan struct{}),
		expectedSeq: 0,
	}
	go ch.receiverLoop()
	return ch
}

// Close releases resources.
func (c *ReliableChannel) Close() {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.done)
	})
}

// shouldDrop reports whether a transmission should be dropped.
func (c *ReliableChannel) shouldDrop() bool {
	if c.lossRate == 0 {
		return false
	}
	c.mu.Lock()
	v := c.randSrc.Float64()
	c.mu.Unlock()
	return v < c.lossRate
}

// receiverLoop delivers packets in order and generates ACKs (which may also be dropped).
func (c *ReliableChannel) receiverLoop() {
	for {
		select {
		case <-c.done:
			return
		case pkt := <-c.sendCh:
			// Ordered delivery: only accept next expected seq; duplicates are ACKed but not delivered twice.
			if c.expectedSeq == 0 && pkt.seq == 1 {
				c.expectedSeq = 1
				select {
				case c.deliveryCh <- append([]byte(nil), pkt.data...):
				case <-c.done:
					return
				}
			} else if pkt.seq == c.expectedSeq+1 {
				c.expectedSeq = pkt.seq
				select {
				case c.deliveryCh <- append([]byte(nil), pkt.data...):
				case <-c.done:
					return
				}
			} else if pkt.seq <= c.expectedSeq {
				// duplicate: already delivered, just ack again
			} else {
				// out-of-order gap - with stop-and-wait this should not happen; drop and let sender retry
				continue
			}
			// Send ACK, possibly dropped.
			if c.shouldDrop() {
				continue
			}
			select {
			case c.ackCh <- pkt.seq:
			case <-c.done:
				return
			}
		}
	}
}

// Send transmits data reliably, retrying on simulated loss. It blocks until ACK or failure.
func (c *ReliableChannel) Send(data []byte) error {
	if c.closed.Load() {
		return errors.New("reliable channel is closed")
	}
	if len(data) == 0 {
		return nil
	}
	seq := atomic.AddUint32(&c.nextSeq, 1)
	pkt := packet{seq: seq, data: append([]byte(nil), data...)}
	const maxAttempts = 20
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if c.closed.Load() {
			return errors.New("reliable channel is closed")
		}
		if !c.shouldDrop() {
			select {
			case c.sendCh <- pkt:
			case <-c.done:
				return errors.New("reliable channel is closed")
			}
		}
		// Wait for ACK with timeout.
		timer := time.NewTimer(40 * time.Millisecond)
		select {
		case ack := <-c.ackCh:
			timer.Stop()
			if ack == seq {
				return nil
			}
			// Spurious ACK for different seq (should not happen with single outstanding); retry waiting
			attempt--
		case <-timer.C:
			// timeout -> retry
		case <-c.done:
			timer.Stop()
			return errors.New("reliable channel is closed")
		}
	}
	return errors.New("reliable channel: max retries exceeded")
}

// Receive returns the next reliably delivered payload.
func (c *ReliableChannel) Receive() ([]byte, error) {
	select {
	case data := <-c.deliveryCh:
		return data, nil
	case <-c.done:
		return nil, errors.New("reliable channel is closed")
	}
}

// TryReceive returns data if immediately available.
func (c *ReliableChannel) TryReceive() ([]byte, bool) {
	select {
	case data := <-c.deliveryCh:
		return data, true
	default:
		return nil, false
	}
}

// LossyOptions configures simulated network conditions for proxies.
type LossyOptions struct {
	LossRate float64 // packet loss probability in [0,1)
	Seed     int64   // RNG seed for determinism
}

// DefaultLossyOptions returns conservative loss for tests.
func DefaultLossyOptions() LossyOptions { return LossyOptions{LossRate: 0, Seed: 1} }

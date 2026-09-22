// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

var (
	ErrStreamClosed = errors.New("quic: stream closed")
)

// streamChunk holds buffered data for a stream at a specific offset.
type streamChunk struct {
	offset uint64
	data   []byte
}

// recvStreamBuffer stores inbound stream data and reassembles it sequentially.
type recvStreamBuffer struct {
	mu         sync.Mutex
	readOffset uint64
	chunks     []streamChunk
	finOffset  uint64
	hasFin     bool
	closed     bool
	notifyCh   chan struct{}
}

func newRecvStreamBuffer() *recvStreamBuffer {
	return &recvStreamBuffer{
		notifyCh: make(chan struct{}, 1),
	}
}

// Push adds an incoming chunk at offset.
func (b *recvStreamBuffer) Push(offset uint64, data []byte, fin bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	if fin {
		b.hasFin = true
		b.finOffset = offset + uint64(len(data))
	}

	// Discard if completely before readOffset
	if offset+uint64(len(data)) <= b.readOffset {
		b.signal()
		return
	}

	// Trim if partially before readOffset
	if offset < b.readOffset {
		diff := b.readOffset - offset
		data = data[diff:]
		offset = b.readOffset
	}

	if len(data) > 0 {
		// Insert chunk maintaining offset sort order
		inserted := false
		for i, c := range b.chunks {
			if offset < c.offset {
				b.chunks = append(b.chunks[:i], append([]streamChunk{{offset: offset, data: data}}, b.chunks[i:]...)...)
				inserted = true
				break
			}
		}
		if !inserted {
			b.chunks = append(b.chunks, streamChunk{offset: offset, data: data})
		}
	}

	b.signal()
}

func (b *recvStreamBuffer) signal() {
	select {
	case b.notifyCh <- struct{}{}:
	default:
	}
}

// Read reads up to len(p) contiguous bytes starting at readOffset.
func (b *recvStreamBuffer) Read(p []byte) (int, error) {
	for {
		b.mu.Lock()

		// Reassemble contiguous data
		nCopied := 0
		for len(b.chunks) > 0 {
			c := &b.chunks[0]
			if c.offset > b.readOffset {
				break // hole in sequence, wait for missing packet
			}
			if c.offset+uint64(len(c.data)) <= b.readOffset {
				// already consumed
				b.chunks = b.chunks[1:]
				continue
			}

			start := int(b.readOffset - c.offset)
			avail := len(c.data) - start
			toCopy := len(p) - nCopied
			if toCopy > avail {
				toCopy = avail
			}

			copy(p[nCopied:], c.data[start:start+toCopy])
			nCopied += toCopy
			b.readOffset += uint64(toCopy)

			if start+toCopy >= len(c.data) {
				b.chunks = b.chunks[1:]
			}

			if nCopied == len(p) {
				break
			}
		}

		if nCopied > 0 {
			b.mu.Unlock()
			return nCopied, nil
		}

		if b.hasFin && b.readOffset >= b.finOffset {
			b.mu.Unlock()
			return 0, io.EOF
		}

		if b.closed {
			b.mu.Unlock()
			return 0, io.EOF
		}

		b.mu.Unlock()

		// Wait for more data
		<-b.notifyCh
	}
}

func (b *recvStreamBuffer) Close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.signal()
}

// sendStreamBuffer queues outbound stream bytes.
type sendStreamBuffer struct {
	mu         sync.Mutex
	buf        bytes.Buffer
	sendOffset uint64
}

func newSendStreamBuffer() *sendStreamBuffer {
	return &sendStreamBuffer{}
}

func (b *sendStreamBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *sendStreamBuffer) Take(maxLen int) (offset uint64, data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.buf.Len() == 0 {
		return b.sendOffset, nil
	}

	n := maxLen
	if n > b.buf.Len() {
		n = b.buf.Len()
	}

	offset = b.sendOffset
	data = append([]byte(nil), b.buf.Next(n)...)
	b.sendOffset += uint64(len(data))
	return offset, data
}

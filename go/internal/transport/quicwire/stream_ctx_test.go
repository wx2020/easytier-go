// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRecvStreamReadContextCancel guards the liveness fix for a peer that
// never sends the bytes a Receive is waiting for. Before the context-aware
// read, this blocked forever and the interop cell only ended at the 10-minute
// go test timeout.
func TestRecvStreamReadContextCancel(t *testing.T) {
	buf := newRecvStreamBuffer()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	n, err := buf.ReadContext(ctx, make([]byte, 4))
	elapsed := time.Since(start)
	if n != 0 {
		t.Fatalf("ReadContext returned %d bytes, want 0", n)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadContext error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ReadContext took %v, want cancellation near 50ms", elapsed)
	}
}

// TestRecvStreamReadContextData verifies that normal data delivery still
// works through the context-aware path.
func TestRecvStreamReadContextData(t *testing.T) {
	buf := newRecvStreamBuffer()
	buf.Push(0, []byte("hello"), false)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	out := make([]byte, 5)
	n, err := buf.ReadContext(ctx, out)
	if err != nil {
		t.Fatalf("ReadContext: %v", err)
	}
	if n != 5 || string(out) != "hello" {
		t.Fatalf("ReadContext = %d %q, want 5 %q", n, out, "hello")
	}
}

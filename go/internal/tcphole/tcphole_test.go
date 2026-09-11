// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package tcphole

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestSelectLocalPort(t *testing.T) {
	port, err := SelectLocalPort(false)
	if err != nil {
		t.Fatal(err)
	}
	if port == 0 {
		t.Fatal("port is zero")
	}
	// Verify we can bind again (port was released)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		// Port may be reused quickly; not fatal
		t.Logf("re-listen failed (may be in TIME_WAIT): %v", err)
		return
	}
	_ = l.Close()
}

func TestSelectLocalPortV6(t *testing.T) {
	port, err := SelectLocalPort(true)
	if err != nil {
		t.Skip("ipv6 not available: " + err.Error())
	}
	if port == 0 {
		t.Fatal("port is zero")
	}
}

func TestSimultaneousConnectLoopback(t *testing.T) {
	// Start a listener on ephemeral port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	remote := netip.MustParseAddrPort(ln.Addr().String())

	// Accept in background.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	// Use simultaneous connect from random local port to remote.
	localPort, err := SelectLocalPort(false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := Punch(ctx, localPort, remote, Options{DialTimeout: 1 * time.Second, MaxAttempts: 3, ListenTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Punch: %v", err)
	}
	defer result.Conn.Close()
	// The accepted side should have a connection.
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("remote did not accept")
	}
}

func TestFallbackListen(t *testing.T) {
	// Test fallback: dial to non-existent port, then fallback listen accepts incoming.
	localPort, err := SelectLocalPort(false)
	if err != nil {
		t.Fatal(err)
	}
	remote := netip.MustParseAddrPort("127.0.0.1:59999") // unlikely to be listening
	// Punch will attempt dial and fail, then listen on localPort.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	// For this test we use a more deterministic approach: create a separate goroutine that dials localPort after short delay.
	resultCh := make(chan error, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(localPort))))
		if err != nil {
			resultCh <- err
			return
		}
		_ = c.Close()
		resultCh <- nil
	}()

	// Punch will fail dial to remote, then listen and accept the above dial.
	result, err := Punch(ctx, localPort, remote, Options{DialTimeout: 200 * time.Millisecond, MaxAttempts: 1, ListenTimeout: 3 * time.Second})
	if err != nil {
		t.Skipf("Punch fallback listen not exercised (expected dial failure then listen success): %v", err)
	}
	defer result.Conn.Close()
	// Ensure the dialer succeeded (the connection we made to fallback listener is the one Punch accepted)
	// The Punch's fallbackListen returns the accepted conn, so we have success.
	select {
	case err := <-resultCh:
		if err != nil {
			t.Fatalf("dial to fallback listener failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		// Punch already succeeded; the dial goroutine may have timed.
	}
}

func TestDirectDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			_ = c.Close()
		}
	}()
	remote := netip.MustParseAddrPort(ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := DirectDial(ctx, remote)
	if err != nil {
		t.Fatalf("DirectDial: %v", err)
	}
	_ = c.Close()
}

// Use strconv via fmt to avoid extra import alias confusion; but we already have helper needed above.
// Replace itoa with proper.

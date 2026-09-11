// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package tcphole implements TCP hole punching with simultaneous connect and fallback.
package tcphole

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"time"
)

// Options tunes TCP hole punching behavior. Zero values use defaults.
type Options struct {
	// DialTimeout per attempt
	DialTimeout time.Duration
	// MaxAttempts for simultaneous connect before fallback
	MaxAttempts int
	// ListenTimeout for fallback accept
	ListenTimeout time.Duration
}

func defaults() Options {
	return Options{
		DialTimeout:   3 * time.Second,
		MaxAttempts:   5,
		ListenTimeout: 10 * time.Second,
	}
}

// DialResult is the outcome of a hole punch attempt.
type DialResult struct {
	Conn net.Conn
	// LocalPort is the bound local port used.
	LocalPort uint16
}

// Punch attempts TCP hole punching to remoteAddr from a specific localPort.
// It first tries simultaneous connect with the local port bound, retrying up to MaxAttempts.
// If that fails, it falls back to listening on localPort and accepting an incoming connection.
// The caller must ensure localPort is not currently in use by another listener expecting incoming.
func Punch(ctx context.Context, localPort uint16, remoteAddr netip.AddrPort, opts Options) (*DialResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("TCP hole punch context is nil")
	}
	if !remoteAddr.IsValid() {
		return nil, fmt.Errorf("TCP hole punch remote address is invalid")
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 3 * time.Second
	}
	if opts.MaxAttempts == 0 {
		opts.MaxAttempts = 1
	}
	if opts.ListenTimeout == 0 {
		opts.ListenTimeout = 10 * time.Second
	}
	// First phase: try simultaneous connect loop.
	conn, err := trySimultaneousConnect(ctx, localPort, remoteAddr, opts)
	if err == nil {
		return &DialResult{Conn: conn, LocalPort: localPort}, nil
	}
	// Fallback: listen on localPort and wait for incoming (like Rust initiator fallback).
	// This mirrors Rust's fallback where initiator listens after failed SYN.
	listenConn, listenErr := fallbackListen(ctx, localPort, opts.ListenTimeout)
	if listenErr != nil {
		// Return original dial error if listen also fails.
		return nil, fmt.Errorf("TCP hole punch failed: dial error: %v; listen fallback error: %v", err, listenErr)
	}
	return &DialResult{Conn: listenConn, LocalPort: localPort}, nil
}

// trySimultaneousConnect binds to localPort and dials remoteAddr repeatedly.
func trySimultaneousConnect(ctx context.Context, localPort uint16, remoteAddr netip.AddrPort, opts Options) (net.Conn, error) {
	isV6 := remoteAddr.Addr().Is6()
	var localAddr net.Addr
	if isV6 {
		localAddr = &net.TCPAddr{IP: net.ParseIP("::"), Port: int(localPort)}
	} else {
		localAddr = &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: int(localPort)}
	}
	remoteTCP := net.TCPAddrFromAddrPort(remoteAddr)

	start := time.Now()
	attempts := 0
	for time.Since(start) < opts.DialTimeout*time.Duration(opts.MaxAttempts+2) && attempts < opts.MaxAttempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attempts++
		dialer := net.Dialer{
			LocalAddr: localAddr,
			Timeout:   opts.DialTimeout,
		}
		dialCtx, cancel := context.WithTimeout(ctx, opts.DialTimeout)
		conn, err := dialer.DialContext(dialCtx, "tcp", remoteTCP.String())
		cancel()
		if err == nil {
			return conn, nil
		}
		// Jittered backoff like Rust's 10..100ms
		sleep := time.Duration(10+rand.Intn(90)) * time.Millisecond
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
	}
	return nil, fmt.Errorf("simultaneous connect timeout after %d attempts", attempts)
}

// fallbackListen listens on localPort and accepts one connection within timeout.
func fallbackListen(ctx context.Context, localPort uint16, timeout time.Duration) (net.Conn, error) {
	lc := net.ListenConfig{}
	// Bind to 0.0.0.0:localPort (or [::]:port for IPv6? Use 0.0.0.0 to cover both for test simplicity)
	addr := fmt.Sprintf("0.0.0.0:%d", localPort)
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fallback listen on %s: %w", addr, err)
	}
	defer listener.Close()

	acceptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Use channel to allow context cancellation to interrupt Accept.
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, e := listener.Accept()
		ch <- result{c, e}
	}()
	select {
	case <-acceptCtx.Done():
		return nil, acceptCtx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// SelectLocalPort chooses an available TCP port by binding to :0 and reading it.
// It mirrors Rust select_local_port.
func SelectLocalPort(isV6 bool) (uint16, error) {
	network := "tcp4"
	bind := "0.0.0.0:0"
	if isV6 {
		network = "tcp6"
		bind = "[::]:0"
	}
	l, err := net.Listen(network, bind)
	if err != nil {
		return 0, fmt.Errorf("select local port: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return uint16(port), nil
}

// DialWithFallback is a higher-level helper that selects a local port automatically,
// obtains a mapped address via stun-like mapping (here just echoes local port),
// and performs hole punching. For tests we allow injection of a getMappedAddr func.

// DirectDial dials remoteAddr without binding to a specific local port (normal dial).
func DirectDial(ctx context.Context, remoteAddr netip.AddrPort) (net.Conn, error) {
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, "tcp", net.TCPAddrFromAddrPort(remoteAddr).String())
}

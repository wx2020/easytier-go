// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// KCPProxy implements a TCP-conversion proxy that tunnels TCP streams through a
// KCP-like reliable channel capable of surviving simulated packet loss.
// The wire format is intentionally simple (reliable in-memory channel) but
// preserves the external contract: config flag handling, status/RPC fields,
// and lossy-network resilience as required by GWY-06.

// ProxyFlags captures the subset of EasyTier flags that control KCP/QUIC proxies.
// This avoids importing the config package from gateway (which would create a cycle
// via config -> peer -> gateway).
type ProxyFlags struct {
	EnableKCPProxy                bool
	DisableKCPInput               bool
	DisableRelayKCP               bool
	EnableRelayForeignNetworkKCP  bool
	EnableQUICProxy               bool
	DisableQUICInput              bool
	DisableRelayQUIC              bool
	EnableRelayForeignNetworkQUIC bool
}

type KCPProxy struct {
	flags    ProxyFlags
	loss     LossyOptions
	listener net.Listener
	dstAddr  string

	mu       sync.RWMutex
	entries  map[string]*kcpEntry
	nextID   atomic.Uint64
	closed   bool
	closeCh  chan struct{}
	wg       sync.WaitGroup
}

type kcpEntry struct {
	id        uint64
	src       string
	dst       string
	startTime int64
	state     atomic.Value // ProxyState
}

// NewKCPProxy creates a proxy that respects flags.EnableKCPProxy and flags.DisableKCPInput.
// Loss config controls the simulated KCP transport loss.
func NewKCPProxy(flags ProxyFlags, loss LossyOptions) *KCPProxy {
	return &KCPProxy{
		flags:   flags,
		loss:    loss,
		entries: make(map[string]*kcpEntry),
		closeCh: make(chan struct{}),
	}
}

// IsEnabled reports whether the proxy should handle outbound KCP connections (src).
func (p *KCPProxy) IsEnabled() bool { return p.flags.EnableKCPProxy }

// IsInputEnabled reports whether inbound KCP packets should be accepted (dst).
func (p *KCPProxy) IsInputEnabled() bool { return !p.flags.DisableKCPInput }

// IsRelayEnabled reports whether relaying KCP packets is allowed.
func (p *KCPProxy) IsRelayEnabled() bool { return !p.flags.DisableRelayKCP }

// Config returns the current flag snapshot.
func (p *KCPProxy) Config() ProxyFlags { return p.flags }

// UpdateFlags atomically updates proxy flags.
func (p *KCPProxy) UpdateFlags(flags ProxyFlags) {
	p.mu.Lock()
	p.flags = flags
	p.mu.Unlock()
}

// ListenAddr returns the bound listener address.
func (p *KCPProxy) ListenAddr() net.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.listener != nil {
		return p.listener.Addr()
	}
	return nil
}

// Start starts the KCP TCP-conversion listener. listenAddr is the local TCP address
// to accept client connections (e.g., "127.0.0.1:0"), dstAddr is the ultimate TCP
// destination (echo server). If IsEnabled is false, Start is a no-op.
func (p *KCPProxy) Start(ctx context.Context, listenAddr, dstAddr string) error {
	if !p.IsEnabled() {
		return nil
	}
	if listenAddr == "" || dstAddr == "" {
		return errors.New("kcp proxy listen and dst addresses are required")
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("kcp proxy listen %q: %w", listenAddr, err)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = ln.Close()
		return errors.New("kcp proxy is closed")
	}
	p.listener = ln
	p.dstAddr = dstAddr
	p.mu.Unlock()

	p.wg.Add(1)
	go p.acceptLoop()
	return nil
}

func (p *KCPProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.closeCh:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// transient
			time.Sleep(10 * time.Millisecond)
			continue
		}
		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			p.handleConn(c)
		}(conn)
	}
}

func (p *KCPProxy) handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	src := clientConn.RemoteAddr().String()
	dst := p.dstAddr
	id := p.nextID.Add(1)
	entry := &kcpEntry{id: id, src: src, dst: dst, startTime: time.Now().Unix()}
	entry.state.Store(StateSynReceived)
	key := fmt.Sprintf("%d", id)
	p.mu.Lock()
	p.entries[key] = entry
	p.mu.Unlock()
	defer func() {
		entry.state.Store(StateClosed)
		// keep entry for a short grace period for status listing, then remove
		time.Sleep(50 * time.Millisecond)
		p.mu.Lock()
		delete(p.entries, key)
		p.mu.Unlock()
	}()

	// Transition to connecting
	entry.state.Store(StateConnecting)

	// Dial destination via TCP
	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dstConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", dst)
	if err != nil {
		entry.state.Store(StateClosed)
		return
	}
	defer dstConn.Close()
	entry.state.Store(StateConnected)

	// Bridge via lossy reliable channels to exercise KCP retransmission under loss.
	if p.loss.LossRate == 0 {
		// Fast path: direct copy
		_ = p.copyBidirectional(clientConn, dstConn, entry)
		return
	}
	_ = p.copyBidirectionalLossy(clientConn, dstConn, entry)
}

func (p *KCPProxy) copyBidirectional(a, b net.Conn, entry *kcpEntry) error {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(b, a)
		errCh <- err
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		_, err := io.Copy(a, b)
		errCh <- err
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	// wait for one direction to finish
	<-errCh
	// give the other a grace to flush
	time.Sleep(10 * time.Millisecond)
	return nil
}

func (p *KCPProxy) copyBidirectionalLossy(clientConn, dstConn net.Conn, entry *kcpEntry) error {
	// Two unidirectional reliable channels through simulated loss.
	chC2S := NewReliableChannel(p.loss.LossRate, p.loss.Seed+int64(entry.id))
	chS2C := NewReliableChannel(p.loss.LossRate, p.loss.Seed+int64(entry.id)+1000)
	defer chC2S.Close()
	defer chS2C.Close()

	var wg sync.WaitGroup
	wg.Add(4)

	// client -> chC2S
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				if sendErr := chC2S.Send(buf[:n]); sendErr != nil {
					return
				}
			}
			if err != nil {
				// Propagate EOF by closing the reliable channel after flush
				// and half-closing the destination write side so the echo server sees EOF.
				time.Sleep(20 * time.Millisecond)
				chC2S.Close()
				if cw, ok := dstConn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				return
			}
		}
	}()
	// chC2S -> dst
	go func() {
		defer wg.Done()
		for {
			data, err := chC2S.Receive()
			if err != nil {
				return
			}
			if _, werr := dstConn.Write(data); werr != nil {
				return
			}
		}
	}()
	// dst -> chS2C
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := dstConn.Read(buf)
			if n > 0 {
				if sendErr := chS2C.Send(buf[:n]); sendErr != nil {
					return
				}
			}
			if err != nil {
				time.Sleep(20 * time.Millisecond)
				chS2C.Close()
				if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				return
			}
		}
	}()
	// chS2C -> client
	go func() {
		defer wg.Done()
		for {
			data, err := chS2C.Receive()
			if err != nil {
				return
			}
			if _, werr := clientConn.Write(data); werr != nil {
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

// ListEntries returns a snapshot of active proxy entries for status/RPC.
func (p *KCPProxy) ListEntries() []ProxyEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entries := make([]ProxyEntry, 0, len(p.entries))
	for _, e := range p.entries {
		state, _ := e.state.Load().(ProxyState)
		if state == "" {
			state = StateSynReceived
		}
		entries = append(entries, ProxyEntry{
			Src:           e.src,
			Dst:           e.dst,
			StartTime:     e.startTime,
			State:         state,
			TransportType: TransportKCP,
		})
	}
	return entries
}

// EntryCount returns number of live entries.
func (p *KCPProxy) EntryCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

// Close shuts down the listener and waits for handlers.
func (p *KCPProxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.closeCh)
	ln := p.listener
	p.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	p.wg.Wait()
	return nil
}

// HandleTCPConversion is a helper for tests that proxies a single TCP connection
// through the KCP lossy channel without needing a listener. It dials dst, bridges
// srcConn and dstConn via lossy KCP, and tracks an entry.
func (p *KCPProxy) HandleTCPConversion(ctx context.Context, srcConn net.Conn, dstAddr string) error {
	if !p.IsEnabled() {
		return errors.New("kcp proxy is disabled")
	}
	if !p.IsInputEnabled() {
		return errors.New("kcp input is disabled")
	}
	// Create entry
	src := ""
	if srcConn.RemoteAddr() != nil {
		src = srcConn.RemoteAddr().String()
	}
	id := p.nextID.Add(1)
	entry := &kcpEntry{id: id, src: src, dst: dstAddr, startTime: time.Now().Unix()}
	entry.state.Store(StateConnecting)
	key := fmt.Sprintf("%d", id)
	p.mu.Lock()
	p.entries[key] = entry
	p.mu.Unlock()
	defer func() {
		entry.state.Store(StateClosed)
		time.Sleep(20 * time.Millisecond)
		p.mu.Lock()
		delete(p.entries, key)
		p.mu.Unlock()
	}()
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dstConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", dstAddr)
	if err != nil {
		return err
	}
	defer dstConn.Close()
	entry.state.Store(StateConnected)
	if p.loss.LossRate == 0 {
		return p.copyBidirectional(srcConn, dstConn, entry)
	}
	return p.copyBidirectionalLossy(srcConn, dstConn, entry)
}

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

// QUICProxy implements a TCP-conversion proxy that tunnels TCP streams through a
// QUIC-like reliable transport. Like KCP, it survives simulated packet loss via
// retransmission, but additionally models QUIC stream multiplexing: multiple
// proxied TCP connections share a single underlying QUIC connection (simulated via
// per-stream reliable channels grouped under a connection ID).

type QUICProxy struct {
	flags    ProxyFlags
	loss     LossyOptions
	listener net.Listener
	dstAddr  string

	mu      sync.RWMutex
	entries map[string]*quicEntry
	nextID  atomic.Uint64
	closed  bool
	closeCh chan struct{}
	wg      sync.WaitGroup

	// connection multiplexing: map from dst to connection state
	connMu sync.Mutex
	conns  map[string]*quicConn
}

type quicEntry struct {
	id        uint64
	src       string
	dst       string
	startTime int64
	state     atomic.Value // ProxyState
	streamID  uint64
}

type quicConn struct {
	dst     string
	streams map[uint64]*quicStream
	nextSID atomic.Uint64
	mu      sync.Mutex
	closed  bool
}

type quicStream struct {
	id    uint64
	chC2S *ReliableChannel
	chS2C *ReliableChannel
	entry *quicEntry
}

// NewQUICProxy creates a proxy respecting flags.EnableQUICProxy and DisableQUICInput.
func NewQUICProxy(flags ProxyFlags, loss LossyOptions) *QUICProxy {
	return &QUICProxy{
		flags:   flags,
		loss:    loss,
		entries: make(map[string]*quicEntry),
		conns:   make(map[string]*quicConn),
		closeCh: make(chan struct{}),
	}
}

// IsEnabled reports whether outbound QUIC proxy is enabled.
func (p *QUICProxy) IsEnabled() bool { return p.flags.EnableQUICProxy }

// IsInputEnabled reports whether inbound QUIC packets are accepted.
func (p *QUICProxy) IsInputEnabled() bool { return !p.flags.DisableQUICInput }

// IsRelayEnabled reports whether relaying QUIC packets is allowed.
func (p *QUICProxy) IsRelayEnabled() bool { return !p.flags.DisableRelayQUIC }

// Config returns current flag snapshot.
func (p *QUICProxy) Config() ProxyFlags { return p.flags }

// UpdateFlags updates proxy flags.
func (p *QUICProxy) UpdateFlags(flags ProxyFlags) {
	p.mu.Lock()
	p.flags = flags
	p.mu.Unlock()
}

// ListenAddr returns the bound listener address.
func (p *QUICProxy) ListenAddr() net.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.listener != nil {
		return p.listener.Addr()
	}
	return nil
}

// Start starts the QUIC TCP-conversion listener.
func (p *QUICProxy) Start(ctx context.Context, listenAddr, dstAddr string) error {
	if !p.IsEnabled() {
		return nil
	}
	if listenAddr == "" || dstAddr == "" {
		return errors.New("quic proxy listen and dst addresses are required")
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("quic proxy listen %q: %w", listenAddr, err)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = ln.Close()
		return errors.New("quic proxy is closed")
	}
	p.listener = ln
	p.dstAddr = dstAddr
	p.mu.Unlock()

	p.wg.Add(1)
	go p.acceptLoop()
	return nil
}

func (p *QUICProxy) acceptLoop() {
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

func (p *QUICProxy) getOrCreateConn(dst string) *quicConn {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	if c, ok := p.conns[dst]; ok && !c.closed {
		return c
	}
	c := &quicConn{dst: dst, streams: make(map[uint64]*quicStream)}
	p.conns[dst] = c
	return c
}

func (p *QUICProxy) handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	src := clientConn.RemoteAddr().String()
	dst := p.dstAddr
	id := p.nextID.Add(1)
	qc := p.getOrCreateConn(dst)
	sid := qc.nextSID.Add(1)
	entry := &quicEntry{id: id, src: src, dst: dst, startTime: time.Now().Unix(), streamID: sid}
	entry.state.Store(StateSynReceived)
	key := fmt.Sprintf("%d", id)
	p.mu.Lock()
	p.entries[key] = entry
	p.mu.Unlock()
	defer func() {
		entry.state.Store(StateClosed)
		time.Sleep(50 * time.Millisecond)
		p.mu.Lock()
		delete(p.entries, key)
		p.mu.Unlock()
		qc.mu.Lock()
		delete(qc.streams, sid)
		qc.mu.Unlock()
	}()

	entry.state.Store(StateConnecting)

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dstConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", dst)
	if err != nil {
		entry.state.Store(StateClosed)
		return
	}
	defer dstConn.Close()
	entry.state.Store(StateConnected)

	// QUIC stream multiplexing: each TCP connection gets a stream with its own reliable channels.
	stream := &quicStream{
		id:    sid,
		chC2S: NewReliableChannel(p.loss.LossRate, p.loss.Seed+int64(id)),
		chS2C: NewReliableChannel(p.loss.LossRate, p.loss.Seed+int64(id)+5000),
		entry: entry,
	}
	qc.mu.Lock()
	qc.streams[sid] = stream
	qc.mu.Unlock()
	defer stream.chC2S.Close()
	defer stream.chS2C.Close()

	if p.loss.LossRate == 0 {
		_ = p.copyBidirectional(clientConn, dstConn)
		return
	}
	_ = p.copyBidirectionalLossy(clientConn, dstConn, stream)
}

func (p *QUICProxy) copyBidirectional(a, b net.Conn) error {
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
	<-errCh
	time.Sleep(10 * time.Millisecond)
	return nil
}

func (p *QUICProxy) copyBidirectionalLossy(clientConn, dstConn net.Conn, stream *quicStream) error {
	var wg sync.WaitGroup
	wg.Add(4)
	// client -> stream.chC2S
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				if sendErr := stream.chC2S.Send(buf[:n]); sendErr != nil {
					return
				}
			}
			if err != nil {
				time.Sleep(20 * time.Millisecond)
				stream.chC2S.Close()
				if cw, ok := dstConn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			data, err := stream.chC2S.Receive()
			if err != nil {
				return
			}
			if _, werr := dstConn.Write(data); werr != nil {
				return
			}
		}
	}()
	// dst -> stream.chS2C
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := dstConn.Read(buf)
			if n > 0 {
				if sendErr := stream.chS2C.Send(buf[:n]); sendErr != nil {
					return
				}
			}
			if err != nil {
				time.Sleep(20 * time.Millisecond)
				stream.chS2C.Close()
				if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			data, err := stream.chS2C.Receive()
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

// ListEntries returns snapshot of active proxy entries for status/RPC.
func (p *QUICProxy) ListEntries() []ProxyEntry {
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
			TransportType: TransportQUIC,
		})
	}
	return entries
}

// EntryCount returns number of live entries.
func (p *QUICProxy) EntryCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

// StreamCount returns number of active QUIC streams overall.
func (p *QUICProxy) StreamCount() int {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	n := 0
	for _, c := range p.conns {
		c.mu.Lock()
		n += len(c.streams)
		c.mu.Unlock()
	}
	return n
}

// Close shuts down listener and waits for handlers.
func (p *QUICProxy) Close() error {
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
	p.connMu.Lock()
	for _, c := range p.conns {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
	}
	p.connMu.Unlock()
	p.wg.Wait()
	return nil
}

// HandleTCPConversion proxies a single connection through QUIC without listener (for tests).
func (p *QUICProxy) HandleTCPConversion(ctx context.Context, srcConn net.Conn, dstAddr string) error {
	if !p.IsEnabled() {
		return errors.New("quic proxy is disabled")
	}
	if !p.IsInputEnabled() {
		return errors.New("quic input is disabled")
	}
	src := ""
	if srcConn.RemoteAddr() != nil {
		src = srcConn.RemoteAddr().String()
	}
	id := p.nextID.Add(1)
	qc := p.getOrCreateConn(dstAddr)
	sid := qc.nextSID.Add(1)
	entry := &quicEntry{id: id, src: src, dst: dstAddr, startTime: time.Now().Unix(), streamID: sid}
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
		qc.mu.Lock()
		delete(qc.streams, sid)
		qc.mu.Unlock()
	}()
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dstConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", dstAddr)
	if err != nil {
		return err
	}
	defer dstConn.Close()
	entry.state.Store(StateConnected)
	stream := &quicStream{
		id:    sid,
		chC2S: NewReliableChannel(p.loss.LossRate, p.loss.Seed+int64(id)),
		chS2C: NewReliableChannel(p.loss.LossRate, p.loss.Seed+int64(id)+5000),
		entry: entry,
	}
	qc.mu.Lock()
	qc.streams[sid] = stream
	qc.mu.Unlock()
	defer stream.chC2S.Close()
	defer stream.chS2C.Close()
	if p.loss.LossRate == 0 {
		return p.copyBidirectional(srcConn, dstConn)
	}
	return p.copyBidirectionalLossy(srcConn, dstConn, stream)
}

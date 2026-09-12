// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package punch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/stun"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

// Listener pool sizing and retention, mirroring the reference constants.
const (
	// MaxPublicListeners caps the punch listener pool.
	MaxPublicListeners = 4
	// listenerActiveTTL retires listeners with no accepted connection.
	listenerActiveTTL = 40 * time.Second
	// listenerSelectedTTL keeps a freshly selected listener alive briefly.
	listenerSelectedTTL = 30 * time.Second
	// listenerRetentionTick paces the retention sweep.
	listenerRetentionTick = 5 * time.Second
)

// PortMapper optionally leases a public UDP mapping (UPnP / NAT-PMP).
type PortMapper interface {
	// AcquireUDPLease maps port (or an ephemeral one when 0) and returns the
	// public address. A nil-able implementation: callers check for nil.
	AcquireUDPLease(ctx context.Context, port uint16) (netip.AddrPort, error)
}

// PunchListener is one public UDP socket that accepts punched tunnel
// sessions and answers punch control datagrams.
type PunchListener struct {
	service    *transport.UDPService
	socket     *net.UDPConn
	mapped     netip.AddrPort
	portMapped bool

	connCount  atomic.Int64
	listenTime time.Time
	lastSelect atomic.Int64
	lastActive atomic.Int64
	acceptWg   sync.WaitGroup
}

// LocalPort returns the bound local port.
func (l *PunchListener) LocalPort() uint16 {
	local, err := netip.ParseAddrPort(l.socket.LocalAddr().String())
	if err != nil {
		return 0
	}
	return local.Port()
}

// Socket exposes the raw listener socket for punch packet emission.
func (l *PunchListener) Socket() *net.UDPConn { return l.socket }

// ConnCount reports the number of accepted sessions that are still open.
func (l *PunchListener) ConnCount() int64 { return l.connCount.Load() }

// MappedAddr returns the public address of this listener.
func (l *PunchListener) MappedAddr() netip.AddrPort { return l.mapped }

// reuse reports whether remote peers may target the mapped address.
func (l *PunchListener) reusable() bool {
	return l.mapped.IsValid() && !l.mapped.Addr().IsUnspecified()
}

// hasPortMapping reports whether the mapping came from a router lease.
func (l *PunchListener) withPortMapping() bool { return l.portMapped }

// serve accepts punched tunnel sessions until ctx or the service ends.
// Each accepted session increments the connection counter and decrements it
// when the session closes; onSession receives the session for handoff.
func (l *PunchListener) serve(onSession func(*transport.UDPSession), ctx context.Context) {
	l.acceptWg.Add(1)
	go func() {
		defer l.acceptWg.Done()
		for {
			session, err := l.service.Accept(ctx)
			if err != nil {
				return
			}
			l.connCount.Add(1)
			l.lastActive.Store(time.Now().Unix())
			go func(session *transport.UDPSession) {
				<-session.Done()
				l.connCount.Add(-1)
			}(session)
			if onSession != nil {
				onSession(session)
			}
		}
	}()
}

// ListenerPool owns the punch listener lifecycle: creation, selection, and
// retention.
type ListenerPool struct {
	stun   stun.Source
	mapper PortMapper

	onSession func(*transport.UDPSession)

	mu        sync.Mutex
	listeners []*PunchListener
	retainCtx context.Context
	retainWg  sync.WaitGroup
	started   bool
	closed    bool
}

// NewListenerPool builds a pool that resolves mapped addresses via stun and
// optionally via mapper (UPnP) first. onSession receives accepted sessions.
func NewListenerPool(stunSource stun.Source, mapper PortMapper, onSession func(*transport.UDPSession)) *ListenerPool {
	return &ListenerPool{
		stun:      stunSource,
		mapper:    mapper,
		onSession: onSession,
	}
}

// Start launches the retention sweep.
func (p *ListenerPool) Start(ctx context.Context) {
	p.mu.Lock()
	if p.started || p.closed {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.retainCtx = ctx
	p.mu.Unlock()

	p.retainWg.Add(1)
	go func() {
		defer p.retainWg.Done()
		ticker := time.NewTicker(listenerRetentionTick)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.retain()
			}
		}
	}()
}

// retain drops listeners that are inactive and not freshly selected.
func (p *ListenerPool) retain() {
	now := time.Now().Unix()
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.listeners[:0]
	for _, listener := range p.listeners {
		active := now-listener.lastActive.Load() < int64(listenerActiveTTL.Seconds())
		selected := now-listener.lastSelect.Load() < int64(listenerSelectedTTL.Seconds())
		if active || selected {
			kept = append(kept, listener)
			continue
		}
		_ = listener.service.Close()
	}
	p.listeners = kept
}

// Close shuts down every listener and the retention sweep.
func (p *ListenerPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	listeners := p.listeners
	p.listeners = nil
	p.mu.Unlock()
	for _, listener := range listeners {
		_ = listener.service.Close()
	}
	p.retainWg.Wait()
}

// newPunchListener binds one socket, resolves its public address, and starts
// serving. The caller owns failure cleanup.
func (p *ListenerPool) newPunchListener(ctx context.Context, port uint16) (*PunchListener, error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(port)})
	if err != nil {
		return nil, fmt.Errorf("bind punch listener: %w", err)
	}

	var mapped netip.AddrPort
	portMapped := false
	if p.mapper != nil {
		if lease, leaseErr := p.mapper.AcquireUDPLease(ctx, uint16(socket.LocalAddr().(*net.UDPAddr).Port)); leaseErr == nil {
			mapped = lease
			portMapped = true
		}
	}
	if !mapped.IsValid() {
		stunCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		mapped, err = p.stun.GetUDPPortMappingWithSocket(stunCtx, socket)
		cancel()
		if err != nil {
			_ = socket.Close()
			return nil, fmt.Errorf("resolve punch listener public address: %w", err)
		}
	}

	listener := &PunchListener{
		service:    transport.AdoptUDP(socket),
		socket:     socket,
		mapped:     mapped,
		portMapped: portMapped,
		listenTime: time.Now(),
	}
	listener.lastActive.Store(time.Now().Unix())
	listener.lastSelect.Store(time.Now().Unix())

	serveCtx, serveCancel := context.WithCancel(context.WithoutCancel(ctx))
	listener.serve(p.onSession, serveCtx)
	listener.acceptWg.Add(1)
	go func() {
		defer listener.acceptWg.Done()
		_ = listener.service.Serve(serveCtx)
		defer serveCancel()
	}()
	return listener, nil
}

func (p *ListenerPool) closeListener(listener *PunchListener) {
	_ = listener.service.Close()
}

func (p *ListenerPool) poolState() (count int, reusable, withMapping bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	count = len(p.listeners)
	for _, listener := range p.listeners {
		if listener.reusable() {
			reusable = true
		}
		if listener.reusable() && listener.withPortMapping() {
			withMapping = true
		}
	}
	return count, reusable, withMapping
}

func shouldCreateListener(count int, reusable, withMapping, forceNew, preferMapping bool) bool {
	if count >= MaxPublicListeners {
		return false
	}
	if count == 0 {
		return true
	}
	if forceNew {
		return true
	}
	if preferMapping && !withMapping {
		return true
	}
	return !reusable
}

// SelectListener returns the mapped address of a reusable listener, creating
// one when the reference rules call for it.
func (p *ListenerPool) SelectListener(ctx context.Context, forceNew, preferMapping bool) (netip.AddrPort, error) {
	count, reusable, withMapping := p.poolState()
	if shouldCreateListener(count, reusable, withMapping, forceNew, preferMapping) {
		listener, err := p.newPunchListener(ctx, 0)
		if err == nil {
			p.mu.Lock()
			p.listeners = append(p.listeners, listener)
			p.mu.Unlock()
		}
	}

	p.mu.Lock()
	listeners := append([]*PunchListener(nil), p.listeners...)
	p.mu.Unlock()
	if len(listeners) == 0 {
		return netip.AddrPort{}, errors.New("no punch listener available")
	}

	var selected *PunchListener
	if preferMapping {
		selected = pickListener(listeners, func(l *PunchListener) bool { return l.reusable() && l.withPortMapping() })
	}
	if selected == nil {
		selected = pickListener(listeners, func(l *PunchListener) bool { return l.reusable() })
	}
	if selected == nil {
		return netip.AddrPort{}, errors.New("no reusable punch listener")
	}
	selected.lastSelect.Store(time.Now().Unix())
	return selected.MappedAddr(), nil
}

// pickListener returns the most recently active listener matching want.
func pickListener(listeners []*PunchListener, want func(*PunchListener) bool) *PunchListener {
	var best *PunchListener
	var bestActive int64
	for _, listener := range listeners {
		if !want(listener) {
			continue
		}
		active := listener.lastActive.Load()
		if best == nil || active > bestActive {
			best = listener
			bestActive = active
		}
	}
	return best
}

// FindListener returns the socket of the listener mapped to addr.
func (p *ListenerPool) FindListener(addr netip.AddrPort) (*net.UDPConn, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, listener := range p.listeners {
		if listener.reusable() && listener.mapped == addr {
			listener.lastSelect.Store(time.Now().Unix())
			return listener.socket, true
		}
	}
	return nil, false
}

// AddListener installs an externally created listener (used by the both
// easy symmetric strategy to adopt punched ports).
func (p *ListenerPool) AddListener(listener *PunchListener) {
	p.mu.Lock()
	if p.closed || len(p.listeners) >= MaxPublicListeners {
		p.mu.Unlock()
		p.closeListener(listener)
		return
	}
	p.listeners = append(p.listeners, listener)
	p.mu.Unlock()
}

// NewExternalListener binds a listener on the given port without a mapped
// address check; used by the both easy symmetric strategy.
func (p *ListenerPool) NewExternalListener(ctx context.Context, port uint16) (*PunchListener, error) {
	return p.newPunchListenerWithoutMapping(ctx, port)
}

func (p *ListenerPool) newPunchListenerWithoutMapping(ctx context.Context, port uint16) (*PunchListener, error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(port)})
	if err != nil {
		return nil, fmt.Errorf("bind punch listener: %w", err)
	}
	local, _ := netip.ParseAddrPort(socket.LocalAddr().String())
	listener := &PunchListener{
		service:    transport.AdoptUDP(socket),
		socket:     socket,
		mapped:     netip.AddrPortFrom(netip.IPv4Unspecified(), local.Port()),
		portMapped: false,
		listenTime: time.Now(),
	}
	listener.lastActive.Store(time.Now().Unix())
	listener.lastSelect.Store(time.Now().Unix())

	serveCtx, serveCancel := context.WithCancel(context.WithoutCancel(ctx))
	listener.serve(p.onSession, serveCtx)
	listener.acceptWg.Add(1)
	go func() {
		defer listener.acceptWg.Done()
		_ = listener.service.Serve(serveCtx)
		defer serveCancel()
	}()
	return listener, nil
}

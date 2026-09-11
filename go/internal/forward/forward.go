// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package forward provides local TCP port forwarding.
package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	ErrInvalidRule   = errors.New("invalid forwarding rule")
	ErrDuplicateRule = errors.New("duplicate forwarding rule")
	ErrNotFound      = errors.New("forwarding rule not found")
	ErrClosed        = errors.New("forwarding manager is closed")
)

// Rule forwards TCP connections accepted at Bind to Destination.
// Bind must be a loopback TCP address.
type Rule struct {
	Bind        string
	Destination string
}

// Status describes one live forwarding listener and its observed traffic.
type Status struct {
	Rule              Rule
	State             string
	ActiveConnections uint64
	Accepted          uint64
	Failed            uint64
	BytesFromClient   uint64
	BytesToClient     uint64
}

// Manager owns a set of local TCP forwarding listeners.
type Manager struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	closed   bool
	services map[string]*service
}

// NewManager creates a forwarding manager that stops all listeners and active
// connections when ctx is canceled.
func NewManager(ctx context.Context) *Manager {
	if ctx == nil {
		ctx = context.Background()
	}
	managerCtx, cancel := context.WithCancel(ctx)
	m := &Manager{
		ctx:      managerCtx,
		cancel:   cancel,
		services: make(map[string]*service),
	}
	go func() {
		<-managerCtx.Done()
		_ = m.Close()
	}()
	return m
}

// Add validates rule, starts its listener, and registers it with the manager.
func (m *Manager) Add(rule Rule) error {
	rule, err := normalizeRule(rule)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.initializeLocked()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if err := m.ctx.Err(); err != nil {
		m.mu.Unlock()
		return err
	}
	if _, ok := m.services[rule.Bind]; ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrDuplicateRule, rule.Bind)
	}

	listener, err := (&net.ListenConfig{}).Listen(m.ctx, "tcp", rule.Bind)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("listen on %q: %w", rule.Bind, err)
	}
	forwarder := newService(m.ctx, rule, listener)
	m.services[rule.Bind] = forwarder
	forwarder.acceptWG.Add(1)
	m.mu.Unlock()

	go forwarder.serve()
	return nil
}

// Remove stops the listener and every active connection for rule.
func (m *Manager) Remove(rule Rule) error {
	rule, err := normalizeRule(rule)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.initializeLocked()
	forwarder, ok := m.services[rule.Bind]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNotFound, rule.Bind)
	}
	if forwarder.rule.Destination != rule.Destination {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNotFound, rule.Bind)
	}
	delete(m.services, rule.Bind)
	m.mu.Unlock()

	return forwarder.close()
}

// List returns a snapshot of active rules ordered by bind address, then
// destination.
func (m *Manager) List() []Rule {
	m.mu.Lock()
	m.initializeLocked()
	rules := make([]Rule, 0, len(m.services))
	for _, forwarder := range m.services {
		rules = append(rules, forwarder.rule)
	}
	m.mu.Unlock()

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Bind == rules[j].Bind {
			return rules[i].Destination < rules[j].Destination
		}
		return rules[i].Bind < rules[j].Bind
	})
	return rules
}

// Statuses returns live listener state ordered like List.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	m.initializeLocked()
	services := make([]*service, 0, len(m.services))
	for _, forwarder := range m.services {
		services = append(services, forwarder)
	}
	m.mu.Unlock()

	result := make([]Status, 0, len(services))
	for _, forwarder := range services {
		result = append(result, forwarder.status())
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Rule.Bind == result[j].Rule.Bind {
			return result[i].Rule.Destination < result[j].Rule.Destination
		}
		return result[i].Rule.Bind < result[j].Rule.Bind
	})
	return result
}

// Close stops every listener and active connection. It is idempotent.
func (m *Manager) Close() error {
	m.mu.Lock()
	m.initializeLocked()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.cancel()
	services := make([]*service, 0, len(m.services))
	for _, forwarder := range m.services {
		services = append(services, forwarder)
	}
	m.services = make(map[string]*service)
	m.mu.Unlock()

	var result error
	for _, forwarder := range services {
		result = errors.Join(result, forwarder.close())
	}
	return result
}

func (m *Manager) initializeLocked() {
	if m.ctx == nil {
		m.ctx, m.cancel = context.WithCancel(context.Background())
	}
	if m.services == nil {
		m.services = make(map[string]*service)
	}
}

type service struct {
	ctx      context.Context
	rule     Rule
	listener net.Listener

	mu        sync.Mutex
	closed    bool
	conns     map[net.Conn]struct{}
	acceptWG  sync.WaitGroup
	connWG    sync.WaitGroup
	closeOnce sync.Once
	active    atomic.Uint64
	accepted  atomic.Uint64
	failed    atomic.Uint64
	from      atomic.Uint64
	to        atomic.Uint64
}

func newService(ctx context.Context, rule Rule, listener net.Listener) *service {
	return &service{
		ctx:      ctx,
		rule:     rule,
		listener: listener,
		conns:    make(map[net.Conn]struct{}),
	}
}

func (s *service) serve() {
	defer s.acceptWG.Done()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.accepted.Add(1)
		if !s.startConnection(connection) {
			_ = connection.Close()
			continue
		}
		s.active.Add(1)
		go func() {
			defer s.connWG.Done()
			defer s.untrack(connection)
			defer s.active.Add(^uint64(0))
			defer connection.Close()

			dialer := net.Dialer{}
			upstream, err := dialer.DialContext(s.ctx, "tcp", s.rule.Destination)
			if err != nil {
				s.failed.Add(1)
				return
			}
			if !s.track(upstream) {
				_ = upstream.Close()
				return
			}
			defer s.untrack(upstream)
			defer upstream.Close()
			from, to := proxy(connection, upstream)
			s.from.Add(uint64(from))
			s.to.Add(uint64(to))
		}()
	}
}

func (s *service) status() Status {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	state := "listening"
	if closed {
		state = "closed"
	}
	return Status{
		Rule:              s.rule,
		State:             state,
		ActiveConnections: s.active.Load(),
		Accepted:          s.accepted.Load(),
		Failed:            s.failed.Load(),
		BytesFromClient:   s.from.Load(),
		BytesToClient:     s.to.Load(),
	}
}

func (s *service) track(connection net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[connection] = struct{}{}
	return true
}

func (s *service) startConnection(connection net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.connWG.Add(1)
	s.conns[connection] = struct{}{}
	return true
}

func (s *service) untrack(connection net.Conn) {
	s.mu.Lock()
	delete(s.conns, connection)
	s.mu.Unlock()
}

func (s *service) close() error {
	var result error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		connections := make([]net.Conn, 0, len(s.conns))
		for connection := range s.conns {
			connections = append(connections, connection)
		}
		s.mu.Unlock()

		result = s.listener.Close()
		for _, connection := range connections {
			result = errors.Join(result, connection.Close())
		}
		s.acceptWG.Wait()
		s.connWG.Wait()
	})
	return result
}

func proxy(client, upstream net.Conn) (uint64, uint64) {
	var closeBoth sync.Once
	closeConnections := func() {
		_ = client.Close()
		_ = upstream.Close()
	}
	var clientToUpstream, upstreamToClient atomic.Uint64
	copyDirection := func(destination, source net.Conn, count *atomic.Uint64) {
		written, err := io.Copy(destination, source)
		count.Add(uint64(written))
		if err != nil {
			closeBoth.Do(closeConnections)
			return
		}
		if writer, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = writer.CloseWrite()
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyDirection(upstream, client, &clientToUpstream)
	}()
	go func() {
		defer wg.Done()
		copyDirection(client, upstream, &upstreamToClient)
	}()
	wg.Wait()
	return clientToUpstream.Load(), upstreamToClient.Load()
}

func normalizeRule(rule Rule) (Rule, error) {
	bind, err := normalizeAddress(rule.Bind, true)
	if err != nil {
		return Rule{}, fmt.Errorf("%w: bind: %v", ErrInvalidRule, err)
	}
	destination, err := normalizeAddress(rule.Destination, false)
	if err != nil {
		return Rule{}, fmt.Errorf("%w: destination: %v", ErrInvalidRule, err)
	}
	return Rule{Bind: bind, Destination: destination}, nil
}

func normalizeAddress(address string, bind bool) (string, error) {
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if host == "" {
		return "", errors.New("host is required")
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("port %q must be between 1 and 65535", rawPort)
	}

	canonicalHost, loopback, err := normalizeHost(host)
	if err != nil {
		return "", err
	}
	if bind && !loopback {
		return "", fmt.Errorf("host %q is not loopback", host)
	}
	return net.JoinHostPort(canonicalHost, strconv.FormatUint(port, 10)), nil
}

func normalizeHost(host string) (string, bool, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String(), address.IsLoopback(), nil
	}
	canonicalHost := strings.ToLower(host)
	if canonicalHost == "localhost" {
		return canonicalHost, true, nil
	}
	if !validHostname(canonicalHost) {
		return "", false, fmt.Errorf("host %q is invalid", host)
	}
	return canonicalHost, false, nil
}

func validHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
				return false
			}
		}
	}
	return true
}

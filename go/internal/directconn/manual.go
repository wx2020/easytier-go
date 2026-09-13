// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package directconn

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/peer"
)

// Manual connector reconnect tuning mirroring the reference behavior.
const (
	// DefaultReconnectInterval paces the reconnect sweep.
	DefaultReconnectInterval = time.Second
	// shortReconnectTimeout applies to plain tunnel URLs.
	shortReconnectTimeout = 2 * time.Second
	// longReconnectTimeout applies to discovery-style URLs.
	longReconnectTimeout = 20 * time.Second
)

// ConnectorStatus is the reported state of one manual connector.
type ConnectorStatus int

const (
	// StatusConnected means a live authenticated session exists.
	StatusConnected ConnectorStatus = iota
	// StatusConnecting means a reconnect attempt is in flight.
	StatusConnecting
	// StatusDisconnected means the URL is known but not connected.
	StatusDisconnected
)

// String implements fmt.Stringer.
func (s ConnectorStatus) String() string {
	switch s {
	case StatusConnected:
		return "Connected"
	case StatusConnecting:
		return "Connecting"
	default:
		return "Disconnected"
	}
}

// ListedConnector is one manual connector list entry.
type ListedConnector struct {
	URL    string
	Status ConnectorStatus
}

// ManualDial dials one connector URL.
type ManualDial func(ctx context.Context, rawURL string) (peer.PacketChannel, error)

// ManualHandoff authenticates and installs one dialed connection.
type ManualHandoff func(ctx context.Context, channel peer.PacketChannel) error

// ManualConfig wires the manual connector manager.
type ManualConfig struct {
	Dial              ManualDial
	Handoff           ManualHandoff
	ReconnectInterval time.Duration
	// MaxFrame is passed to the dialer when the URL needs frame limits;
	// zero selects the dialer default.
	MaxFrame int
}

// ManualManager keeps a set of connector URLs alive with periodic reconnects.
type ManualManager struct {
	cfg ManualConfig

	mu           sync.Mutex
	connectors   map[string]*manualConn
	order        []string
	removed      map[string]struct{}
	reconnecting map[string]struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed bool
}

type manualConn struct {
	url     string
	channel peer.PacketChannel
	done    chan struct{}
	alive   bool
}

// NewManualManager builds the manager; Start runs the reconnect loop.
func NewManualManager(cfg ManualConfig) *ManualManager {
	if cfg.ReconnectInterval <= 0 {
		cfg.ReconnectInterval = DefaultReconnectInterval
	}
	return &ManualManager{
		cfg:          cfg,
		connectors:   make(map[string]*manualConn),
		removed:      make(map[string]struct{}),
		reconnecting: make(map[string]struct{}),
	}
}

// Start launches the reconnect loop.
func (m *ManualManager) Start(ctx context.Context) {
	if ctx == nil {
		return
	}
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.loop()
}

// Stop cancels the loop and drops every tracked connection.
func (m *ManualManager) Stop() {
	m.mu.Lock()
	if m.closed || m.cancel == nil {
		m.mu.Unlock()
		return
	}
	m.closed = true
	connections := make([]*manualConn, 0, len(m.connectors))
	for _, conn := range m.connectors {
		connections = append(connections, conn)
	}
	m.mu.Unlock()

	m.cancel()
	m.wg.Wait()
	for _, conn := range connections {
		m.closeConn(conn)
	}
}

// AddConnector registers a connector URL.
func (m *ManualManager) AddConnector(rawURL string) error {
	normalized, err := normalizeConnectorURL(rawURL)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("manual connector manager is closed")
	}
	delete(m.removed, normalized)
	if _, exists := m.connectors[normalized]; !exists {
		m.connectors[normalized] = &manualConn{url: normalized, done: make(chan struct{})}
		m.order = append(m.order, normalized)
	}
	return nil
}

// RemoveConnector drops a connector URL. Unknown URLs are an error.
func (m *ManualManager) RemoveConnector(rawURL string) error {
	normalized, err := normalizeConnectorURL(rawURL)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.connectors[normalized]; !exists {
		return fmt.Errorf("connector %q is not registered", normalized)
	}
	m.removed[normalized] = struct{}{}
	return nil
}

// ClearConnectors removes every connector URL.
func (m *ManualManager) ClearConnectors() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, url := range m.order {
		m.removed[url] = struct{}{}
	}
}

// ListConnectors returns the current connector list, sorted by URL.
func (m *ManualManager) ListConnectors() []ListedConnector {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ListedConnector, 0, len(m.order))
	for _, url := range m.order {
		conn := m.connectors[url]
		status := StatusDisconnected
		if _, reconnecting := m.reconnecting[url]; reconnecting {
			status = StatusConnecting
		} else if conn != nil && conn.alive {
			status = StatusConnected
		}
		out = append(out, ListedConnector{URL: url, Status: status})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func (m *ManualManager) loop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.cfg.ReconnectInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		}
		m.processRemoved()
		m.reconnectDead()
	}
}

// processRemoved drops URLs the user removed; reconnecting URLs are retried
// on the next tick.
func (m *ManualManager) processRemoved() {
	m.mu.Lock()
	defer m.mu.Unlock()
	var removeLater []string
	for url := range m.removed {
		if _, reconnecting := m.reconnecting[url]; reconnecting {
			removeLater = append(removeLater, url)
			continue
		}
		if conn, exists := m.connectors[url]; exists {
			m.closeConnLocked(conn)
			delete(m.connectors, url)
		}
		for i, candidate := range m.order {
			if candidate == url {
				m.order = append(m.order[:i], m.order[i+1:]...)
				break
			}
		}
		delete(m.removed, url)
	}
	for _, url := range removeLater {
		m.removed[url] = struct{}{}
	}
}

// reconnectDead finds connectors without live sessions and dials them.
func (m *ManualManager) reconnectDead() {
	var dead []string
	m.mu.Lock()
	for _, url := range m.order {
		conn := m.connectors[url]
		if conn == nil || !conn.alive {
			if _, reconnecting := m.reconnecting[url]; !reconnecting {
				dead = append(dead, url)
			}
		}
	}
	for _, url := range dead {
		m.reconnecting[url] = struct{}{}
	}
	m.mu.Unlock()

	for _, url := range dead {
		m.wg.Add(1)
		go func(url string) {
			defer m.wg.Done()
			m.reconnect(url)
		}(url)
	}
}

func (m *ManualManager) reconnect(url string) {
	defer func() {
		m.mu.Lock()
		delete(m.reconnecting, url)
		m.mu.Unlock()
	}()

	timeout := reconnectTimeout(url)
	dialCtx, cancel := context.WithTimeout(m.ctx, timeout)
	defer cancel()
	if m.ctx.Err() != nil {
		return
	}

	channel, err := m.cfg.Dial(dialCtx, url)
	if err != nil {
		return
	}
	handoffCtx, cancelHandoff := context.WithTimeout(m.ctx, timeout)
	defer cancelHandoff()
	if err := m.cfg.Handoff(handoffCtx, channel); err != nil {
		_ = closeChannel(channel)
		return
	}

	conn := &manualConn{url: url, channel: channel, done: make(chan struct{})}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = closeChannel(channel)
		return
	}
	existing, exists := m.connectors[url]
	if exists {
		m.closeConnLocked(existing)
		conn.done = existing.done
	} else {
		// The URL may have been removed while dialing.
		if _, removing := m.removed[url]; removing {
			m.mu.Unlock()
			_ = closeChannel(channel)
			return
		}
	}
	conn.alive = true
	m.connectors[url] = conn
	m.mu.Unlock()

	// Watch the session; when it dies the next tick reconnects.
	go func(channel peer.PacketChannel, done chan struct{}) {
		defer close(done)
		watchCtx, watchCancel := context.WithCancel(m.ctx)
		defer watchCancel()
		for {
			if _, err := channel.Receive(watchCtx); err != nil {
				return
			}
		}
	}(channel, conn.done)

	m.mu.Lock()
	conn.alive = true
	m.mu.Unlock()
}

func (m *ManualManager) closeConn(conn *manualConn) {
	if conn == nil {
		return
	}
	if closer, ok := conn.channel.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func (m *ManualManager) closeConnLocked(conn *manualConn) {
	m.closeConn(conn)
	conn.alive = false
}

// reconnectTimeout applies the reference per-URL budget.
func reconnectTimeout(rawURL string) time.Duration {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return shortReconnectTimeout
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "txt", "srv", "ws", "wss":
		return longReconnectTimeout
	default:
		return shortReconnectTimeout
	}
}

// normalizeConnectorURL validates and canonicalizes one connector URL.
func normalizeConnectorURL(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", errors.New("connector URL is empty")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "tcp://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse connector URL %q: %w", rawURL, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("connector URL %q has no scheme or host", rawURL)
	}
	return trimmed, nil
}

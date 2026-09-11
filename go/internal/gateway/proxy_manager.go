// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gateway

import (
	"context"
	"net"
)

// Manager aggregates KCP and QUIC proxies and exposes combined status/RPC views.
// It mirrors the Rust Gateway's lifecycle where proxies are conditionally
// started based on Flags.

type Manager struct {
	kcp   *KCPProxy
	quic  *QUICProxy
	flags ProxyFlags
}

// NewManager creates a proxy manager from flags.
func NewManager(flags ProxyFlags, kcpLoss, quicLoss LossyOptions) *Manager {
	return &Manager{
		kcp:   NewKCPProxy(flags, kcpLoss),
		quic:  NewQUICProxy(flags, quicLoss),
		flags: flags,
	}
}

// KCP returns the KCP proxy (may be disabled).
func (m *Manager) KCP() *KCPProxy { return m.kcp }

// QUIC returns the QUIC proxy (may be disabled).
func (m *Manager) QUIC() *QUICProxy { return m.quic }

// IsKCPEnabled reports whether KCP proxy is enabled via config.
func (m *Manager) IsKCPEnabled() bool { return m.kcp.IsEnabled() }

// IsQUICEnabled reports whether QUIC proxy is enabled via config.
func (m *Manager) IsQUICEnabled() bool { return m.quic.IsEnabled() }

// ListEntries returns combined KCP and QUIC entries for RPC/management.
func (m *Manager) ListEntries() []ProxyEntry {
	var out []ProxyEntry
	if m.kcp != nil {
		out = append(out, m.kcp.ListEntries()...)
	}
	if m.quic != nil {
		out = append(out, m.quic.ListEntries()...)
	}
	return out
}

// Start starts enabled proxies. Each proxy's listenAddr/dstAddr are provided
// explicitly so tests can bind to ephemeral ports. In production, dstAddr is the
// proxied destination network.
func (m *Manager) Start(ctx context.Context, kcpListen, kcpDst, quicListen, quicDst string) error {
	if m.kcp.IsEnabled() && kcpListen != "" && kcpDst != "" {
		if err := m.kcp.Start(ctx, kcpListen, kcpDst); err != nil {
			return err
		}
	}
	if m.quic.IsEnabled() && quicListen != "" && quicDst != "" {
		if err := m.quic.Start(ctx, quicListen, quicDst); err != nil {
			_ = m.kcp.Close()
			return err
		}
	}
	return nil
}

// Close shuts down both proxies.
func (m *Manager) Close() error {
	var first error
	if m.kcp != nil {
		if err := m.kcp.Close(); err != nil && first == nil {
			first = err
		}
	}
	if m.quic != nil {
		if err := m.quic.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// ListenerAddrs returns bound listener addresses for diagnostics.
func (m *Manager) ListenerAddrs() map[string]net.Addr {
	out := make(map[string]net.Addr)
	if m.kcp != nil && m.kcp.ListenAddr() != nil {
		out["kcp"] = m.kcp.ListenAddr()
	}
	if m.quic != nil && m.quic.ListenAddr() != nil {
		out["quic"] = m.quic.ListenAddr()
	}
	return out
}

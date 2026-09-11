// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package publicipv6

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Provider advertises a /64 and leases /80s.
type Provider struct {
	mu     sync.Mutex
	prefix netip.Prefix
	leases map[string]lease
	ttl    time.Duration
}
type lease struct {
	addr    netip.Addr
	expires time.Time
}

func NewProvider(prefix netip.Prefix) (*Provider, error) {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Bits() != 64 {
		return nil, fmt.Errorf("invalid IPv6 /64 prefix: %v", prefix)
	}
	return &Provider{prefix: prefix.Masked(), leases: make(map[string]lease), ttl: 5 * time.Minute}, nil
}
func (p *Provider) Prefix() netip.Prefix { return p.prefix }
func (p *Provider) Acquire(client string) (netip.Prefix, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l, ok := p.leases[client]; ok && time.Now().Before(l.expires) {
		return netip.PrefixFrom(l.addr, 80), nil
	}
	// simple deterministic lease: hash client to last 16 bits
	var hash uint16
	for _, b := range []byte(client) {
		hash = hash*31 + uint16(b)
	}
	// Use last 16 bits of prefix + hash
	addr := p.prefix.Addr().As16()
	addr[14] = byte(hash >> 8)
	addr[15] = byte(hash)
	a := netip.AddrFrom16(addr)
	lease := lease{addr: a, expires: time.Now().Add(p.ttl)}
	p.leases[client] = lease
	return netip.PrefixFrom(a, 80), nil
}
func (p *Provider) Release(client string) { p.mu.Lock(); delete(p.leases, client); p.mu.Unlock() }

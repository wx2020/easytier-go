// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package mapping

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// activeMapping tracks an established UDP mapping with renewal.
type activeMapping struct {
	gateway       Gateway
	localListener string // url string
	localAddr     netip.AddrPort
	externalPort  uint16
	backend       string
	stop          chan struct{}
	done          chan struct{}
}

// Lease represents a live port mapping lease. It stops renewal when closed.
type Lease struct {
	Backend       string
	ExternalPort  uint16
	LocalAddr     netip.AddrPort
	LocalListener string
	stop          chan struct{}
	done          chan struct{}
	mu            sync.Mutex
	closed        bool
}

// Close stops renewal and removes the mapping.
func (l *Lease) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.stop)
	done := l.done
	l.mu.Unlock()
	<-done
	return nil
}

// Mapper manages UDP port mappings via UPnP IGD with NAT-PMP fallback.
type Mapper struct {
	discoverIGD    Discovery
	discoverNATPMP Discovery
	leaseDuration  time.Duration
	renewInterval  time.Duration

	mu       sync.Mutex
	mappings map[string]*activeMapping // keyed by localListener url
}

// MapperOptions configures Mapper for production or tests.
type MapperOptions struct {
	DiscoverIGD    Discovery
	DiscoverNATPMP Discovery
	LeaseDuration  time.Duration
	RenewInterval  time.Duration
}

// NewMapper creates a Mapper with optional custom discovery functions and durations.
// If options is nil or fields are zero, defaults are used (real discovery fails gracefully).
func NewMapper(opts MapperOptions) *Mapper {
	lease := opts.LeaseDuration
	if lease == 0 {
		lease = LeaseDuration
	}
	renew := opts.RenewInterval
	if renew == 0 {
		renew = RenewInterval
	}
	return &Mapper{
		discoverIGD:    opts.DiscoverIGD,
		discoverNATPMP: opts.DiscoverNATPMP,
		leaseDuration:  lease,
		renewInterval:  renew,
		mappings:       make(map[string]*activeMapping),
	}
}

// ShouldMapUDPListener reports whether a udp:// listener should be mapped.
// Mirrors Rust should_map_udp_listener: scheme must be udp, host must be non-loopback
// and not broadcast, and must be unspecified, private, or link-local.
func ShouldMapUDPListener(rawURL string) bool {
	u, err := parseMappedURL(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "udp" {
		return false
	}
	if u.Host == "" {
		return false
	}
	addr, err := netip.ParseAddr(u.Host)
	if err != nil {
		return false
	}
	if addr.IsLoopback() {
		return false
	}
	// No explicit broadcast check in netip; approximate via IsPrivate etc plus IsUnspecified.
	// Rust also checks is_broadcast; for IPv4 broadcast is 255.255.255.255.
	if addr.Is4() && addr.As4() == [4]byte{255, 255, 255, 255} {
		return false
	}
	if addr.IsUnspecified() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return true
	}
	return false
}

type parsedURL struct {
	Scheme string
	Host   string
	Port   uint16
}

func parseMappedURL(raw string) (*parsedURL, error) {
	// Lightweight parsing for ShouldMap check; reuse similar logic to config endpoint
	// but simpler: require scheme://host:port
	// Use net/url for robustness.
	// Import inline to avoid cycle
	// We parse here without importing net/url at top to keep mapper.go self-contained;
	// but we already imported net/netip, so add net/url.
	return parseURLInternal(raw)
}

// parseURLInternal is extracted to avoid import cycle issues; uses net/url.
func parseURLInternal(raw string) (*parsedURL, error) {
	// Use standard library
	// We can't import net/url at top due to earlier file having it? Actually mapper.go can import net/url.
	return doParseURL(raw)
}

// AddMapping attempts to create a UDP mapping for the given localListener URL.
// localAddr is the internal address (e.g., 192.168.1.2:11010) to map.
// It tries IGD first, then NAT-PMP fallback. It starts a renewal goroutine and
// returns a Lease that controls lifecycle. The lease's Close removes the mapping.
func (m *Mapper) AddMapping(ctx context.Context, localListener string, localAddr netip.AddrPort) (*Lease, error) {
	if !ShouldMapUDPListener(localListener) {
		return nil, fmt.Errorf("listener %q is not mappable", localListener)
	}
	m.mu.Lock()
	if _, exists := m.mappings[localListener]; exists {
		m.mu.Unlock()
		return nil, fmt.Errorf("mapping already exists for %q", localListener)
	}
	m.mu.Unlock()

	active, err := m.discoverAndEstablish(ctx, localListener, localAddr)
	if err != nil {
		return nil, err
	}

	lease := &Lease{
		Backend:       active.backend,
		ExternalPort:  active.externalPort,
		LocalAddr:     active.localAddr,
		LocalListener: active.localListener,
		stop:          active.stop,
		done:          active.done,
	}
	m.mu.Lock()
	m.mappings[localListener] = active
	m.mu.Unlock()
	return lease, nil
}

// RemoveMapping stops renewal and removes the mapping for localListener.
func (m *Mapper) RemoveMapping(ctx context.Context, localListener string) error {
	m.mu.Lock()
	active, ok := m.mappings[localListener]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("mapping not found for %q", localListener)
	}
	delete(m.mappings, localListener)
	m.mu.Unlock()
	close(active.stop)
	select {
	case <-active.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// ListMappings returns snapshots of active mappings.
func (m *Mapper) ListMappings() []PortMappingEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []PortMappingEntry
	for _, a := range m.mappings {
		result = append(result, PortMappingEntry{
			ExternalPort: a.externalPort,
			InternalAddr: a.localAddr,
			Protocol:     "UDP",
			Description:  Description,
		})
	}
	return result
}

// HasMapping reports whether a mapping for localListener exists.
func (m *Mapper) HasMapping(localListener string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.mappings[localListener]
	return ok
}

func (m *Mapper) discoverAndEstablish(ctx context.Context, localListener string, localAddr netip.AddrPort) (*activeMapping, error) {
	// Try IGD first.
	var lastErr error
	igdGateway, err := m.tryDiscover(ctx, m.discoverIGD)
	if err == nil {
		extPort, err := m.establishViaGateway(ctx, igdGateway, localAddr)
		if err == nil {
			return m.startRenewal(localListener, localAddr, extPort, igdGateway), nil
		}
		lastErr = fmt.Errorf("igd mapping failed: %w", err)
	} else {
		lastErr = fmt.Errorf("igd discovery failed: %w", err)
	}
	// Fallback to NAT-PMP.
	natGateway, err := m.tryDiscover(ctx, m.discoverNATPMP)
	if err != nil {
		if lastErr != nil {
			return nil, fmt.Errorf("udp port mapping failed for %s: igd error: %v; nat-pmp discovery error: %v", localListener, lastErr, err)
		}
		return nil, fmt.Errorf("nat-pmp discovery failed: %w", err)
	}
	extPort, err := m.establishViaGateway(ctx, natGateway, localAddr)
	if err != nil {
		if lastErr != nil {
			return nil, fmt.Errorf("udp port mapping failed for %s: igd error: %v; nat-pmp error: %v", localListener, lastErr, err)
		}
		return nil, err
	}
	return m.startRenewal(localListener, localAddr, extPort, natGateway), nil
}

func (m *Mapper) tryDiscover(ctx context.Context, discover Discovery) (Gateway, error) {
	if discover == nil {
		return nil, fmt.Errorf("no discovery function configured")
	}
	return discover(ctx)
}

func (m *Mapper) establishViaGateway(ctx context.Context, gw Gateway, localAddr netip.AddrPort) (uint16, error) {
	// Try AddAnyPort first (external 0), fallback to same port if that fails (matching Rust).
	extPort, err := gw.AddAnyPort(ctx, localAddr, m.leaseDuration, Description)
	if err == nil {
		return extPort, nil
	}
	// Fallback: try AddPort with same port as local.
	if err2 := gw.AddPort(ctx, localAddr.Port(), localAddr, m.leaseDuration, Description); err2 != nil {
		return 0, fmt.Errorf("any-port error: %v; same-port error: %v", err, err2)
	}
	return localAddr.Port(), nil
}

func (m *Mapper) startRenewal(localListener string, localAddr netip.AddrPort, externalPort uint16, gw Gateway) *activeMapping {
	stop := make(chan struct{})
	done := make(chan struct{})
	active := &activeMapping{
		gateway:       gw,
		localListener: localListener,
		localAddr:     localAddr,
		externalPort:  externalPort,
		backend:       gw.Backend(),
		stop:          stop,
		done:          done,
	}
	go m.renewLoop(active)
	return active
}

func (m *Mapper) renewLoop(a *activeMapping) {
	defer close(a.done)
	defer func() {
		_ = a.gateway.RemovePort(context.Background(), a.externalPort)
	}()
	ticker := time.NewTicker(m.renewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-ticker.C:
			// Renew by re-adding with same external port and lease.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = a.gateway.AddPort(ctx, a.externalPort, a.localAddr, m.leaseDuration, Description)
			cancel()
		}
	}
}

func doParseURL(raw string) (*parsedURL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	var port uint16
	if p := u.Port(); p != "" {
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, err
		}
		port = uint16(v)
	}
	return &parsedURL{Scheme: scheme, Host: host, Port: port}, nil
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package vpnportal

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

// Portal implements a minimal WireGuard VPN portal listener.
// It handles client connections over UDP and tracks connected endpoints.
// For real WireGuard crypto, a stock client can handshake using the
// deterministic keys from GetWgConfig. In this Go port the portal tracks
// any UDP packet as a client registration (suitable for mock testing) and
// can be extended with boringtun-style packet handling.
type Portal struct {
	cfg      config.VPNPortalConfig
	nid      config.NetworkIdentity
	wgConfig WgConfig

	mu      sync.RWMutex
	conn    net.PacketConn
	closed  bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	clients map[string]time.Time // endpoint -> lastSeen

	// native, when non-nil, authenticates EasyTier-native clients via
	// sealed datagrams (see portal_crypto.go). Stock WireGuard clients
	// keep the best-effort tracking below.
	native *nativeCrypto

	// stock tracks standard WireGuard endpoints (see portal_stock.go).
	// meshForward carries decapsulated stock IP packets into the mesh.
	stock        map[string]*stockPeer
	stockEnabled bool
	meshForward  func(ctx context.Context, ipPacket []byte) error
}

// NewPortal creates a WireGuard portal for the given configuration.
func NewPortal(vpnCfg config.VPNPortalConfig, nid config.NetworkIdentity) (*Portal, error) {
	if _, err := netip.ParsePrefix(vpnCfg.ClientCIDR); err != nil {
		return nil, fmt.Errorf("invalid client CIDR %q: %w", vpnCfg.ClientCIDR, err)
	}
	if _, err := net.ResolveUDPAddr("udp", vpnCfg.WireGuardListen); err != nil {
		return nil, fmt.Errorf("invalid wireguard listen %q: %w", vpnCfg.WireGuardListen, err)
	}
	wc, err := GetWgConfig(nid.NetworkName, nid.NetworkSecret)
	if err != nil {
		return nil, err
	}
	return &Portal{
		cfg:      vpnCfg,
		nid:      nid,
		wgConfig: wc,
		clients:  make(map[string]time.Time),
	}, nil
}

// WgConfig returns the deterministic WireGuard keys.
func (p *Portal) WgConfig() WgConfig { return p.wgConfig }

// ListenAddr returns the bound UDP address, or nil if not started.
func (p *Portal) ListenAddr() net.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.conn == nil {
		return nil
	}
	return p.conn.LocalAddr()
}

// Start binds the UDP listener and begins tracking client packets.
func (p *Portal) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		return fmt.Errorf("portal is already started")
	}
	conn, err := net.ListenPacket("udp", p.cfg.WireGuardListen)
	if err != nil {
		return fmt.Errorf("listen wireguard portal on %q: %w", p.cfg.WireGuardListen, err)
	}
	// If port was 0, update stored listen string to actual address
	if p.cfg.WireGuardListen == "0.0.0.0:0" || p.cfg.WireGuardListen == "[::]:0" {
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			p.cfg.WireGuardListen = addr.String()
		}
	}
	p.conn = conn
	child, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.wg.Add(1)
	go p.serve(child)
	return nil
}

func (p *Portal) serve(ctx context.Context) {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	var sinceSweep int
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Short deadline to check context.
		if pc, ok := p.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		}
		n, addr, err := p.conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// Connection closed
			p.mu.RLock()
			closed := p.closed
			p.mu.RUnlock()
			if closed {
				return
			}
			continue
		}
		if n == 0 || addr == nil {
			continue
		}
		endpoint := addr.String()
		// Standard-shaped datagrams go to the stock interop path when
		// armed; otherwise (and for anything else) keep best-effort
		// tracking so stock handshakes are at least observed.
		if p.StockEnabled() && isStockFramed(buf[:n]) {
			packet := append([]byte(nil), buf[:n]...)
			_ = p.handleStockPacket(ctx, addr, packet, func(reply []byte) error {
				_, err := p.conn.WriteTo(reply, addr)
				return err
			})
			sinceSweep++
			if sinceSweep >= 1024 {
				sinceSweep = 0
				p.sweepStock(time.Now())
			}
			continue
		}
		// With native crypto armed, only authenticated clients are
		// tracked; strangers leave no state. Otherwise (unsecured
		// portal) keep the best-effort tracking for stock clients.
		if p.NativeCryptoEnabled() {
			packet := append([]byte(nil), buf[:n]...)
			_ = p.handleNativePacket(ctx, endpoint, packet, func(reply []byte) error {
				_, err := p.conn.WriteTo(reply, addr)
				return err
			})
			continue
		}
		p.mu.Lock()
		p.clients[endpoint] = time.Now()
		p.mu.Unlock()
		// For a real WireGuard portal we would decapsulate with boringtun
		// and forward to PeerManager. For the mock we simply track the client
		// and optionally echo a minimal handshake response if the packet looks
		// like a WireGuard initiation (first byte 0x01). Sending back a packet
		// keeps a stock client from timing out in manual tests.
		if n >= 4 && buf[0] == 0x01 {
			// Minimal response: echo back an empty packet to acknowledge.
			// Real handshake is not required for tracking.
			_, _ = p.conn.WriteTo(buf[:n], addr)
		}
	}
}

// ListClients returns the current connected client endpoints sorted.
func (p *Portal) ListClients() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.clients))
	for k := range p.clients {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RegisterClient is a testing helper that injects a client endpoint without
// needing a real UDP packet. It mirrors the effect of handle_incoming_conn
// registering the client's IP.
func (p *Portal) RegisterClient(endpoint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clients == nil {
		p.clients = make(map[string]time.Time)
	}
	p.clients[endpoint] = time.Now()
}

// GenerateClientConfig returns the WireGuard INI for this portal's network.
func (p *Portal) GenerateClientConfig(cfg config.Config) (string, error) {
	return GenerateClientConfig(cfg)
}

// Close stops the portal and releases the UDP socket.
func (p *Portal) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	conn := p.conn
	p.mu.Unlock()
	p.wg.Wait()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// ClientCount returns number of tracked clients.
func (p *Portal) ClientCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.clients)
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package vpnportal

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/transport/wginterop"
)

// Stock WireGuard client support (boringtun-compatible Noise).
//
// When a mesh forwarder is installed (SetMeshForwarder), the portal also
// answers standard WireGuard handshakes: one wginterop.Tunn per UDP
// endpoint, keyed by the portal's deterministic server/client identity
// (WgConfig::new_for_portal equivalent). Decapsulated IP packets go to
// the mesh forwarder; return traffic enters via DeliverToClient, which
// looks up the endpoint by learned client IP. Without a forwarder the
// portal keeps the legacy best-effort tracking only.

// stockHandshakeRateLimit mirrors boringtun device HANDSHAKE_RATE_LIMIT.
const stockHandshakeRateLimit = 100

// stockPeerIdleTTL bounds endpoint state for vanished clients.
const stockPeerIdleTTL = 10 * time.Minute

type stockPeer struct {
	tunn     *wginterop.Tunn
	addr     net.Addr
	clientIP netip.Addr
	lastSeen time.Time
}

// SetMeshForwarder installs the mesh forward path for decapsulated stock
// packets and arms stock handshake handling.
func (p *Portal) SetMeshForwarder(forward func(ctx context.Context, ipPacket []byte) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.meshForward = forward
	if forward != nil && !p.stockEnabled {
		p.stockEnabled = true
	}
}

// StockEnabled reports whether stock handshake handling is armed.
func (p *Portal) StockEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stockEnabled
}

// isStockFramed reports whether datagram has strict standard framing:
// exact sizes for handshake/cookie messages, LE32 type match.
func isStockFramed(datagram []byte) bool {
	if len(datagram) < 4 {
		return false
	}
	msgType := uint32(datagram[0]) | uint32(datagram[1])<<8 | uint32(datagram[2])<<16 | uint32(datagram[3])<<24
	switch msgType {
	case 1:
		return len(datagram) == wginterop.HandshakeInitSize
	case 2:
		return len(datagram) == wginterop.HandshakeRespSize
	case 3:
		return len(datagram) == wginterop.CookieReplySize
	case 4:
		return len(datagram) >= wginterop.DataOverheadSize
	default:
		return false
	}
}

// handleStockPacket processes one stock datagram from addr. It reports
// whether the datagram was consumed (valid stock traffic).
func (p *Portal) handleStockPacket(ctx context.Context, addr net.Addr, datagram []byte, reply func([]byte) error) bool {
	endpoint := addr.String()
	p.mu.Lock()
	peer := p.stock[endpoint]
	if peer == nil {
		tunn, err := wginterop.NewTunn(p.wgConfig.ServerPrivate, p.wgConfig.ClientPublic, stockHandshakeRateLimit)
		if err != nil {
			p.mu.Unlock()
			return false
		}
		peer = &stockPeer{tunn: tunn, addr: addr}
		if p.stock == nil {
			p.stock = make(map[string]*stockPeer)
		}
		p.stock[endpoint] = peer
	}
	forward := p.meshForward
	p.mu.Unlock()

	var ip net.IP
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		ip = udpAddr.IP
	}
	result := peer.tunn.HandleDatagram(ip, datagram)
	p.mu.Lock()
	peer.lastSeen = time.Now()
	peer.addr = addr
	p.mu.Unlock()
	switch result.Kind {
	case wginterop.KindNetwork:
		_ = reply(result.ToNetwork)
		p.RegisterClient(endpoint)
		return true
	case wginterop.KindTunnel:
		p.learnClientIP(peer, result.ToTunnel)
		p.RegisterClient(endpoint)
		if forward != nil && len(result.ToTunnel) > 0 {
			_ = forward(ctx, append([]byte(nil), result.ToTunnel...))
		}
		return true
	default:
		return false
	}
}

// learnClientIP records the source IP of decapsulated traffic for the
// return path.
func (p *Portal) learnClientIP(peer *stockPeer, ipPacket []byte) {
	src, ok := packetSourceIP(ipPacket)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	peer.clientIP = src
}

// DeliverToClient forwards one mesh IP packet to the stock client owning
// its destination IP. It reports whether the packet was consumed.
func (p *Portal) DeliverToClient(ctx context.Context, ipPacket []byte) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("portal deliver context is nil")
	}
	dst, ok := packetDestIP(ipPacket)
	if !ok {
		return false, nil
	}
	p.mu.Lock()
	var target *stockPeer
	for _, peer := range p.stock {
		if peer.clientIP.IsValid() && peer.clientIP == dst {
			target = peer
			break
		}
	}
	p.mu.Unlock()
	if target == nil {
		return false, nil
	}
	sealed, ok := target.tunn.SealData(ipPacket)
	if !ok {
		return false, nil
	}
	p.mu.RLock()
	conn := p.conn
	addr := target.addr
	p.mu.RUnlock()
	if conn == nil || addr == nil {
		return false, nil
	}
	if _, err := conn.WriteTo(sealed, addr); err != nil {
		return true, err
	}
	return true, nil
}

// sweepStock drops endpoints idle beyond stockPeerIdleTTL.
func (p *Portal) sweepStock(now time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	dropped := 0
	for endpoint, peer := range p.stock {
		peer.tunn.ExpireIdle(now)
		if now.Sub(peer.lastSeen) > stockPeerIdleTTL {
			delete(p.stock, endpoint)
			dropped++
		}
	}
	return dropped
}

func packetSourceIP(packet []byte) (netip.Addr, bool) {
	if len(packet) == 0 {
		return netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		var addr [16]byte
		copy(addr[:], packet[8:24])
		return netip.AddrFrom16(addr), true
	default:
		return netip.Addr{}, false
	}
}

func packetDestIP(packet []byte) (netip.Addr, bool) {
	if len(packet) == 0 {
		return netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]}), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		var addr [16]byte
		copy(addr[:], packet[24:40])
		return netip.AddrFrom16(addr), true
	default:
		return netip.Addr{}, false
	}
}

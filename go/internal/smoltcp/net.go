// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package smoltcp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// Net is the main interface to the user-space stack, mirroring Rust's Net.
type Net struct {
	reactor  *Reactor
	ipAddr   netip.Prefix
	fromPort atomic.Uint32
	stopCh   chan struct{}
	device   AsyncDevice
	anyIP    atomic.Bool
}

// New creates a new Net instance.
func New(device AsyncDevice, config NetConfig) (*Net, error) {
	if !config.IPAddr.IsValid() {
		return nil, errors.New("invalid IP address")
	}
	caps := device.Capabilities()
	if caps.Medium != MediumIP {
		return nil, errors.New("only IP medium supported")
	}
	maxSockets := config.MaxSockets
	if maxSockets == 0 {
		maxSockets = 1024
	}
	reactor := newReactor(device, config.IPAddr, config.BufferSize, maxSockets)
	n := &Net{
		reactor: reactor,
		ipAddr:  config.IPAddr,
		stopCh:  make(chan struct{}),
		device:  device,
	}
	n.fromPort.Store(10001)
	if config.AnyIP {
		n.anyIP.Store(true)
		reactor.anyIP = true
	}
	return n, nil
}

func (n *Net) GetAddress() net.IP {
	addr := n.ipAddr.Addr()
	return net.ParseIP(addr.String())
}

func (n *Net) GetIPPrefix() netip.Prefix { return n.ipAddr }

func (n *Net) GetPort() uint16 {
	for {
		old := n.fromPort.Load()
		next := old + 1
		if next > 60000 {
			next = 10000
		}
		if n.fromPort.CompareAndSwap(old, next) {
			return uint16(old)
		}
	}
}

func (n *Net) SetAnyIP(enabled bool) {
	n.anyIP.Store(enabled)
	n.reactor.anyIP = enabled
}

func (n *Net) AnyIP() bool { return n.anyIP.Load() }

func (n *Net) Close() error {
	select {
	case <-n.reactor.stopCh:
		return nil
	default:
		close(n.reactor.stopCh)
	}
	return nil
}

// TcpBind creates a listener. Mirrors Rust tcp_bind.
func (n *Net) TcpBind(addr net.TCPAddr) (*TcpListener, error) {
	// Normalize: if IP unspecified, use our IP; if port 0, allocate.
	listenIP := addr.IP
	if listenIP == nil || listenIP.IsUnspecified() {
		listenIP = n.GetAddress()
	}
	port := addr.Port
	if port == 0 {
		port = int(n.GetPort())
	}
	key := net.TCPAddr{IP: listenIP, Port: port}

	n.reactor.mu.Lock()
	defer n.reactor.mu.Unlock()
	if len(n.reactor.tcpSockets) >= n.reactor.maxSockets {
		return nil, ErrTooManySockets
	}
	// Check if port already in use.
	for _, s := range n.reactor.tcpSockets {
		s.mu.Lock()
		isListen := s.state == tcpListen
		conflict := isListen && s.localAddr.Port == port
		s.mu.Unlock()
		if conflict {
			return nil, fmt.Errorf("address already in use")
		}
	}
	handle := n.reactor.nextHandle
	n.reactor.nextHandle++
	sock := &tcpSocket{
		handle:      handle,
		state:       tcpListen,
		localAddr:   key,
		maxRx:       n.reactor.bufferSize.TCPRxSize,
		maxTx:       n.reactor.bufferSize.TCTxSize,
		acceptReady: make(chan struct{}, 1),
		recvReady:   make(chan struct{}, 1),
		sendReady:   make(chan struct{}, 1),
		closeCh:     make(chan struct{}),
		connected:   make(chan struct{}),
	}
	n.reactor.tcpSockets[handle] = sock
	listener := &TcpListener{
		reactor:   n.reactor,
		localAddr: key,
		handle:    handle,
	}
	return listener, nil
}

// TcpConnect opens a connection. Mirrors Rust tcp_connect.
func (n *Net) TcpConnect(remote net.TCPAddr, localPort uint16) (*TcpStream, error) {
	if localPort == 0 {
		localPort = n.GetPort()
	}
	localIP := n.GetAddress()
	local := net.TCPAddr{IP: localIP, Port: int(localPort)}

	n.reactor.mu.Lock()
	if len(n.reactor.tcpSockets) >= n.reactor.maxSockets {
		n.reactor.mu.Unlock()
		return nil, ErrTooManySockets
	}
	handle := n.reactor.nextHandle
	n.reactor.nextHandle++
	sock := &tcpSocket{
		handle:     handle,
		state:      tcpSynSent,
		localAddr:  local,
		remoteAddr: remote,
		seq:        0,
		ack:        0,
		maxRx:      n.reactor.bufferSize.TCPRxSize,
		maxTx:      n.reactor.bufferSize.TCTxSize,
		connected:  make(chan struct{}),
		recvReady:  make(chan struct{}, 1),
		sendReady:  make(chan struct{}, 1),
		closeCh:    make(chan struct{}),
	}
	sockHandle := handle
	n.reactor.tcpSockets[handle] = sock
	n.reactor.mu.Unlock()

	// Send SYN
	syn := buildTCPPacket(uint16(local.Port), uint16(remote.Port), sock.seq, 0, TCPFlagSyn, 8192, nil)
	ipPkt := buildIPv4Packet(local.IP, remote.IP, 6, syn)
	if !n.reactor.enqueuePacket(ipPkt, remote.IP) {
		n.reactor.removeTCPSocket(handle)
		return nil, ErrBufferFull
	}
	select {
	case n.reactor.notifyCh <- struct{}{}:
	default:
	}

	// Wait for SYN-ACK / established with timeout
	select {
	case <-sock.connected:
		// Check if closed (RST)
		sock.mu.Lock()
		closed := sock.closed
		state := sock.state
		sock.mu.Unlock()
		if closed || state == tcpClosed {
			n.reactor.removeTCPSocket(sockHandle)
			return nil, ErrConnectionRefused
		}
		stream := &TcpStream{
			reactor:    n.reactor,
			handle:     sockHandle,
			localAddr:  local,
			remoteAddr: remote,
		}
		return stream, nil
	case <-time.After(10 * time.Second):
		n.reactor.removeTCPSocket(sockHandle)
		return nil, errors.New("connect timeout")
	case <-n.reactor.stopCh:
		n.reactor.removeTCPSocket(sockHandle)
		return nil, ErrSocketClosed
	}
}

// UdpBind creates a UDP socket. Mirrors Rust udp_bind.
func (n *Net) UdpBind(addr net.UDPAddr) (*UdpSocket, error) {
	bindIP := addr.IP
	if bindIP == nil || bindIP.IsUnspecified() {
		bindIP = n.GetAddress()
	}
	port := addr.Port
	if port == 0 {
		port = int(n.GetPort())
	}
	key := net.UDPAddr{IP: bindIP, Port: port}

	n.reactor.mu.Lock()
	defer n.reactor.mu.Unlock()
	if len(n.reactor.udpSockets)+len(n.reactor.tcpSockets) >= n.reactor.maxSockets {
		return nil, ErrTooManySockets
	}
	for _, s := range n.reactor.udpSockets {
		s.mu.Lock()
		conflict := s.localAddr.Port == port
		s.mu.Unlock()
		if conflict {
			return nil, fmt.Errorf("address already in use")
		}
	}
	handle := n.reactor.nextHandle
	n.reactor.nextHandle++
	sock := newUDPSocket(key, n.reactor.bufferSize.UDPRxSize, n.reactor.bufferSize.UDPTxSize)
	n.reactor.udpSockets[handle] = sock
	us := &UdpSocket{
		reactor:   n.reactor,
		handle:    handle,
		localAddr: key,
	}
	return us, nil
}

// Routes and helpers for compatibility.
func (n *Net) SetRoutes(fn func()) { fn() }

// For testing: expose device capture/inject.
func (n *Net) Device() AsyncDevice { return n.device }

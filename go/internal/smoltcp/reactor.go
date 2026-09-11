// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package smoltcp

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type Reactor struct {
	mu           sync.Mutex
	device       AsyncDevice
	bufferDevice *BufferDevice
	ipAddr       netip.Prefix
	ip           net.IP
	anyIP        bool
	notifyCh     chan struct{}
	stopCh       chan struct{}
	tcpSockets   map[int]*tcpSocket
	udpSockets   map[int]*udpSocket
	nextHandle   int
	bufferSize   BufferSize
	maxSockets   int
	gateway      []netip.Addr
}

func newReactor(device AsyncDevice, ipAddr netip.Prefix, bs BufferSize, maxSockets int) *Reactor {
	ip := net.ParseIP(ipAddr.Addr().String())
	caps := device.Capabilities()
	bd := NewBufferDevice(caps)
	r := &Reactor{
		device:       device,
		bufferDevice: bd,
		ipAddr:       ipAddr,
		ip:           ip,
		notifyCh:     make(chan struct{}, 10),
		stopCh:       make(chan struct{}),
		tcpSockets:   make(map[int]*tcpSocket),
		udpSockets:   make(map[int]*udpSocket),
		nextHandle:   1,
		bufferSize:   bs,
		maxSockets:   maxSockets,
	}
	go r.run()
	return r
}

func (r *Reactor) run() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
		case <-r.notifyCh:
		case pkt := <-r.device.RecvChan():
			// Inject into buffer device
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			r.bufferDevice.PushOneRecv(cp)
		}
		// Drain any pending packets from device (non-blocking)
		for {
			p, ok := r.device.TryRecv()
			if !ok {
				break
			}
			cp := make([]byte, len(p))
			copy(cp, p)
			if !r.bufferDevice.PushOneRecv(cp) {
				break
			}
		}
		// Flush send queue to device
		for _, pkt := range r.bufferDevice.TakeSendQueue() {
			_ = r.device.Send(pkt)
		}
		// Process recv queue
		for {
			pkt, ok := r.bufferDevice.PopRecv()
			if !ok {
				break
			}
			r.handleIncoming(pkt)
		}
		// Flush outbound data from sockets
		r.flushTCPSend()
		// Handle timeouts / close
		r.cleanupClosed()
	}
}

func (r *Reactor) handleIncoming(data []byte) {
	srcIP, dstIP, proto, payload, ok := parseIPv4Packet(data)
	if !ok {
		return
	}
	// Check destination
	if !r.anyIP {
		if !dstIP.Equal(r.ip) {
			// Allow 127.0.0.1 loopback handling? If our IP is 192.88.99.254 style like Rust, also accept.
			// If packet is for any local, drop unless anyIP.
			return
		}
	}
	switch proto {
	case 6:
		r.handleTCP(srcIP, dstIP, payload)
	case 17:
		r.handleUDP(srcIP, dstIP, payload)
	}
}

func (r *Reactor) handleTCP(srcIP, dstIP net.IP, data []byte) {
	srcPort, dstPort, seq, ack, flags, payload, ok := parseTCPPacket(data)
	if !ok {
		return
	}
	srcAddr := net.TCPAddr{IP: srcIP, Port: int(srcPort)}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Try to find established connection by 4-tuple
	var established *tcpSocket
	var establishedHandle int
	for h, s := range r.tcpSockets {
		s.mu.Lock()
		isEstablished := s.state == tcpEstablished || s.state == tcpSynReceived || s.state == tcpSynSent
		match := s.localAddr.Port == int(dstPort) && s.remoteAddr.Port == int(srcPort) && s.remoteAddr.IP.Equal(srcIP)
		if isEstablished && match {
			established = s
			establishedHandle = h
			// keep lock for handling below
		} else {
			s.mu.Unlock()
		}
		if established != nil {
			break
		}
	}
	if established != nil {
		// Handle existing connection
		switch established.state {
		case tcpSynSent:
			if flags&TCPFlagSyn != 0 && flags&TCPFlagAck != 0 {
				// SYN-ACK -> send ACK, move to established
				established.state = tcpEstablished
				established.ack = seq + 1
				established.seq = ack
				// Notify connector
				select {
				case <-established.connected:
				default:
					close(established.connected)
				}
				// Send ACK
				ackPkt := buildTCPPacket(uint16(dstPort), uint16(srcPort), established.seq, established.ack, TCPFlagAck, 8192, nil)
				ipPkt := buildIPv4Packet(dstIP, srcIP, 6, ackPkt)
				r.enqueuePacket(ipPkt, srcIP)
				// Deliver payload if any (unlikely in SYN-ACK)
				if len(payload) > 0 {
					if len(established.recvBuf)+len(payload) <= established.maxRx {
						established.recvBuf = append(established.recvBuf, payload...)
						select {
						case established.recvReady <- struct{}{}:
						default:
						}
					}
				}
			} else if flags&TCPFlagRst != 0 {
				established.state = tcpClosed
				established.closed = true
				select {
				case <-established.connected:
				default:
					close(established.connected)
				}
			}
			established.mu.Unlock()
			return
		case tcpSynReceived:
			if flags&TCPFlagAck != 0 {
				established.state = tcpEstablished
				// Find listener that owns this pending connection and move to its pending queue
				// The pending connection is already in listener's pending, but we need to ensure ack matches.
				established.ack = seq
				// Wake listener accept
				for _, ls := range r.tcpSockets {
					if ls.state == tcpListen && ls.localAddr.Port == int(dstPort) {
						select {
						case ls.acceptReady <- struct{}{}:
						default:
						}
						break
					}
				}
			}
			established.mu.Unlock()
			return
		case tcpEstablished:
			if flags&TCPFlagRst != 0 {
				established.state = tcpClosed
				established.closed = true
				select {
				case established.recvReady <- struct{}{}:
				default:
				}
				established.mu.Unlock()
				return
			}
			if flags&TCPFlagFin != 0 {
				established.state = tcpCloseWait
				// Send ACK for FIN
				ackPkt := buildTCPPacket(uint16(dstPort), uint16(srcPort), established.seq, seq+1, TCPFlagAck, 8192, nil)
				ipPkt := buildIPv4Packet(dstIP, srcIP, 6, ackPkt)
				r.enqueuePacket(ipPkt, srcIP)
				// Also deliver FIN as EOF
				established.closed = true
				select {
				case established.recvReady <- struct{}{}:
				default:
				}
				established.mu.Unlock()
				return
			}
			// Data packet (PSH/ACK)
			if len(payload) > 0 {
				if len(established.recvBuf)+len(payload) <= established.maxRx {
					established.recvBuf = append(established.recvBuf, payload...)
					select {
					case established.recvReady <- struct{}{}:
					default:
					}
					// Send ACK
					established.ack = seq + uint32(len(payload))
					ackPkt := buildTCPPacket(uint16(dstPort), uint16(srcPort), established.seq, established.ack, TCPFlagAck, 8192, nil)
					ipPkt := buildIPv4Packet(dstIP, srcIP, 6, ackPkt)
					r.enqueuePacket(ipPkt, srcIP)
				}
			} else if flags&TCPFlagAck != 0 {
				// Pure ACK for our sent data: clear sendBuf (simplified)
				// We assume ACK acknowledges all sent data.
				established.sendBuf = nil
				select {
				case established.sendReady <- struct{}{}:
				default:
				}
			}
			established.mu.Unlock()
			// keep handle for debugging
			_ = establishedHandle
			return
		default:
			established.mu.Unlock()
			return
		}
	}

	// No established connection found: check for listener
	for _, ls := range r.tcpSockets {
		ls.mu.Lock()
		if ls.state == tcpListen && ls.localAddr.Port == int(dstPort) {
			// Listener found
			if flags&TCPFlagSyn != 0 && flags&TCPFlagAck == 0 {
				// SYN -> create syn-received socket
				if len(r.tcpSockets) >= r.maxSockets {
					ls.mu.Unlock()
					// Send RST
					rst := buildTCPPacket(uint16(dstPort), uint16(srcPort), 0, seq+1, TCPFlagRst|TCPFlagAck, 0, nil)
					ipPkt := buildIPv4Packet(dstIP, srcIP, 6, rst)
					r.enqueuePacket(ipPkt, srcIP)
					return
				}
				// Create child socket
				childLocal := net.TCPAddr{IP: dstIP, Port: int(dstPort)}
				child := &tcpSocket{
					handle:      r.nextHandle,
					state:       tcpSynReceived,
					localAddr:   childLocal,
					remoteAddr:  srcAddr,
					seq:         0,
					ack:         seq + 1,
					maxRx:       r.bufferSize.TCPRxSize,
					maxTx:       r.bufferSize.TCTxSize,
					connected:   make(chan struct{}),
					recvReady:   make(chan struct{}, 1),
					sendReady:   make(chan struct{}, 1),
					closeCh:     make(chan struct{}),
					acceptReady: make(chan struct{}, 1),
				}
				handle := r.nextHandle
				r.nextHandle++
				r.tcpSockets[handle] = child
				ls.pending = append(ls.pending, child)
				// Send SYN-ACK
				synAck := buildTCPPacket(uint16(dstPort), uint16(srcPort), child.seq, child.ack, TCPFlagSyn|TCPFlagAck, 8192, nil)
				ipPkt := buildIPv4Packet(dstIP, srcIP, 6, synAck)
				r.enqueuePacket(ipPkt, srcIP)
				ls.mu.Unlock()
				return
			}
			ls.mu.Unlock()
			// Not SYN: send RST
			rst := buildTCPPacket(uint16(dstPort), uint16(srcPort), 0, 0, TCPFlagRst, 0, nil)
			ipPkt := buildIPv4Packet(dstIP, srcIP, 6, rst)
			r.enqueuePacket(ipPkt, srcIP)
			return
		}
		ls.mu.Unlock()
	}
	// No listener: send RST
	rst := buildTCPPacket(uint16(dstPort), uint16(srcPort), 0, seq+1, TCPFlagRst|TCPFlagAck, 0, nil)
	ipPkt := buildIPv4Packet(dstIP, srcIP, 6, rst)
	r.enqueuePacket(ipPkt, srcIP)
}

func (r *Reactor) handleUDP(srcIP, dstIP net.IP, data []byte) {
	srcPort, dstPort, payload, ok := parseUDPPacket(data)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sock := range r.udpSockets {
		sock.mu.Lock()
		if sock.localAddr.Port == int(dstPort) && (sock.localAddr.IP.Equal(net.IPv4zero) || sock.localAddr.IP.Equal(dstIP)) {
			// Check anyIP or exact match? Already checked dstIP at top.
			dgram := udpDatagram{
				data: append([]byte(nil), payload...),
				src:  net.UDPAddr{IP: srcIP, Port: int(srcPort)},
			}
			select {
			case sock.recvCh <- dgram:
			default:
				// drop if full (resource limit)
			}
			sock.mu.Unlock()
			return
		}
		sock.mu.Unlock()
	}
	// No socket: drop (could send ICMP unreachable but ignore)
}

func (r *Reactor) flushTCPSend() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sock := range r.tcpSockets {
		sock.mu.Lock()
		if sock.state == tcpEstablished && len(sock.sendBuf) > 0 {
			payload := append([]byte(nil), sock.sendBuf...)
			sock.sendBuf = nil
			srcPort := uint16(sock.localAddr.Port)
			dstPort := uint16(sock.remoteAddr.Port)
			srcIP := sock.localAddr.IP
			if srcIP == nil || srcIP.Equal(net.IPv4zero) {
				srcIP = r.ip
			}
			dstIP := sock.remoteAddr.IP
			seq := sock.seq
			ack := sock.ack
			tcpPkt := buildTCPPacket(srcPort, dstPort, seq, ack, TCPFlagPsh|TCPFlagAck, 8192, payload)
			ipPkt := buildIPv4Packet(srcIP, dstIP, 6, tcpPkt)
			r.enqueuePacket(ipPkt, dstIP)
			sock.seq += uint32(len(payload))
			select {
			case sock.sendReady <- struct{}{}:
			default:
			}
		} else if sock.state == tcpFinWait1 {
			srcPort := uint16(sock.localAddr.Port)
			dstPort := uint16(sock.remoteAddr.Port)
			srcIP := sock.localAddr.IP
			if srcIP == nil || srcIP.Equal(net.IPv4zero) {
				srcIP = r.ip
			}
			dstIP := sock.remoteAddr.IP
			finPkt := buildTCPPacket(srcPort, dstPort, sock.seq, sock.ack, TCPFlagFin|TCPFlagAck, 8192, nil)
			ipPkt := buildIPv4Packet(srcIP, dstIP, 6, finPkt)
			r.enqueuePacket(ipPkt, dstIP)
			sock.state = tcpClosed
		}
		sock.mu.Unlock()
	}
}

func (r *Reactor) enqueuePacket(ipPkt []byte, dstIP net.IP) bool {
	if dstIP.Equal(r.ip) {
		// Loopback: deliver directly
		if !r.bufferDevice.PushOneRecv(ipPkt) {
			return false
		}
		select {
		case r.notifyCh <- struct{}{}:
		default:
		}
		// Also enqueue to send queue for device visibility if needed; but loopback already delivered
		// Keep send queue for external observation if device is ChannelDevice with loopback bridge disabled.
		// We still enqueue to send queue so tests can observe via Capture channel.
		_ = r.bufferDevice.EnqueueSend(ipPkt)
		return true
	}
	return r.bufferDevice.EnqueueSend(ipPkt)
}

func (r *Reactor) sendUDP(src net.UDPAddr, dst net.UDPAddr, data []byte) error {
	srcIP := src.IP
	if srcIP == nil || srcIP.Equal(net.IPv4zero) {
		srcIP = r.ip
	}
	dstIP := dst.IP
	udpPkt := buildUDPPacket(uint16(src.Port), uint16(dst.Port), data)
	ipPkt := buildIPv4Packet(srcIP, dstIP, 17, udpPkt)
	if len(ipPkt) > r.device.Capabilities().MTU {
		return ErrBufferFull
	}
	if !r.enqueuePacket(ipPkt, dstIP) {
		return ErrBufferFull
	}
	select {
	case r.notifyCh <- struct{}{}:
	default:
	}
	return nil
}

func (r *Reactor) removeTCPSocket(handle int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sock, ok := r.tcpSockets[handle]; ok {
		sock.mu.Lock()
		if !sock.closed {
			sock.closed = true
			close(sock.closeCh)
		}
		sock.mu.Unlock()
		delete(r.tcpSockets, handle)
	}
}

func (r *Reactor) removeUDPSocket(handle int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sock, ok := r.udpSockets[handle]; ok {
		sock.mu.Lock()
		if !sock.closed {
			sock.closed = true
			close(sock.closeCh)
		}
		sock.mu.Unlock()
		delete(r.udpSockets, handle)
	}
}

func (r *Reactor) cleanupClosed() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for h, s := range r.tcpSockets {
		s.mu.Lock()
		closed := s.closed && s.state == tcpClosed
		// Also cleanup TimeWait after timeout? Simplified.
		s.mu.Unlock()
		if closed {
			delete(r.tcpSockets, h)
		}
	}
}

var _ = atomic.Value{}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package smoltcp

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var (
	ErrSocketClosed      = errors.New("socket closed")
	ErrConnectionRefused = errors.New("connection refused")
	ErrBufferFull        = errors.New("buffer full")
	ErrTooManySockets    = errors.New("too many sockets")
	ErrNotConnected      = errors.New("not connected")
)

type tcpState int

const (
	tcpClosed tcpState = iota
	tcpListen
	tcpSynSent
	tcpSynReceived
	tcpEstablished
	tcpFinWait1
	tcpCloseWait
	tcpClosing
	tcpLastAck
	tcpTimeWait
)

type tcpSocket struct {
	mu         sync.Mutex
	handle     int
	state      tcpState
	localAddr  net.TCPAddr
	remoteAddr net.TCPAddr
	seq        uint32
	ack        uint32
	recvBuf    []byte
	sendBuf    []byte
	maxRx      int
	maxTx      int
	// channels for blocking ops
	connected   chan struct{}
	acceptReady chan struct{}
	recvReady   chan struct{}
	sendReady   chan struct{}
	closed      bool
	closeCh     chan struct{}
	// for listener
	pending []*tcpSocket
	// for data
	lastActivity time.Time
}

type udpSocket struct {
	mu        sync.Mutex
	localAddr net.UDPAddr
	recvCh    chan udpDatagram
	closed    bool
	closeCh   chan struct{}
	maxRx     int
	maxTx     int
}

type udpDatagram struct {
	data []byte
	src  net.UDPAddr
}

func newTCPSocket(local net.TCPAddr, maxRx, maxTx int) *tcpSocket {
	return &tcpSocket{
		state:     tcpClosed,
		localAddr: local,
		maxRx:     maxRx,
		maxTx:     maxTx,
		connected: make(chan struct{}),
		recvReady: make(chan struct{}, 1),
		sendReady: make(chan struct{}, 1),
		closeCh:   make(chan struct{}),
	}
}

func newUDPSocket(local net.UDPAddr, maxRx, maxTx int) *udpSocket {
	return &udpSocket{
		localAddr: local,
		recvCh:    make(chan udpDatagram, 32),
		closeCh:   make(chan struct{}),
		maxRx:     maxRx,
		maxTx:     maxTx,
	}
}

// Public socket wrappers.

type TcpListener struct {
	reactor   *Reactor
	localAddr net.TCPAddr
	handle    int
	closed    bool
	mu        sync.Mutex
}

func (l *TcpListener) Addr() net.Addr { return &l.localAddr }
func (l *TcpListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.reactor.removeTCPSocket(l.handle)
	return nil
}

func (l *TcpListener) Accept() (*TcpStream, net.Addr, error) {
	for {
		l.reactor.mu.Lock()
		sock, ok := l.reactor.tcpSockets[l.handle]
		l.reactor.mu.Unlock()
		if !ok {
			return nil, nil, ErrSocketClosed
		}
		sock.mu.Lock()
		if len(sock.pending) > 0 {
			child := sock.pending[0]
			sock.pending = sock.pending[1:]
			child.mu.Lock()
			child.state = tcpEstablished
			child.mu.Unlock()
			sock.mu.Unlock()
			stream := &TcpStream{
				reactor:    l.reactor,
				handle:     child.handle,
				localAddr:  child.localAddr,
				remoteAddr: child.remoteAddr,
			}
			return stream, &child.remoteAddr, nil
		}
		ch := sock.acceptReady
		sock.mu.Unlock()
		select {
		case <-ch:
		case <-l.reactor.stopCh:
			return nil, nil, ErrSocketClosed
		case <-time.After(30 * time.Second):
			return nil, nil, errors.New("accept timeout")
		}
	}
}

type TcpStream struct {
	reactor       *Reactor
	handle        int
	localAddr     net.TCPAddr
	remoteAddr    net.TCPAddr
	readDeadline  time.Time
	writeDeadline time.Time
	deadMu        sync.Mutex
}

func (s *TcpStream) LocalAddr() net.Addr  { return &s.localAddr }
func (s *TcpStream) RemoteAddr() net.Addr { return &s.remoteAddr }

func (s *TcpStream) Read(b []byte) (int, error) {
	for {
		s.reactor.mu.Lock()
		sock, ok := s.reactor.tcpSockets[s.handle]
		s.reactor.mu.Unlock()
		if !ok {
			return 0, ErrSocketClosed
		}
		sock.mu.Lock()
		if len(sock.recvBuf) > 0 {
			n := copy(b, sock.recvBuf)
			sock.recvBuf = append([]byte(nil), sock.recvBuf[n:]...)
			sock.mu.Unlock()
			// Notify reactor that buffer has space for more data.
			select {
			case s.reactor.notifyCh <- struct{}{}:
			default:
			}
			return n, nil
		}
		if sock.state == tcpClosed || sock.closed {
			if len(sock.recvBuf) == 0 {
				sock.mu.Unlock()
				return 0, io.EOF
			}
		}
		ch := sock.recvReady
		sock.mu.Unlock()
		select {
		case <-ch:
		case <-s.reactor.stopCh:
			return 0, ErrSocketClosed
		case <-time.After(30 * time.Second):
			// Return 0 to avoid hanging forever in tests; allow retry.
			return 0, nil
		}
		// Check deadline
		s.deadMu.Lock()
		dl := s.readDeadline
		s.deadMu.Unlock()
		if !dl.IsZero() && time.Now().After(dl) {
			return 0, errors.New("read timeout")
		}
	}
}

func (s *TcpStream) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s.reactor.mu.Lock()
	sock, ok := s.reactor.tcpSockets[s.handle]
	s.reactor.mu.Unlock()
	if !ok {
		return 0, ErrSocketClosed
	}
	sock.mu.Lock()
	if sock.state != tcpEstablished {
		sock.mu.Unlock()
		return 0, ErrNotConnected
	}
	// Enforce buffer limit.
	if len(sock.sendBuf)+len(b) > sock.maxTx {
		sock.mu.Unlock()
		return 0, ErrBufferFull
	}
	sock.sendBuf = append(sock.sendBuf, b...)
	sock.lastActivity = time.Now()
	sock.mu.Unlock()
	// Notify reactor to flush.
	select {
	case s.reactor.notifyCh <- struct{}{}:
	default:
	}
	// Wait for send to be drained (with timeout).
	// For simplicity, return immediately and let reactor send.
	return len(b), nil
}

func (s *TcpStream) Close() error {
	s.reactor.mu.Lock()
	sock, ok := s.reactor.tcpSockets[s.handle]
	s.reactor.mu.Unlock()
	if !ok {
		return nil
	}
	sock.mu.Lock()
	if !sock.closed {
		sock.closed = true
		close(sock.closeCh)
		// Enqueue FIN packet
		sock.state = tcpFinWait1
	}
	sock.mu.Unlock()
	select {
	case s.reactor.notifyCh <- struct{}{}:
	default:
	}
	// Give reactor time to send FIN
	time.Sleep(10 * time.Millisecond)
	s.reactor.removeTCPSocket(s.handle)
	return nil
}

func (s *TcpStream) SetDeadline(t time.Time) error {
	s.deadMu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.deadMu.Unlock()
	return nil
}
func (s *TcpStream) SetReadDeadline(t time.Time) error {
	s.deadMu.Lock()
	s.readDeadline = t
	s.deadMu.Unlock()
	return nil
}
func (s *TcpStream) SetWriteDeadline(t time.Time) error {
	s.deadMu.Lock()
	s.writeDeadline = t
	s.deadMu.Unlock()
	return nil
}

// UdpSocket wrapper.
type UdpSocket struct {
	reactor   *Reactor
	handle    int
	localAddr net.UDPAddr
}

func (u *UdpSocket) LocalAddr() net.Addr { return &u.localAddr }

func (u *UdpSocket) Close() error {
	u.reactor.removeUDPSocket(u.handle)
	return nil
}

func (u *UdpSocket) SendTo(data []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		// Try parse string
		resolved, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return 0, err
		}
		udpAddr = resolved
	}
	u.reactor.mu.Lock()
	sock, ok := u.reactor.udpSockets[u.handle]
	u.reactor.mu.Unlock()
	if !ok {
		return 0, ErrSocketClosed
	}
	sock.mu.Lock()
	if sock.closed {
		sock.mu.Unlock()
		return 0, ErrSocketClosed
	}
	if len(data) > sock.maxTx {
		sock.mu.Unlock()
		return 0, ErrBufferFull
	}
	sock.mu.Unlock()
	// Build and enqueue packet via reactor
	if err := u.reactor.sendUDP(u.localAddr, *udpAddr, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (u *UdpSocket) RecvFrom(b []byte) (int, net.Addr, error) {
	u.reactor.mu.Lock()
	sock, ok := u.reactor.udpSockets[u.handle]
	u.reactor.mu.Unlock()
	if !ok {
		return 0, nil, ErrSocketClosed
	}
	select {
	case dgram := <-sock.recvCh:
		n := copy(b, dgram.data)
		// If datagram larger than buffer, truncate (like real UDP)
		return n, &dgram.src, nil
	case <-sock.closeCh:
		return 0, nil, ErrSocketClosed
	case <-u.reactor.stopCh:
		return 0, nil, ErrSocketClosed
	case <-time.After(30 * time.Second):
		return 0, nil, errors.New("recv timeout")
	}
}

func (u *UdpSocket) WriteTo(data []byte, addr net.Addr) (int, error) { return u.SendTo(data, addr) }
func (u *UdpSocket) ReadFrom(b []byte) (int, net.Addr, error)        { return u.RecvFrom(b) }

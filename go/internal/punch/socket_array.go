// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package punch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

// PunchedSocket is one array socket that received a punch datagram carrying
// an interesting transaction ID.
type PunchedSocket struct {
	Socket *net.UDPConn
	TID    uint32
	Remote *net.UDPAddr
}

// UdpSocketArray holds a pool of bound UDP sockets used for symmetric hole
// punching. Each socket watches for punch datagrams whose transaction ID is
// registered as interesting and records the first match per socket.
type UdpSocketArray struct {
	maxSockets int

	mu       sync.Mutex
	sockets  map[string]*net.UDPConn
	punched  map[uint32][]PunchedSocket
	interest map[uint32]struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed bool
}

// NewUdpSocketArray builds an array holding at most maxSockets sockets.
func NewUdpSocketArray(maxSockets int) *UdpSocketArray {
	ctx, cancel := context.WithCancel(context.Background())
	return &UdpSocketArray{
		maxSockets: maxSockets,
		sockets:    make(map[string]*net.UDPConn),
		punched:    make(map[uint32][]PunchedSocket),
		interest:   make(map[uint32]struct{}),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start binds the socket pool and starts the receive loops.
func (a *UdpSocketArray) Start() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return errors.New("udp socket array is closed")
	}
	a.mu.Unlock()
	for len(a.snapshotSockets()) < a.maxSockets {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			return fmt.Errorf("bind udp array socket: %w", err)
		}
		if err := a.AddSocket(conn); err != nil {
			_ = conn.Close()
			return err
		}
	}
	return nil
}

func (a *UdpSocketArray) snapshotSockets() map[string]*net.UDPConn {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]*net.UDPConn, len(a.sockets))
	for key, conn := range a.sockets {
		out[key] = conn
	}
	return out
}

// AddSocket registers one additional socket with a receive loop.
func (a *UdpSocketArray) AddSocket(conn *net.UDPConn) error {
	local := conn.LocalAddr().String()
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return errors.New("udp socket array is closed")
	}
	if _, exists := a.sockets[local]; exists {
		a.mu.Unlock()
		return fmt.Errorf("udp socket %s is already registered", local)
	}
	a.sockets[local] = conn
	a.wg.Add(1)
	a.mu.Unlock()

	go a.recvLoop(local, conn)
	return nil
}

// recvLoop watches one socket until it records a punched match, errors, or
// the array shuts down. The socket leaves the pool when the loop ends.
func (a *UdpSocketArray) recvLoop(local string, conn *net.UDPConn) {
	defer a.wg.Done()
	defer a.removeSocket(local, conn)

	buffer := make([]byte, 512)
	for {
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		datagram, err := parsePunchDatagram(buffer[:n])
		if err != nil {
			continue
		}
		a.mu.Lock()
		interested := false
		if _, ok := a.interest[datagram.tid]; ok {
			interested = true
			a.punched[datagram.tid] = append(a.punched[datagram.tid], PunchedSocket{
				Socket: conn,
				TID:    datagram.tid,
				Remote: remote,
			})
		}
		a.mu.Unlock()
		if interested {
			return
		}
	}
}

func (a *UdpSocketArray) removeSocket(local string, conn *net.UDPConn) {
	a.mu.Lock()
	delete(a.sockets, local)
	a.mu.Unlock()
}

// AddInterestTID registers a transaction ID as worth capturing.
func (a *UdpSocketArray) AddInterestTID(tid uint32) {
	a.mu.Lock()
	a.interest[tid] = struct{}{}
	a.mu.Unlock()
}

// RemoveInterestTID drops a transaction ID and its captured sockets.
func (a *UdpSocketArray) RemoveInterestTID(tid uint32) {
	a.mu.Lock()
	delete(a.interest, tid)
	delete(a.punched, tid)
	a.mu.Unlock()
}

// TryFetchPunchedSocket pops one captured socket for the transaction ID.
func (a *UdpSocketArray) TryFetchPunchedSocket(tid uint32) (PunchedSocket, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	captured := a.punched[tid]
	if len(captured) == 0 {
		return PunchedSocket{}, false
	}
	socket := captured[len(captured)-1]
	a.punched[tid] = captured[:len(captured)-1]
	if len(a.punched[tid]) == 0 {
		delete(a.punched, tid)
	}
	return socket, true
}

// SendWithAll sends data three times from every pooled socket.
func (a *UdpSocketArray) SendWithAll(data []byte, target *net.UDPAddr) error {
	sockets := a.snapshotSockets()
	if len(sockets) == 0 {
		return errors.New("udp socket array has no sockets")
	}
	var firstErr error
	for _, conn := range sockets {
		for i := 0; i < 3; i++ {
			if _, err := conn.WriteToUDP(data, target); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// SocketCount reports the number of live pooled sockets.
func (a *UdpSocketArray) SocketCount() int {
	return len(a.snapshotSockets())
}

// Started reports whether any socket is pooled.
func (a *UdpSocketArray) Started() bool {
	return a.SocketCount() > 0
}

// Close shuts down every pooled socket and stops the receive loops.
func (a *UdpSocketArray) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	sockets := a.sockets
	a.sockets = make(map[string]*net.UDPConn)
	a.punched = make(map[uint32][]PunchedSocket)
	a.interest = make(map[uint32]struct{})
	a.mu.Unlock()

	a.cancel()
	for _, conn := range sockets {
		_ = conn.Close()
	}
	a.wg.Wait()
}

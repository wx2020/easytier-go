// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrConnClosed    = errors.New("quic: connection closed")
	ErrHandshakeFail = errors.New("quic: handshake failed")
)

type connState int

const (
	stateInitial connState = iota
	stateHandshaking
	stateEstablished
	stateClosed
)

type inFlightPacket struct {
	pn     uint64
	sentAt time.Time
	frames []Frame
}

// Connection represents a single EasyTier QUIC tunnel connection.
type Connection struct {
	endpoint   *Endpoint
	remoteAddr *net.UDPAddr
	isClient   bool

	localCID  []byte
	remoteCID []byte

	mu            sync.Mutex
	state         connState
	nextSendPN    uint64
	largestPeerPN uint64
	largestAcked  uint64
	hasPeerPN     bool

	inFlight      map[uint64]*inFlightPacket
	pendingFrames []Frame
	ackScheduled  bool

	recvStream *recvStreamBuffer
	sendStream *sendStreamBuffer

	handshakeDone chan struct{}
	closeOnce     sync.Once
	doneCh        chan struct{}
	err           error

	rttEstimate time.Duration
}

func newConnection(ep *Endpoint, remote *net.UDPAddr, isClient bool, localCID, remoteCID []byte) *Connection {
	if len(localCID) == 0 {
		localCID = make([]byte, 8)
		_, _ = rand.Read(localCID)
	}
	if len(remoteCID) == 0 {
		remoteCID = make([]byte, 8)
		_, _ = rand.Read(remoteCID)
	}

	c := &Connection{
		endpoint:      ep,
		remoteAddr:    remote,
		isClient:      isClient,
		localCID:      localCID,
		remoteCID:     remoteCID,
		state:         stateInitial,
		inFlight:      make(map[uint64]*inFlightPacket),
		recvStream:    newRecvStreamBuffer(),
		sendStream:    newSendStreamBuffer(),
		handshakeDone: make(chan struct{}),
		doneCh:        make(chan struct{}),
		rttEstimate:   50 * time.Millisecond,
	}

	return c
}

// LocalAddr returns the local network address.
func (c *Connection) LocalAddr() net.Addr {
	return c.endpoint.socket.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// Read reads stream data received on Stream 0.
func (c *Connection) Read(p []byte) (int, error) {
	return c.recvStream.Read(p)
}

// Write writes stream data to be sent on Stream 0.
func (c *Connection) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.state == stateClosed {
		c.mu.Unlock()
		return 0, ErrConnClosed
	}
	c.mu.Unlock()

	n, err := c.sendStream.Write(p)
	if err != nil {
		return n, err
	}

	// Trigger packet flush
	c.flushOutbound()
	return n, nil
}

// Close closes the connection and releases resources.
func (c *Connection) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.state = stateClosed
		close(c.doneCh)
		c.recvStream.Close()
		c.mu.Unlock()

		// Send close frame
		closeFrame := ConnectionCloseFrame{
			ErrorCode:    0,
			ReasonPhrase: "done",
		}
		c.sendPacketDirect([]Frame{closeFrame})
		c.endpoint.removeConn(c)
	})
	return nil
}

// Done returns a channel that is closed when the connection terminates.
func (c *Connection) Done() <-chan struct{} {
	return c.doneCh
}

// WaitHandshake blocks until handshake completes or ctx cancels.
func (c *Connection) WaitHandshake(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.doneCh:
		return ErrConnClosed
	case <-c.handshakeDone:
		return nil
	}
}

func (c *Connection) sendPacketDirect(frames []Frame) {
	c.mu.Lock()
	pn := c.nextSendPN
	c.nextSendPN++
	is1RTT := (c.state == stateEstablished)
	localCID := c.localCID
	remoteCID := c.remoteCID
	c.mu.Unlock()

	var payload []byte
	for _, f := range frames {
		payload = f.Append(payload)
	}

	var packet []byte
	if is1RTT {
		hdr := AppendShortHeader(nil, remoteCID, pn, 2)
		packet = SealPacket(hdr, payload)
	} else {
		// Handshake or Initial packet
		pktType := PacketTypeHandshake
		if c.isClient && pn == 0 {
			pktType = PacketTypeInitial
		}
		hdr := AppendLongHeader(nil, pktType, Version1, remoteCID, localCID, nil, pn, 2, len(payload))
		packet = SealPacket(hdr, payload)

		// RFC 9000 §14.1: Client Initial must be padded to >= 1200 bytes
		if c.isClient && pktType == PacketTypeInitial && len(packet) < 1200 {
			padNeed := 1200 - len(packet)
			padFrame := PaddingFrame{Length: padNeed}
			payload = padFrame.Append(payload)
			hdr = AppendLongHeader(nil, pktType, Version1, remoteCID, localCID, nil, pn, 2, len(payload))
			packet = SealPacket(hdr, payload)
		}
	}

	_, _ = c.endpoint.socket.WriteToUDP(packet, c.remoteAddr)
}

func (c *Connection) flushOutbound() {
	c.mu.Lock()
	if c.state != stateEstablished {
		c.mu.Unlock()
		return
	}

	var framesToSend []Frame

	// Include ACK if scheduled
	if c.ackScheduled && c.hasPeerPN {
		ack := AckFrame{
			LargestAcked: c.largestPeerPN,
			AckDelay:     1,
			FirstRange:   0,
		}
		framesToSend = append(framesToSend, ack)
		c.ackScheduled = false
	}

	// Include pending frames (e.g. retransmissions)
	if len(c.pendingFrames) > 0 {
		framesToSend = append(framesToSend, c.pendingFrames...)
		c.pendingFrames = nil
	}

	// Take from send stream up to 1100 bytes (keeping packet < 1200)
	offset, chunk := c.sendStream.Take(1100)
	if len(chunk) > 0 {
		sf := StreamFrame{
			StreamID: 0,
			Offset:   offset,
			Fin:      false,
			Data:     chunk,
		}
		framesToSend = append(framesToSend, sf)
	}

	if len(framesToSend) == 0 {
		c.mu.Unlock()
		return
	}

	pn := c.nextSendPN
	c.nextSendPN++
	remoteCID := c.remoteCID

	c.inFlight[pn] = &inFlightPacket{
		pn:     pn,
		sentAt: time.Now(),
		frames: framesToSend,
	}
	c.mu.Unlock()

	var payload []byte
	for _, f := range framesToSend {
		payload = f.Append(payload)
	}
	hdr := AppendShortHeader(nil, remoteCID, pn, 2)
	packet := SealPacket(hdr, payload)
	_, _ = c.endpoint.socket.WriteToUDP(packet, c.remoteAddr)
}

func (c *Connection) handlePacket(hdr *Header, rawPayload []byte) {
	c.mu.Lock()
	if !c.hasPeerPN || hdr.PacketNumber > c.largestPeerPN {
		c.largestPeerPN = hdr.PacketNumber
		c.hasPeerPN = true
	}
	c.ackScheduled = true
	c.mu.Unlock()

	frames, err := ParseFrames(rawPayload)
	if err != nil {
		return
	}

	var hasStreamData bool
	for _, f := range frames {
		switch frame := f.(type) {
		case AckFrame:
			c.handleAck(frame)
		case CryptoFrame:
			c.handleCrypto(frame)
		case StreamFrame:
			if frame.StreamID == 0 {
				c.recvStream.Push(frame.Offset, frame.Data, frame.Fin)
				hasStreamData = true
			}
		case ConnectionCloseFrame:
			_ = c.Close()
			return
		case PingFrame:
			// PING forces an ACK
		}
	}

	if hasStreamData || c.ackScheduled {
		c.flushOutbound()
	}
}

func (c *Connection) handleAck(ack AckFrame) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for pn, pkt := range c.inFlight {
		if pn <= ack.LargestAcked {
			rtt := now.Sub(pkt.sentAt)
			if rtt > 0 && rtt < 5*time.Second {
				c.rttEstimate = (c.rttEstimate*7 + rtt) / 8
			}
			delete(c.inFlight, pn)
		}
	}
}

func (c *Connection) handleCrypto(crypto CryptoFrame) {
	tp, err := UnmarshalTransportParameters(crypto.Data)
	if err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(tp.InitialSourceCID) > 0 {
		c.remoteCID = append([]byte(nil), tp.InitialSourceCID...)
	}

	if c.isClient {
		if c.state == stateHandshaking {
			c.state = stateEstablished
			close(c.handshakeDone)
			// Reply with ACK
			c.ackScheduled = true
		}
	} else {
		// Server: when receiving Client Initial, reply with Server Initial/Handshake
		if c.state == stateInitial {
			c.state = stateEstablished
			serverParams := DefaultTransportParameters(c.localCID)
			serverParams.OriginalDestCID = c.remoteCID
			cryptoPayload := CryptoFrame{
				Offset: 0,
				Data:   serverParams.Marshal(),
			}
			c.mu.Unlock()
			c.sendPacketDirect([]Frame{cryptoPayload})
			c.mu.Lock()
			close(c.handshakeDone)
		}
	}
}

func (c *Connection) runRetransmitLoop(ctx context.Context) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.doneCh:
			return
		case <-ticker.C:
			c.mu.Lock()
			if c.state != stateEstablished {
				c.mu.Unlock()
				continue
			}

			now := time.Now()
			rto := c.rttEstimate * 2
			if rto < 100*time.Millisecond {
				rto = 100 * time.Millisecond
			}

			var lostFrames []Frame
			for pn, pkt := range c.inFlight {
				if now.Sub(pkt.sentAt) > rto {
					for _, f := range pkt.frames {
						if sf, ok := f.(StreamFrame); ok {
							lostFrames = append(lostFrames, sf)
						}
					}
					delete(c.inFlight, pn)
				}
			}

			if len(lostFrames) > 0 {
				c.pendingFrames = append(c.pendingFrames, lostFrames...)
			}
			c.mu.Unlock()

			if len(lostFrames) > 0 {
				c.flushOutbound()
			}
		}
	}
}

// Endpoint manages a UDP socket and routes QUIC packets to connections.
type Endpoint struct {
	socket *net.UDPConn

	mu     sync.RWMutex
	conns  map[string]*Connection // keyed by localCID string
	byPeer map[string]*Connection // keyed by remote address string
	accept chan *Connection
	closed atomic.Bool
	doneCh chan struct{}
}

// NewEndpointWithSocket creates an Endpoint wrapping an existing bound UDP socket.
func NewEndpointWithSocket(socket *net.UDPConn) *Endpoint {
	ep := &Endpoint{
		socket: socket,
		conns:  make(map[string]*Connection),
		byPeer: make(map[string]*Connection),
		accept: make(chan *Connection, 128),
		doneCh: make(chan struct{}),
	}
	go ep.readLoop()
	return ep
}

// Done returns a channel closed when the endpoint is closed.
func (ep *Endpoint) Done() <-chan struct{} {
	return ep.doneCh
}

// LocalAddr returns the bound UDP address of the endpoint.
func (ep *Endpoint) LocalAddr() net.Addr {
	return ep.socket.LocalAddr()
}

// ListenEndpoint binds a UDP socket for listening and serving QUIC connections.
func ListenEndpoint(addr *net.UDPAddr) (*Endpoint, error) {
	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return NewEndpointWithSocket(socket), nil
}

// NewClientEndpoint creates an endpoint for outbound client dialing on an ephemeral port.
func NewClientEndpoint(local *net.UDPAddr) (*Endpoint, error) {
	if local == nil {
		local = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	socket, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, err
	}
	return NewEndpointWithSocket(socket), nil
}

// Accept returns the next accepted incoming connection.
func (ep *Endpoint) Accept(ctx context.Context) (*Connection, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ep.doneCh:
		return nil, net.ErrClosed
	case conn := <-ep.accept:
		return conn, nil
	}
}

// Dial initiates a new QUIC connection to remote.
func (ep *Endpoint) Dial(ctx context.Context, remote *net.UDPAddr) (*Connection, error) {
	localCID := make([]byte, 8)
	remoteCID := make([]byte, 8)
	_, _ = rand.Read(localCID)
	_, _ = rand.Read(remoteCID)

	conn := newConnection(ep, remote, true, localCID, remoteCID)
	ep.addConn(conn)

	// Send Client Initial
	clientParams := DefaultTransportParameters(localCID)
	cryptoFrame := CryptoFrame{
		Offset: 0,
		Data:   clientParams.Marshal(),
	}

	conn.mu.Lock()
	conn.state = stateHandshaking
	conn.mu.Unlock()

	conn.sendPacketDirect([]Frame{cryptoFrame})
	go conn.runRetransmitLoop(ctx)

	// Wait for handshake completion
	if err := conn.WaitHandshake(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFail, err)
	}

	return conn, nil
}

// Close closes the endpoint.
func (ep *Endpoint) Close() error {
	if ep.closed.CompareAndSwap(false, true) {
		close(ep.doneCh)
		_ = ep.socket.Close()
		ep.mu.Lock()
		conns := make([]*Connection, 0, len(ep.conns))
		for _, c := range ep.conns {
			conns = append(conns, c)
		}
		ep.conns = nil
		ep.byPeer = nil
		ep.mu.Unlock()

		for _, c := range conns {
			_ = c.Close()
		}
	}
	return nil
}

func (ep *Endpoint) addConn(c *Connection) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.conns != nil {
		ep.conns[string(c.localCID)] = c
	}
	if ep.byPeer != nil {
		ep.byPeer[c.remoteAddr.String()] = c
	}
}

func (ep *Endpoint) removeConn(c *Connection) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.conns != nil {
		delete(ep.conns, string(c.localCID))
	}
	if ep.byPeer != nil {
		delete(ep.byPeer, c.remoteAddr.String())
	}
}

func (ep *Endpoint) getConn(destCID []byte, remote *net.UDPAddr) *Connection {
	ep.mu.RLock()
	defer ep.mu.RUnlock()

	// 1. Try by DestCID
	if c, ok := ep.conns[string(destCID)]; ok {
		return c
	}
	// 2. Fall back by remote address
	if c, ok := ep.byPeer[remote.String()]; ok {
		return c
	}
	return nil
}

func (ep *Endpoint) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, remote, err := ep.socket.ReadFromUDP(buf)
		if err != nil {
			if ep.closed.Load() {
				return
			}
			continue
		}

		packet := buf[:n]
		hdr, payloadWithTag, err := ParseHeader(packet, 8, 0)
		if err != nil {
			continue
		}

		payload, err := VerifyAndSplitPayload(packet[:hdr.HeaderLen], payloadWithTag)
		if err != nil {
			// Checksum mismatch, drop
			continue
		}

		conn := ep.getConn(hdr.DestCID, remote)
		if conn == nil {
			// Inbound new connection (Server Initial)
			if hdr.IsLongHeader && hdr.Type == PacketTypeInitial {
				localCID := make([]byte, 8)
				_, _ = rand.Read(localCID)
				conn = newConnection(ep, remote, false, localCID, hdr.SrcCID)
				ep.addConn(conn)

				ctx, cancel := context.WithCancel(context.Background())
				go func() {
					<-conn.Done()
					cancel()
				}()
				go conn.runRetransmitLoop(ctx)

				conn.handlePacket(hdr, payload)

				select {
				case ep.accept <- conn:
				default:
				}
				continue
			}
			// Unknown connection, drop
			continue
		}

		conn.handlePacket(hdr, payload)
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package stun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// NAT behavior detection constants.
const (
	// DefaultSTUNPort is the port used when a server entry omits one.
	DefaultSTUNPort = 3478
	// probeResponseTimeout bounds one binding request/response exchange.
	probeResponseTimeout = 3 * time.Second
	// probeRepeat is how many times each request is repeated to survive loss.
	probeRepeat = 2
	// tcpConnectTimeout and tcpIOTimeout bound TCP STUN exchanges.
	tcpConnectTimeout = 1500 * time.Millisecond
	tcpIOTimeout      = 3 * time.Second
	// maxSTUNMessage bounds accepted STUN message sizes.
	maxSTUNMessage = 1620
	// easySymMaxPortGap is the largest mapped-port delta still considered
	// "easy" symmetric allocation.
	easySymMaxPortGap = 100
	// symMaxPortSpread is the mapped-port spread above which a NAT is
	// classified as (hard) symmetric.
	symMaxPortSpread = 15
	// minDistinctServers is the number of distinct responding STUN servers
	// required for a classification other than unknown.
	minDistinctServers = 2
	// maxTCPSamples caps how many successful TCP probes are collected.
	maxTCPSamples = 3
)

// STUN message types and attributes (RFC 5389 plus legacy behavior probes).
const (
	stunBindingRequest  = 0x0001
	stunBindingSuccess  = 0x0101
	attrMappedAddress   = 0x0001
	attrChangedAddress  = 0x0005
	attrXORMappedAddr   = 0x0020
	attrChangeRequest   = 0x8028
	attrOtherAddress    = 0x802c
	changeRequestFlagIP = 0x04
	changeRequestFlagPT = 0x02
)

var errNoMappedAddress = errors.New("STUN response has no mapped address")

// BindResponse records the outcome of one behavior probe.
type BindResponse struct {
	// LocalAddr is the bound address of the probing socket.
	LocalAddr netip.AddrPort
	// ServerAddr is the STUN server the request targeted.
	ServerAddr netip.AddrPort
	// RecvFromAddr is the address the response was actually received from;
	// it differs from ServerAddr when the server honored a change request.
	RecvFromAddr netip.AddrPort
	// MappedAddr is the external mapping reported for the probing socket.
	MappedAddr netip.AddrPort
	// MappedValid reports whether MappedAddr was present.
	MappedValid bool
	// ChangedAddr is the alternate address advertised by the server.
	ChangedAddr netip.AddrPort
	// ChangedValid reports whether ChangedAddr was present.
	ChangedValid bool
	// ChangeIP and ChangePort echo the requested change flags.
	ChangeIP, ChangePort bool
	// RealIPChanged and RealPortChanged report whether the response arrived
	// from a different IP or port than the queried server.
	RealIPChanged, RealPortChanged bool
	// LatencyUS is the round-trip latency in microseconds.
	LatencyUS uint32
}

// DetectResult is the aggregate of one detection round over all servers.
type DetectResult struct {
	// Transport is "udp" or "tcp".
	Transport string
	// SourceAddr is the local socket address used for probing.
	SourceAddr netip.AddrPort
	// Responses holds every successful probe.
	Responses []BindResponse
	// ExtraBind holds the additional single binding from a fresh socket,
	// collected to classify easy symmetric allocation.
	ExtraBind *BindResponse
}

// Transport names for DetectResult.
const (
	TransportUDP = "udp"
	TransportTCP = "tcp"
)

// NATType returns the classified NAT type for the transport.
func (r *DetectResult) NATType() int {
	if r.Transport == TransportTCP {
		return r.natTypeTCP()
	}
	return r.natTypeUDP()
}

func (r *DetectResult) hasIPChanged() bool {
	for i := range r.Responses {
		if r.Responses[i].RealIPChanged {
			return true
		}
	}
	return false
}

func (r *DetectResult) hasPortChanged() bool {
	for i := range r.Responses {
		if r.Responses[i].RealPortChanged {
			return true
		}
	}
	return false
}

func (r *DetectResult) isOpenInternet() bool {
	for i := range r.Responses {
		if r.Responses[i].MappedValid && r.Responses[i].MappedAddr == r.SourceAddr {
			return true
		}
	}
	return false
}

func (r *DetectResult) isNoPAT() bool {
	for i := range r.Responses {
		if r.Responses[i].MappedValid && r.Responses[i].MappedAddr.Port() == r.SourceAddr.Port() {
			return true
		}
	}
	return false
}

// distinctServerCount counts distinct addresses responses arrived from.
func (r *DetectResult) distinctServerCount() int {
	seen := make(map[netip.AddrPort]struct{}, len(r.Responses))
	for i := range r.Responses {
		seen[r.Responses[i].RecvFromAddr] = struct{}{}
	}
	return len(seen)
}

func (r *DetectResult) isCone() bool {
	seen := make(map[netip.AddrPort]struct{}, len(r.Responses))
	for i := range r.Responses {
		if r.Responses[i].MappedValid {
			seen[r.Responses[i].MappedAddr] = struct{}{}
		}
	}
	return len(seen) == 1
}

// PublicIPs returns the deduplicated public addresses seen in mappings.
func (r *DetectResult) PublicIPs() []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	var ips []netip.Addr
	for i := range r.Responses {
		if !r.Responses[i].MappedValid {
			continue
		}
		addr := r.Responses[i].MappedAddr.Addr()
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		ips = append(ips, addr)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	return ips
}

// AvailableServers returns the STUN servers that responded, in probe order.
func (r *DetectResult) AvailableServers() []netip.AddrPort {
	var servers []netip.AddrPort
	seen := make(map[netip.AddrPort]struct{})
	for i := range r.Responses {
		if _, ok := seen[r.Responses[i].ServerAddr]; ok {
			continue
		}
		seen[r.Responses[i].ServerAddr] = struct{}{}
		servers = append(servers, r.Responses[i].ServerAddr)
	}
	return servers
}

func (r *DetectResult) minPort() uint16 {
	port := uint16(0)
	for i := range r.Responses {
		if !r.Responses[i].MappedValid {
			continue
		}
		p := r.Responses[i].MappedAddr.Port()
		if port == 0 || p < port {
			port = p
		}
	}
	return port
}

func (r *DetectResult) maxPort() uint16 {
	port := uint16(0)
	for i := range r.Responses {
		if !r.Responses[i].MappedValid {
			continue
		}
		p := r.Responses[i].MappedAddr.Port()
		if p > port {
			port = p
		}
	}
	return port
}

func (r *DetectResult) usableResponseCount() int {
	count := 0
	for i := range r.Responses {
		if r.Responses[i].MappedValid {
			count++
		}
	}
	return count
}

// NatType values mirror the common.NatType proto enumeration.
const (
	NatTypeUnknown          = 0
	NatTypeOpenInternet     = 1
	NatTypeNoPAT            = 2
	NatTypeFullCone         = 3
	NatTypeRestricted       = 4
	NatTypePortRestricted   = 5
	NatTypeSymmetric        = 6
	NatTypeSymUdpFirewall   = 7
	NatTypeSymmetricEasyInc = 8
	NatTypeSymmetricEasyDec = 9
)

func (r *DetectResult) natTypeUDP() int {
	if r.distinctServerCount() < minDistinctServers {
		return NatTypeUnknown
	}

	if r.isCone() {
		switch {
		case r.hasIPChanged():
			switch {
			case r.isOpenInternet():
				return NatTypeOpenInternet
			case r.isNoPAT():
				return NatTypeNoPAT
			default:
				return NatTypeFullCone
			}
		case r.hasPortChanged():
			return NatTypeRestricted
		default:
			return NatTypePortRestricted
		}
	}

	if len(r.Responses) == 0 {
		return NatTypeUnknown
	}

	// Symmetric family: mappings vary per destination.
	if len(r.PublicIPs()) != 1 || r.usableResponseCount() <= 1 || int(r.maxPort())-int(r.minPort()) > symMaxPortSpread {
		return NatTypeSymmetric
	}
	if r.ExtraBind != nil && r.ExtraBind.MappedValid {
		extra := r.ExtraBind.MappedAddr.Port()
		above := int(extra) - int(r.maxPort())
		below := int(r.minPort()) - int(extra)
		if above > 0 && above < easySymMaxPortGap {
			return NatTypeSymmetricEasyInc
		}
		if below > 0 && below < easySymMaxPortGap {
			return NatTypeSymmetricEasyDec
		}
	}
	return NatTypeSymmetric
}

func (r *DetectResult) natTypeTCP() int {
	if r.isOpenInternet() {
		return NatTypeOpenInternet
	}
	if r.distinctServerCount() < minDistinctServers || len(r.Responses) == 0 {
		return NatTypeUnknown
	}
	if r.isCone() {
		if r.isNoPAT() {
			return NatTypeNoPAT
		}
		return NatTypeFullCone
	}
	return NatTypeSymmetric
}

// buildBindingRequest serializes one Binding request carrying CHANGE-REQUEST.
func buildBindingRequest(transactionID [12]byte, changeIP, changePort bool) []byte {
	attributes := 0
	if changeIP || changePort {
		attributes = 8
	}
	message := make([]byte, 20+attributes)
	binary.BigEndian.PutUint16(message[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(message[2:4], uint16(attributes))
	binary.BigEndian.PutUint32(message[4:8], magicCookie)
	copy(message[8:20], transactionID[:])
	if attributes > 0 {
		binary.BigEndian.PutUint16(message[20:22], attrChangeRequest)
		binary.BigEndian.PutUint16(message[22:24], 4)
		flags := 0
		if changeIP {
			flags |= changeRequestFlagIP
		}
		if changePort {
			flags |= changeRequestFlagPT
		}
		binary.BigEndian.PutUint32(message[24:28], uint32(flags))
	}
	return message
}

// parseBindingResponse decodes one success response of interest.
func parseBehaviorResponse(message []byte, transactionID [12]byte) (mapped, changed netip.AddrPort, mappedOK, changedOK bool, err error) {
	if len(message) < 20 {
		return netip.AddrPort{}, netip.AddrPort{}, false, false, errors.New("STUN message shorter than header")
	}
	messageType := binary.BigEndian.Uint16(message[0:2])
	if messageType != stunBindingSuccess {
		return netip.AddrPort{}, netip.AddrPort{}, false, false, errors.New("STUN message is not a binding success response")
	}
	if binary.BigEndian.Uint32(message[4:8]) != magicCookie {
		return netip.AddrPort{}, netip.AddrPort{}, false, false, errors.New("STUN message has an invalid magic cookie")
	}
	if !sameTransactionID(message[8:20], transactionID) {
		return netip.AddrPort{}, netip.AddrPort{}, false, false, errors.New("STUN message has an unexpected transaction ID")
	}
	length := int(binary.BigEndian.Uint16(message[2:4]))
	if length%4 != 0 || 20+length > len(message) {
		return netip.AddrPort{}, netip.AddrPort{}, false, false, errors.New("STUN message has an invalid length")
	}

	offset := 20
	for offset+4 <= 20+length {
		attributeType := binary.BigEndian.Uint16(message[offset : offset+2])
		attributeLength := int(binary.BigEndian.Uint16(message[offset+2 : offset+4]))
		offset += 4
		if attributeLength < 0 || offset+attributeLength > 20+length {
			return netip.AddrPort{}, netip.AddrPort{}, false, false, errors.New("STUN attribute exceeds message length")
		}
		value := message[offset : offset+attributeLength]
		offset += (attributeLength + 3) &^ 3

		switch attributeType {
		case attrMappedAddress, attrXORMappedAddr:
			if mappedOK {
				continue
			}
			if mapped, mappedOK, err = decodeAddressAttribute(attributeType, value, transactionID); err != nil {
				return netip.AddrPort{}, netip.AddrPort{}, false, false, err
			}
		case attrChangedAddress, attrOtherAddress:
			if changedOK {
				continue
			}
			if changed, changedOK, err = decodeAddressAttribute(attrMappedAddress, value, transactionID); err != nil {
				return netip.AddrPort{}, netip.AddrPort{}, false, false, err
			}
		}
	}
	if !mappedOK {
		return netip.AddrPort{}, netip.AddrPort{}, false, false, errNoMappedAddress
	}
	return mapped, changed, mappedOK, changedOK, nil
}

func sameTransactionID(got []byte, want [12]byte) bool {
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// decodeAddressAttribute decodes MAPPED-ADDRESS style values. XOR decoding
// applies only when xor is true.
func decodeAddressAttribute(attributeType uint16, value []byte, transactionID [12]byte) (netip.AddrPort, bool, error) {
	if len(value) < 4 || value[0] != 0 {
		return netip.AddrPort{}, false, errors.New("STUN address attribute has an invalid value")
	}
	port := binary.BigEndian.Uint16(value[2:4])
	var addr netip.Addr
	switch value[1] {
	case 0x01:
		if len(value) != 8 {
			return netip.AddrPort{}, false, errors.New("STUN IPv4 address attribute has an invalid length")
		}
		var raw [4]byte
		copy(raw[:], value[4:8])
		addr = netip.AddrFrom4(raw)
	case 0x02:
		if len(value) != 20 {
			return netip.AddrPort{}, false, errors.New("STUN IPv6 address attribute has an invalid length")
		}
		var raw [16]byte
		copy(raw[:], value[4:20])
		addr = netip.AddrFrom16(raw)
	default:
		return netip.AddrPort{}, false, errors.New("STUN address attribute has an unknown family")
	}
	if attributeType == attrXORMappedAddr {
		port ^= uint16(magicCookie >> 16)
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[:4], magicCookie)
		copy(mask[4:], transactionID[:])
		raw := addr.As16()
		for i := range raw {
			raw[i] ^= mask[i]
		}
		if addr.Is4() {
			addr = netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]})
		} else {
			addr = netip.AddrFrom16(raw)
		}
	}
	return netip.AddrPortFrom(addr, port), true, nil
}

func newTransactionID() [12]byte {
	var id [12]byte
	_, _ = rand.Read(id[:])
	return id
}

// responseDemux broadcasts datagrams received on one socket to all probes.
type responseDemux struct {
	mu      sync.Mutex
	closed  bool
	subs    map[chan responsePacket]struct{}
	stopped chan struct{}
}

type responsePacket struct {
	data []byte
	from netip.AddrPort
}

func newResponseDemux() *responseDemux {
	return &responseDemux{
		subs:    make(map[chan responsePacket]struct{}),
		stopped: make(chan struct{}),
	}
}

func (d *responseDemux) subscribe() chan responsePacket {
	ch := make(chan responsePacket, 64)
	d.mu.Lock()
	d.subs[ch] = struct{}{}
	d.mu.Unlock()
	return ch
}

func (d *responseDemux) unsubscribe(ch chan responsePacket) {
	d.mu.Lock()
	delete(d.subs, ch)
	d.mu.Unlock()
}

func (d *responseDemux) broadcast(data []byte, from netip.AddrPort) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	for ch := range d.subs {
		select {
		case ch <- responsePacket{data: append([]byte(nil), data...), from: from}:
		default:
		}
	}
	d.mu.Unlock()
}

func (d *responseDemux) close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	for ch := range d.subs {
		close(ch)
		delete(d.subs, ch)
	}
	d.mu.Unlock()
	close(d.stopped)
}

// udpDetect runs one detection round on socket against every server. Each
// server gets three concurrent probes: no change, change port, change both.
// The socket stays open afterwards with a cleared read deadline.
func udpDetect(ctx context.Context, socket *net.UDPConn, servers []netip.AddrPort) (*DetectResult, error) {
	local, err := netip.ParseAddrPort(socket.LocalAddr().String())
	if err != nil {
		return nil, fmt.Errorf("parse probe socket local address: %w", err)
	}
	result := &DetectResult{Transport: TransportUDP, SourceAddr: local}

	demux := newResponseDemux()
	reader := startProbeReader(socket, demux)
	defer func() {
		reader.Stop()
		demux.close()
	}()

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, server := range servers {
		for _, change := range [3][2]bool{{false, false}, {false, true}, {true, true}} {
			wg.Add(1)
			go func(server netip.AddrPort, changeIP, changePort bool) {
				defer wg.Done()
				response, err := udpBindRequest(ctx, socket, demux, server, changeIP, changePort)
				if err != nil {
					return
				}
				mu.Lock()
				result.Responses = append(result.Responses, response)
				mu.Unlock()
			}(server, change[0], change[1])
		}
	}
	wg.Wait()
	return result, nil
}

// probeReader forwards datagrams from one socket into a demux until stopped.
// It polls with short read deadlines so Stop never has to close a socket the
// caller may keep using; Stop restores a clear read deadline on exit.
type probeReader struct {
	socket *net.UDPConn
	stop   chan struct{}
	done   chan struct{}
}

// probeReaderPollInterval bounds how long Stop waits for the read loop.
const probeReaderPollInterval = 100 * time.Millisecond

func startProbeReader(socket *net.UDPConn, demux *responseDemux) *probeReader {
	reader := &probeReader{socket: socket, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(reader.done)
		buffer := make([]byte, maxSTUNMessage)
		for {
			_ = socket.SetReadDeadline(time.Now().Add(probeReaderPollInterval))
			n, from, err := socket.ReadFromUDP(buffer)
			if err == nil {
				if fromAddr, ok := udpAddrToAddrPort(from); ok {
					demux.broadcast(buffer[:n], fromAddr)
				}
				continue
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				select {
				case <-reader.stop:
					return
				default:
				}
				continue
			}
			return
		}
	}()
	return reader
}

// Stop waits for the read loop to exit and clears the read deadline.
func (r *probeReader) Stop() {
	close(r.stop)
	<-r.done
	_ = r.socket.SetReadDeadline(time.Time{})
}

func udpAddrToAddrPort(addr *net.UDPAddr) (netip.AddrPort, bool) {
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)), true
}

// udpBindRequest sends one binding request (repeated for loss resilience)
// and waits for the matching response.
func udpBindRequest(ctx context.Context, socket *net.UDPConn, demux *responseDemux, server netip.AddrPort, changeIP, changePort bool) (BindResponse, error) {
	ids := make([][12]byte, 0, probeRepeat)
	for i := 0; i < probeRepeat; i++ {
		id := newTransactionID()
		ids = append(ids, id)
		request := buildBindingRequest(id, changeIP, changePort)
		target := &net.UDPAddr{IP: net.IP(server.Addr().AsSlice()), Port: int(server.Port())}
		if _, err := socket.WriteToUDP(request, target); err != nil {
			return BindResponse{}, fmt.Errorf("send STUN binding request: %w", err)
		}
	}

	start := time.Now()
	deadline := time.Now().Add(probeResponseTimeout)
	subscription := demux.subscribe()
	defer demux.unsubscribe(subscription)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return BindResponse{}, errors.New("STUN binding request timed out")
		}
		if err := ctx.Err(); err != nil {
			return BindResponse{}, err
		}
		select {
		case packet, ok := <-subscription:
			if !ok {
				return BindResponse{}, errors.New("STUN probe socket closed")
			}
			if len(packet.data) < 20 {
				continue
			}
			var id [12]byte
			copy(id[:], packet.data[8:20])
			matched := false
			for _, candidate := range ids {
				if candidate == id {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			mapped, changed, mappedOK, changedOK, err := parseBehaviorResponse(packet.data, id)
			if err != nil {
				continue
			}
			return BindResponse{
				LocalAddr:       udpLocalAddr(socket),
				ServerAddr:      server,
				RecvFromAddr:    packet.from,
				MappedAddr:      mapped,
				MappedValid:     mappedOK,
				ChangedAddr:     changed,
				ChangedValid:    changedOK,
				ChangeIP:        changeIP,
				ChangePort:      changePort,
				RealIPChanged:   packet.from.Addr() != server.Addr(),
				RealPortChanged: packet.from.Port() != server.Port(),
				LatencyUS:       uint32(time.Since(start).Microseconds()),
			}, nil
		case <-time.After(remaining):
			return BindResponse{}, errors.New("STUN binding request timed out")
		case <-ctx.Done():
			return BindResponse{}, ctx.Err()
		}
	}
}

func udpLocalAddr(socket *net.UDPConn) netip.AddrPort {
	local, err := netip.ParseAddrPort(socket.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}
	}
	return local
}

// tcpBindRequest performs one TCP STUN binding with a source-port-bound
// connection.
func tcpBindRequest(ctx context.Context, server netip.AddrPort, sourcePort uint16) (BindResponse, error) {
	bindAddr := &net.TCPAddr{Port: int(sourcePort)}
	if server.Addr().Is4() {
		bindAddr.IP = net.IPv4zero
	} else {
		bindAddr.IP = net.IPv6zero
	}
	dialer := net.Dialer{LocalAddr: bindAddr, Timeout: tcpConnectTimeout}
	address := &net.TCPAddr{IP: net.IP(server.Addr().AsSlice()), Port: int(server.Port())}
	conn, err := dialer.DialContext(ctx, "tcp", address.String())
	if err != nil {
		return BindResponse{}, fmt.Errorf("dial TCP STUN server: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(tcpIOTimeout)
	_ = conn.SetDeadline(deadline)

	id := newTransactionID()
	request := buildBindingRequest(id, false, false)
	if _, err := conn.Write(request); err != nil {
		return BindResponse{}, fmt.Errorf("send TCP STUN request: %w", err)
	}

	response, err := readTCPSTUNMessage(conn)
	if err != nil {
		return BindResponse{}, err
	}
	mapped, _, mappedOK, _, err := parseBehaviorResponse(response, id)
	if err != nil {
		return BindResponse{}, err
	}
	localAddr, _ := netip.ParseAddrPort(conn.LocalAddr().String())
	return BindResponse{
		LocalAddr:    localAddr,
		ServerAddr:   server,
		RecvFromAddr: server,
		MappedAddr:   mapped,
		MappedValid:  mappedOK,
	}, nil
}

func readTCPSTUNMessage(conn net.Conn) ([]byte, error) {
	header := make([]byte, 20)
	if err := readFull(conn, header); err != nil {
		return nil, err
	}
	if header[0]&0xC0 != 0 {
		return nil, errors.New("STUN TCP message has an invalid type")
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length%4 != 0 {
		return nil, errors.New("STUN TCP message has an invalid length")
	}
	total := 20 + length
	if total > 4096 {
		return nil, errors.New("STUN TCP message is too large")
	}
	message := make([]byte, total)
	copy(message, header)
	if total > 20 {
		if err := readFull(conn, message[20:]); err != nil {
			return nil, err
		}
	}
	return message, nil
}

func readFull(conn net.Conn, buffer []byte) error {
	read := 0
	for read < len(buffer) {
		n, err := conn.Read(buffer[read:])
		if err != nil {
			return err
		}
		read += n
	}
	return nil
}

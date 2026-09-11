// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package dns implements the authoritative Magic DNS UDP server.
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultZone = "et.net"
	maxDatagram = 1232

	typeA    = 1
	typeAAAA = 28
	classIN  = 1

	rcodeFormatError = 1
	rcodeNameError   = 3
	rcodeRefused     = 5
)

// Config configures an authoritative Magic DNS server.
type Config struct {
	Address         string
	Zone            string
	TTL             uint32
	Records         map[string][]netip.Addr
	Upstreams       []string
	UpstreamTimeout time.Duration
}

// Server is an authoritative UDP DNS server for one zone.
type Server struct {
	conn            *net.UDPConn
	zone            string
	ttl             uint32
	records         map[string]recordEntry
	upstreams       []upstreamState
	upstreamTimeout time.Duration

	mu        sync.RWMutex
	closed    bool
	serving   bool
	closeOnce sync.Once
	closeErr  error
}

type recordEntry struct {
	addresses []netip.Addr
	ttl       uint32
	expiresAt time.Time
}

type upstreamState struct {
	address     string
	state       string
	queries     uint64
	successes   uint64
	failures    uint64
	lastError   string
	lastChecked time.Time
}

// Record is a stable snapshot of one authoritative DNS name.
type Record struct {
	Name      string
	Addresses []netip.Addr
	TTL       uint32
	ExpiresAt time.Time
}

// UpstreamStatus is the observed state of one configured recursive upstream.
type UpstreamStatus struct {
	Address     string
	State       string
	Queries     uint64
	Successes   uint64
	Failures    uint64
	LastError   string
	LastChecked time.Time
}

// Status is a point-in-time DNS runtime snapshot.
type Status struct {
	Address         string
	Zone            string
	TTL             uint32
	Serving         bool
	Closed          bool
	UpstreamTimeout time.Duration
	Upstreams       []UpstreamStatus
}

type question struct {
	name     string
	typeCode uint16
	class    uint16
	wire     []byte
}

// NewServer binds a UDP socket and initializes a server from config.
func NewServer(config Config) (*Server, error) {
	if config.Address == "" {
		return nil, errors.New("DNS listen address is required")
	}
	zone, err := normalizeName(config.Zone)
	if config.Zone == "" {
		zone = defaultZone
		err = nil
	}
	if err != nil || zone == "" {
		return nil, fmt.Errorf("invalid DNS zone %q", config.Zone)
	}
	addr, err := net.ResolveUDPAddr("udp", config.Address)
	if err != nil {
		return nil, fmt.Errorf("resolve DNS listen address %q: %w", config.Address, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen for DNS on %q: %w", config.Address, err)
	}

	upstreamTimeout := config.UpstreamTimeout
	if upstreamTimeout <= 0 {
		upstreamTimeout = 2 * time.Second
	}
	server := &Server{
		conn:            conn,
		zone:            zone,
		ttl:             config.TTL,
		records:         make(map[string]recordEntry, len(config.Records)),
		upstreams:       make([]upstreamState, len(config.Upstreams)),
		upstreamTimeout: upstreamTimeout,
	}
	for i, address := range config.Upstreams {
		server.upstreams[i] = upstreamState{address: address, state: "unknown"}
	}
	for name, addresses := range config.Records {
		if err := server.SetRecord(name, addresses...); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("DNS record %q: %w", name, err)
		}
	}
	return server, nil
}

// Address returns the bound UDP address.
func (s *Server) Address() net.Addr { return s.conn.LocalAddr() }

// Zone returns the normalized authoritative zone.
func (s *Server) Zone() string {
	if s == nil {
		return ""
	}
	return s.zone
}

// Records returns all records sorted by name.
func (s *Server) Records() []Record {
	if s == nil {
		return []Record{}
	}
	s.mu.RLock()
	result := make([]Record, 0, len(s.records))
	now := time.Now()
	for name, entry := range s.records {
		if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
			continue
		}
		ttl := entry.ttl
		if !entry.expiresAt.IsZero() {
			remaining := time.Until(entry.expiresAt)
			if remaining <= 0 {
				continue
			}
			ttl = uint32((remaining + time.Second - 1) / time.Second)
		}
		result = append(result, Record{Name: name, Addresses: append([]netip.Addr(nil), entry.addresses...), TTL: ttl, ExpiresAt: entry.expiresAt})
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// Status returns listener, TTL, serving and upstream health state.
func (s *Server) Status() Status {
	if s == nil {
		return Status{}
	}
	s.mu.RLock()
	result := Status{
		Zone:            s.zone,
		TTL:             s.ttl,
		Serving:         s.serving,
		Closed:          s.closed,
		UpstreamTimeout: s.upstreamTimeout,
		Upstreams:       make([]UpstreamStatus, len(s.upstreams)),
	}
	for i, upstream := range s.upstreams {
		result.Upstreams[i] = UpstreamStatus{Address: upstream.address, State: upstream.state, Queries: upstream.queries, Successes: upstream.successes, Failures: upstream.failures, LastError: upstream.lastError, LastChecked: upstream.lastChecked}
	}
	s.mu.RUnlock()
	if s.conn != nil {
		result.Address = s.conn.LocalAddr().String()
	}
	return result
}

// SetRecord replaces the addresses for an in-zone name.
func (s *Server) SetRecord(name string, addresses ...netip.Addr) error {
	return s.SetRecordWithTTL(name, s.ttl, addresses...)
}

// SetRecordWithTTL replaces a record and removes it after ttl. A zero ttl keeps
// the record until it is explicitly replaced or deleted.
func (s *Server) SetRecordWithTTL(name string, ttl uint32, addresses ...netip.Addr) error {
	name, err := normalizeName(name)
	if err != nil {
		return err
	}
	if !s.inZone(name) {
		return fmt.Errorf("DNS record name %q is outside zone %q", name, s.zone)
	}
	record := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() {
			return fmt.Errorf("invalid DNS address for %q", name)
		}
		record = append(record, address.Unmap())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if len(record) == 0 {
		delete(s.records, name)
		return nil
	}
	entry := recordEntry{addresses: record, ttl: ttl}
	if ttl > 0 {
		entry.expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
	}
	s.records[name] = entry
	return nil
}

// DeleteRecord removes an in-zone name.
func (s *Server) DeleteRecord(name string) error {
	return s.SetRecord(name)
}

// Serve processes DNS datagrams until ctx is canceled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("DNS server context is nil")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.serving {
		s.mu.Unlock()
		return errors.New("DNS server is already serving")
	}
	s.serving = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.serving = false
		s.mu.Unlock()
	}()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-stop:
		}
	}()

	buffer := make([]byte, maxDatagram+1)
	for {
		n, remote, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || s.isClosed() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read DNS datagram: %w", err)
		}
		if n > maxDatagram {
			continue
		}
		if response := s.respond(buffer[:n]); response != nil {
			_, _ = s.conn.WriteToUDP(response, remote)
		}
	}
}

// Close interrupts Serve and releases the UDP socket. It is idempotent.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.closeErr = s.conn.Close()
		s.mu.Unlock()
	})
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closeErr
}

func (s *Server) isClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

func (s *Server) inZone(name string) bool {
	return name == s.zone || strings.HasSuffix(name, "."+s.zone)
}

func (s *Server) forwardUpstream(packet []byte) []byte {
	for i := range s.upstreams {
		address := s.upstreams[i].address
		s.upstreamAttempt(i)
		if _, _, err := net.SplitHostPort(address); err != nil {
			address = net.JoinHostPort(address, "53")
		}
		remote, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			s.upstreamFailure(i, err)
			continue
		}
		conn, err := net.DialUDP("udp", nil, remote)
		if err != nil {
			s.upstreamFailure(i, err)
			continue
		}
		deadline := time.Now().Add(s.upstreamTimeout)
		_ = conn.SetDeadline(deadline)
		_, writeErr := conn.Write(packet)
		var buffer [maxDatagram + 1]byte
		n, readErr := conn.Read(buffer[:])
		_ = conn.Close()
		if writeErr != nil || readErr != nil || n < 12 || n > maxDatagram {
			err := writeErr
			if err == nil {
				err = readErr
			}
			if err == nil {
				err = errors.New("invalid upstream DNS response")
			}
			s.upstreamFailure(i, err)
			continue
		}
		if binary.BigEndian.Uint16(buffer[:2]) != binary.BigEndian.Uint16(packet[:2]) || binary.BigEndian.Uint16(buffer[2:])&0x8000 == 0 {
			s.upstreamFailure(i, errors.New("upstream DNS response does not match query"))
			continue
		}
		s.upstreamSuccess(i)
		return append([]byte(nil), buffer[:n]...)
	}
	return nil
}

func (s *Server) upstreamAttempt(index int) {
	s.mu.Lock()
	if index < len(s.upstreams) {
		s.upstreams[index].queries++
		s.upstreams[index].lastChecked = time.Now()
		s.upstreams[index].state = "checking"
	}
	s.mu.Unlock()
}

func (s *Server) upstreamSuccess(index int) {
	s.mu.Lock()
	if index < len(s.upstreams) {
		s.upstreams[index].successes++
		s.upstreams[index].state = "healthy"
		s.upstreams[index].lastError = ""
		s.upstreams[index].lastChecked = time.Now()
	}
	s.mu.Unlock()
}

func (s *Server) upstreamFailure(index int, err error) {
	s.mu.Lock()
	if index < len(s.upstreams) {
		s.upstreams[index].failures++
		s.upstreams[index].state = "unavailable"
		s.upstreams[index].lastError = err.Error()
		s.upstreams[index].lastChecked = time.Now()
	}
	s.mu.Unlock()
}

func (s *Server) respond(packet []byte) []byte {
	if len(packet) < 12 {
		return nil
	}
	id := binary.BigEndian.Uint16(packet)
	flags := binary.BigEndian.Uint16(packet[2:])
	if flags&0x8000 != 0 || flags&0x7800 != 0 {
		return s.errorResponse(id, flags, rcodeFormatError)
	}
	if binary.BigEndian.Uint16(packet[4:]) != 1 || binary.BigEndian.Uint16(packet[6:]) != 0 || binary.BigEndian.Uint16(packet[8:]) != 0 || binary.BigEndian.Uint16(packet[10:]) != 0 {
		return s.errorResponse(id, flags, rcodeFormatError)
	}
	q, err := parseQuestion(packet)
	if err != nil {
		return s.errorResponse(id, flags, rcodeFormatError)
	}
	if q.typeCode != typeA && q.typeCode != typeAAAA || q.class != classIN {
		return s.answerResponse(id, flags, q, nil, false, 0, 0)
	}
	if !s.inZone(q.name) {
		if response := s.forwardUpstream(packet); response != nil {
			return response
		}
		return s.answerResponse(id, flags, q, nil, false, rcodeRefused, 0)
	}

	s.mu.RLock()
	entry, exists := s.records[q.name]
	s.mu.RUnlock()
	if exists && !entry.expiresAt.IsZero() && !time.Now().Before(entry.expiresAt) {
		s.mu.Lock()
		if current, ok := s.records[q.name]; ok && current.expiresAt.Equal(entry.expiresAt) {
			delete(s.records, q.name)
		}
		s.mu.Unlock()
		exists = false
	}
	if !exists || len(entry.addresses) == 0 {
		return s.answerResponse(id, flags, q, nil, true, rcodeNameError, 0)
	}
	return s.answerResponse(id, flags, q, entry.addresses, true, 0, entry.ttl)
}

func (s *Server) errorResponse(id, requestFlags, rcode uint16) []byte {
	response := make([]byte, 12)
	binary.BigEndian.PutUint16(response, id)
	binary.BigEndian.PutUint16(response[2:], 0x8000|(requestFlags&0x0100)|rcode)
	return response
}

func (s *Server) answerResponse(id, requestFlags uint16, q question, addresses []netip.Addr, authoritative bool, rcode uint16, ttl uint32) []byte {
	response := make([]byte, 12, maxDatagram)
	response = append(response, q.wire...)
	flags := uint16(0x8000 | (requestFlags & 0x0100) | rcode)
	if authoritative {
		flags |= 0x0400
	}
	answerCount := uint16(0)
	truncated := false
	if rcode == 0 {
		for _, address := range addresses {
			data := address.AsSlice()
			if (q.typeCode == typeA && !address.Is4()) || (q.typeCode == typeAAAA && !address.Is6()) {
				continue
			}
			if len(response)+12+len(data) > maxDatagram {
				truncated = true
				break
			}
			response = append(response, 0xc0, 0x0c)
			response = appendUint16(response, q.typeCode)
			response = appendUint16(response, classIN)
			response = appendUint32(response, ttl)
			response = appendUint16(response, uint16(len(data)))
			response = append(response, data...)
			answerCount++
		}
	}
	if truncated {
		flags |= 0x0200
	}
	binary.BigEndian.PutUint16(response, id)
	binary.BigEndian.PutUint16(response[2:], flags)
	binary.BigEndian.PutUint16(response[4:], 1)
	binary.BigEndian.PutUint16(response[6:], answerCount)
	return response
}

func parseQuestion(packet []byte) (question, error) {
	name, end, err := parseName(packet, 12)
	if err != nil || end+4 != len(packet) {
		return question{}, errors.New("invalid DNS question")
	}
	return question{
		name:     name,
		typeCode: binary.BigEndian.Uint16(packet[end:]),
		class:    binary.BigEndian.Uint16(packet[end+2:]),
		wire:     append([]byte(nil), packet[12:]...),
	}, nil
}

func parseName(packet []byte, offset int) (string, int, error) {
	labels := make([]string, 0, 4)
	start := offset
	for {
		if offset >= len(packet) || offset-start >= 255 {
			return "", 0, errors.New("invalid DNS name")
		}
		length := int(packet[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || length&0xc0 != 0 || offset+length > len(packet) {
			return "", 0, errors.New("invalid DNS label")
		}
		labels = append(labels, strings.ToLower(string(packet[offset:offset+length])))
		offset += length
	}
	return strings.Join(labels, "."), offset, nil
}

func normalizeName(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" || len(name) > 253 {
		return "", errors.New("invalid DNS name")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "", errors.New("invalid DNS name")
		}
	}
	return name, nil
}

func appendUint16(buffer []byte, value uint16) []byte {
	return append(buffer, byte(value>>8), byte(value))
}

func appendUint32(buffer []byte, value uint32) []byte {
	return append(buffer, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

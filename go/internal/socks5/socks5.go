// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package socks5 implements a TCP SOCKS5 CONNECT proxy.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

const (
	version = 5

	methodNoAuth       = 0
	methodNoAcceptable = 0xff

	commandConnect = 1

	addressIPv4   = 1
	addressDomain = 3
	addressIPv6   = 4

	replySucceeded             = 0
	replyGeneralFailure        = 1
	replyCommandNotSupported   = 7
	replyAddressTypeNotSupport = 8
)

var ErrClosed = errors.New("SOCKS5 manager is closed")

// DialContextFunc establishes a connection to a SOCKS5 CONNECT destination.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Config configures a SOCKS5 manager.
type Config struct {
	ListenAddr  string
	DialContext DialContextFunc
}

// Manager owns a SOCKS5 TCP listener and all connections accepted by it.
type Manager struct {
	listenAddr string
	dial       DialContextFunc

	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	listener  net.Listener
	closed    bool
	conns     map[net.Conn]struct{}
	acceptWG  sync.WaitGroup
	connWG    sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

// NewManager creates an unstarted SOCKS5 manager. An empty ListenAddr uses a
// loopback ephemeral port. A nil DialContext uses net.Dialer.DialContext.
func NewManager(config Config) *Manager {
	if config.ListenAddr == "" {
		config.ListenAddr = "127.0.0.1:0"
	}
	if config.DialContext == nil {
		dialer := &net.Dialer{}
		config.DialContext = dialer.DialContext
	}
	return &Manager{
		listenAddr: config.ListenAddr,
		dial:       config.DialContext,
		conns:      make(map[net.Conn]struct{}),
	}
}

// Start begins accepting SOCKS5 connections. Canceling ctx closes the manager.
func (m *Manager) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	m.mu.Lock()
	m.initializeLocked()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if m.listener != nil {
		m.mu.Unlock()
		return nil
	}
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return err
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", m.listenAddr)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("listen on %q: %w", m.listenAddr, err)
	}
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.listener = listener
	m.acceptWG.Add(1)
	managerCtx := m.ctx
	m.mu.Unlock()

	go m.serve(listener)
	go func() {
		<-managerCtx.Done()
		_ = m.Close()
	}()
	return nil
}

func (m *Manager) initializeLocked() {
	if m.listenAddr == "" {
		m.listenAddr = "127.0.0.1:0"
	}
	if m.dial == nil {
		dialer := &net.Dialer{}
		m.dial = dialer.DialContext
	}
	if m.conns == nil {
		m.conns = make(map[net.Conn]struct{})
	}
}

// Addr returns the address on which the manager is listening, or nil before it
// has been started.
func (m *Manager) Addr() net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listener == nil {
		return nil
	}
	return m.listener.Addr()
}

// Close stops the listener and all active connections. It is idempotent.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.initializeLocked()
		m.closed = true
		if m.cancel != nil {
			m.cancel()
		}
		listener := m.listener
		connections := make([]net.Conn, 0, len(m.conns))
		for connection := range m.conns {
			connections = append(connections, connection)
		}
		m.mu.Unlock()

		if listener != nil {
			m.closeErr = listener.Close()
		}
		for _, connection := range connections {
			m.closeErr = errors.Join(m.closeErr, connection.Close())
		}
		m.acceptWG.Wait()
		m.connWG.Wait()
	})
	return m.closeErr
}

func (m *Manager) serve(listener net.Listener) {
	defer m.acceptWG.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		if !m.startConnection(connection) {
			_ = connection.Close()
			return
		}
		go func() {
			defer m.connWG.Done()
			defer m.untrack(connection)
			defer connection.Close()
			m.handle(connection)
		}()
	}
}

func (m *Manager) handle(client net.Conn) {
	if !negotiate(client) {
		return
	}
	address, reply, ok := readRequest(client)
	if !ok {
		_ = writeReply(client, replyGeneralFailure, nil)
		return
	}
	if reply != replySucceeded {
		_ = writeReply(client, reply, nil)
		return
	}

	upstream, err := m.dial(m.context(), "tcp", address)
	if err != nil {
		_ = writeReply(client, replyGeneralFailure, nil)
		return
	}
	if !m.track(upstream) {
		_ = upstream.Close()
		return
	}
	defer m.untrack(upstream)
	defer upstream.Close()

	if err := writeReply(client, replySucceeded, upstream.LocalAddr()); err != nil {
		return
	}
	copyBoth(client, upstream)
}

func (m *Manager) context() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ctx
}

func (m *Manager) track(connection net.Conn) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	m.conns[connection] = struct{}{}
	return true
}

func (m *Manager) startConnection(connection net.Conn) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	m.conns[connection] = struct{}{}
	m.connWG.Add(1)
	return true
}

func (m *Manager) untrack(connection net.Conn) {
	m.mu.Lock()
	delete(m.conns, connection)
	m.mu.Unlock()
}

func negotiate(connection net.Conn) bool {
	var header [2]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil || header[0] != version {
		return false
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return false
	}
	for _, method := range methods {
		if method == methodNoAuth {
			_, _ = connection.Write([]byte{version, methodNoAuth})
			return true
		}
	}
	_, _ = connection.Write([]byte{version, methodNoAcceptable})
	return false
}

func readRequest(connection net.Conn) (string, byte, bool) {
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return "", replyGeneralFailure, false
	}
	if header[0] != version || header[2] != 0 {
		return "", replyGeneralFailure, false
	}
	if header[1] != commandConnect {
		return "", replyCommandNotSupported, true
	}

	var host string
	switch header[3] {
	case addressIPv4:
		var address [4]byte
		if _, err := io.ReadFull(connection, address[:]); err != nil {
			return "", replyGeneralFailure, false
		}
		host = net.IP(address[:]).String()
	case addressIPv6:
		var address [16]byte
		if _, err := io.ReadFull(connection, address[:]); err != nil {
			return "", replyGeneralFailure, false
		}
		host = net.IP(address[:]).String()
	case addressDomain:
		var length [1]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil || length[0] == 0 {
			return "", replyGeneralFailure, false
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(connection, domain); err != nil {
			return "", replyGeneralFailure, false
		}
		host = string(domain)
	default:
		return "", replyAddressTypeNotSupport, true
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(connection, portBytes[:]); err != nil {
		return "", replyGeneralFailure, false
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes[:])))), replySucceeded, true
}

func writeReply(connection net.Conn, reply byte, bound net.Addr) error {
	address := net.IPv4zero
	port := 0
	if tcpAddress, ok := bound.(*net.TCPAddr); ok {
		if tcpAddress.IP != nil {
			address = tcpAddress.IP
		}
		port = tcpAddress.Port
	}

	if ipv4 := address.To4(); ipv4 != nil {
		response := make([]byte, 10)
		response[0] = version
		response[1] = reply
		response[3] = addressIPv4
		copy(response[4:8], ipv4)
		binary.BigEndian.PutUint16(response[8:10], uint16(port))
		_, err := connection.Write(response)
		return err
	}
	response := make([]byte, 22)
	response[0] = version
	response[1] = reply
	response[3] = addressIPv6
	copy(response[4:20], address.To16())
	binary.BigEndian.PutUint16(response[20:22], uint16(port))
	_, err := connection.Write(response)
	return err
}

func copyBoth(client, upstream net.Conn) {
	var closeBoth sync.Once
	closeConnections := func() {
		_ = client.Close()
		_ = upstream.Close()
	}
	copyDirection := func(destination, source net.Conn) {
		if _, err := io.Copy(destination, source); err != nil {
			closeBoth.Do(closeConnections)
			return
		}
		if writer, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = writer.CloseWrite()
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyDirection(upstream, client)
	}()
	go func() {
		defer wg.Done()
		copyDirection(client, upstream)
	}()
	wg.Wait()
}

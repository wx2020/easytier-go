// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/gorilla/websocket"
)

const websocketSessionQueueSize = 128

// WebSocketOptions controls websocket handshakes and peer message limits.
// Header is used for client handshake headers, CheckOrigin and ResponseHeader
// are used by a websocket listener. TLSClientConfig is used for wss dials;
// TLSServerConfig enables TLS for a listener's Serve method. BindDevice pins
// the underlying TCP sockets to a network interface.
type WebSocketOptions struct {
	MaxMessageSize  int
	CheckOrigin     func(*http.Request) bool
	Header          http.Header
	Origin          string
	ResponseHeader  http.Header
	TLSClientConfig *tls.Config
	TLSServerConfig *tls.Config
	BindDevice      string
}

// WSOptions is a short alias for WebSocketOptions.
type WSOptions = WebSocketOptions

// WebSocketPacketChannel adapts one EasyTier websocket connection to the
// packet-channel contract. Each binary websocket message is exactly one peer
// header followed by its payload; unlike stream transports, it has no length
// prefix.
type WebSocketPacketChannel struct {
	connection     *websocket.Conn
	maxMessageSize int
	readMu         sync.Mutex
	writeMu        sync.Mutex
	closeOnce      sync.Once
	done           chan struct{}
	onClose        func()
}

// NewWebSocketPacketChannel wraps an accepted or dialed websocket connection.
func NewWebSocketPacketChannel(connection *websocket.Conn, maxMessageSize int) (*WebSocketPacketChannel, error) {
	if connection == nil {
		return nil, fmt.Errorf("websocket connection is nil")
	}
	if maxMessageSize == 0 {
		maxMessageSize = protocol.DefaultMaxStreamFrameSize
	}
	if maxMessageSize < protocol.PeerManagerHeaderSize {
		return nil, fmt.Errorf("maximum websocket message size %d is too small", maxMessageSize)
	}
	connection.SetReadLimit(int64(maxMessageSize))
	return &WebSocketPacketChannel{
		connection:     connection,
		maxMessageSize: maxMessageSize,
		done:           make(chan struct{}),
	}, nil
}

// NewWSPacketChannel is a short alias for NewWebSocketPacketChannel.
func NewWSPacketChannel(connection *websocket.Conn, maxMessageSize int) (*WebSocketPacketChannel, error) {
	return NewWebSocketPacketChannel(connection, maxMessageSize)
}

// Send writes one binary EasyTier peer message. Concurrent writes are
// serialized because gorilla/websocket permits only one writer at a time.
func (c *WebSocketPacketChannel) Send(ctx context.Context, packet protocol.Packet) error {
	if ctx == nil {
		return errors.New("websocket send context is nil")
	}
	if err := c.checkContext(ctx); err != nil {
		return err
	}
	if err := lockWithContext(ctx, &c.writeMu); err != nil {
		return err
	}
	defer c.writeMu.Unlock()
	if err := c.checkContext(ctx); err != nil {
		return err
	}

	body, err := packet.MarshalBody()
	if err != nil {
		return fmt.Errorf("marshal websocket peer packet: %w", err)
	}
	if len(body) > c.maxMessageSize {
		return fmt.Errorf("websocket peer message exceeds limit: %d", len(body))
	}

	stop := interruptWebSocketWriteOnCancel(ctx, c.connection)
	defer stop()
	if err := setWebSocketWriteDeadline(ctx, c.connection); err != nil {
		return err
	}
	defer c.connection.SetWriteDeadline(time.Time{})
	if err := c.connection.WriteMessage(websocket.BinaryMessage, body); err != nil {
		return mapWebSocketContextError(ctx, err)
	}
	return nil
}

// Receive waits for the next binary EasyTier peer message.
func (c *WebSocketPacketChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	if ctx == nil {
		return protocol.Packet{}, errors.New("websocket receive context is nil")
	}
	if err := c.checkContext(ctx); err != nil {
		return protocol.Packet{}, err
	}
	if err := lockWithContext(ctx, &c.readMu); err != nil {
		return protocol.Packet{}, err
	}
	defer c.readMu.Unlock()
	if err := c.checkContext(ctx); err != nil {
		return protocol.Packet{}, err
	}

	stop := interruptWebSocketReadOnCancel(ctx, c.connection)
	defer stop()
	if err := setWebSocketReadDeadline(ctx, c.connection); err != nil {
		return protocol.Packet{}, err
	}
	defer c.connection.SetReadDeadline(time.Time{})
	messageType, body, err := c.connection.ReadMessage()
	if err != nil {
		return protocol.Packet{}, mapWebSocketContextError(ctx, err)
	}
	if messageType != websocket.BinaryMessage {
		return protocol.Packet{}, fmt.Errorf("websocket peer message is not binary: %d", messageType)
	}
	if len(body) > c.maxMessageSize {
		return protocol.Packet{}, fmt.Errorf("websocket peer message exceeds limit: %d", len(body))
	}
	packet, err := protocol.ParseBody(body)
	if err != nil {
		return protocol.Packet{}, fmt.Errorf("parse websocket peer message: %w", err)
	}
	return packet, nil
}

// Close terminates the websocket and is safe to call repeatedly.
func (c *WebSocketPacketChannel) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.connection.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func (c *WebSocketPacketChannel) checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return net.ErrClosed
	default:
		return nil
	}
}

func (c *WebSocketPacketChannel) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// WebSocketListener accepts websocket packet channels over an HTTP listener.
type WebSocketListener struct {
	listener *net.TCPListener
	server   *http.Server
	options  WebSocketOptions
	accept   chan *WebSocketPacketChannel
	done     chan struct{}

	mu          sync.Mutex
	closed      bool
	closeErr    error
	tlsEnabled  bool
	connections map[*WebSocketPacketChannel]struct{}
	closeOnce   sync.Once
}

// ListenWebSocket binds a websocket HTTP listener. It accepts requests on any
// path; the websocket URL supplied to DialWebSocket selects the request path.
func ListenWebSocket(address string, options ...WebSocketOptions) (*WebSocketListener, error) {
	configured, err := normalizeWebSocketOptions(options)
	if err != nil {
		return nil, err
	}
	dev := resolveBindDevice(configured.BindDevice, address)
	listenConfig := net.ListenConfig{Control: bindDeviceControl(dev)}
	listener, err := listenConfig.Listen(context.Background(), "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen websocket on %q: %w", address, err)
	}
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("websocket listener is not TCP")
	}
	wsListener := &WebSocketListener{
		listener:    tcpListener,
		options:     configured,
		accept:      make(chan *WebSocketPacketChannel, websocketSessionQueueSize),
		done:        make(chan struct{}),
		tlsEnabled:  configured.TLSServerConfig != nil,
		connections: make(map[*WebSocketPacketChannel]struct{}),
	}
	wsListener.server = &http.Server{
		Handler:   http.HandlerFunc(wsListener.handleRequest),
		TLSConfig: cloneTLSConfig(configured.TLSServerConfig),
	}
	return wsListener, nil
}

// ListenWS is a short alias for ListenWebSocket.
func ListenWS(address string, options ...WebSocketOptions) (*WebSocketListener, error) {
	return ListenWebSocket(address, options...)
}

// Address returns the bound websocket listener address.
func (l *WebSocketListener) Address() net.Addr { return l.listener.Addr() }

// URL returns a ws or wss URL for the bound listener.
func (l *WebSocketListener) URL() string {
	l.mu.Lock()
	tlsEnabled := l.tlsEnabled
	l.mu.Unlock()
	scheme := "ws"
	if tlsEnabled {
		scheme = "wss"
	}
	host, port, err := net.SplitHostPort(l.Address().String())
	if err != nil {
		return scheme + "://" + l.Address().String()
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// Serve accepts HTTP websocket upgrades until context cancellation or Close.
func (l *WebSocketListener) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("websocket serve context is nil")
	}
	l.mu.Lock()
	tlsEnabled := l.tlsEnabled
	l.mu.Unlock()
	return l.serve(ctx, tlsEnabled, "", "")
}

// ServeTLS accepts HTTPS websocket upgrades until context cancellation or
// Close. If certFile and keyFile are empty, the listener's TLSServerConfig
// must provide a certificate.
func (l *WebSocketListener) ServeTLS(ctx context.Context, certFile, keyFile string) error {
	if ctx == nil {
		return errors.New("websocket serve context is nil")
	}
	l.mu.Lock()
	l.tlsEnabled = true
	l.mu.Unlock()
	return l.serve(ctx, true, certFile, keyFile)
}

func (l *WebSocketListener) serve(ctx context.Context, tlsEnabled bool, certFile, keyFile string) error {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	if tlsEnabled {
		// Without explicit key material, wss listeners provision the
		// ephemeral self-signed certificate (insecure_tls.rs behavior).
		if certFile == "" && keyFile == "" && (l.server.TLSConfig == nil || len(l.server.TLSConfig.Certificates) == 0) {
			certificate, err := SelfSignedWSSCertificate()
			if err != nil {
				return fmt.Errorf("generate self-signed wss certificate: %w", err)
			}
			config := l.server.TLSConfig
			if config == nil {
				config = &tls.Config{}
			} else {
				config = config.Clone()
			}
			config.Certificates = []tls.Certificate{certificate}
			l.server.TLSConfig = config
		}
		err := l.server.ServeTLS(l.listener, certFile, keyFile)
		if l.isClosed() || ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve websocket listener: %w", err)
	}
	err := l.server.Serve(l.listener)
	if l.isClosed() || ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serve websocket listener: %w", err)
}

// Accept waits for the next completed websocket upgrade.
func (l *WebSocketListener) Accept(ctx context.Context) (*WebSocketPacketChannel, error) {
	if ctx == nil {
		return nil, errors.New("websocket accept context is nil")
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-l.done:
			return nil, net.ErrClosed
		case channel := <-l.accept:
			if channel.isClosed() {
				continue
			}
			return channel, nil
		}
	}
}

// Close stops accepting requests and closes all accepted packet channels.
func (l *WebSocketListener) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		close(l.done)
		l.closeErr = l.listener.Close()
		connections := make([]*WebSocketPacketChannel, 0, len(l.connections))
		for channel := range l.connections {
			connections = append(connections, channel)
		}
		l.mu.Unlock()
		_ = l.server.Close()
		for _, channel := range connections {
			_ = channel.Close()
		}
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closeErr
}

func (l *WebSocketListener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

func (l *WebSocketListener) handleRequest(writer http.ResponseWriter, request *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: l.options.CheckOrigin,
	}
	connection, err := upgrader.Upgrade(writer, request, cloneHeader(l.options.ResponseHeader))
	if err != nil {
		return
	}
	channel, err := NewWebSocketPacketChannel(connection, l.options.MaxMessageSize)
	if err != nil {
		_ = connection.Close()
		return
	}
	channel.onClose = func() {
		l.mu.Lock()
		delete(l.connections, channel)
		l.mu.Unlock()
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = channel.Close()
		return
	}
	l.connections[channel] = struct{}{}
	l.mu.Unlock()
	select {
	case l.accept <- channel:
	case <-l.done:
		_ = channel.Close()
	}
}

// DialWebSocket connects to a websocket endpoint using ctx for the complete
// HTTP upgrade handshake. Dialing wss:// without an explicit TLSClientConfig
// skips server verification, matching the oracle's insecure_tls dial path;
// an IP-address host presents "localhost" as SNI.
func DialWebSocket(ctx context.Context, address string, options ...WebSocketOptions) (*WebSocketPacketChannel, error) {
	if ctx == nil {
		return nil, errors.New("websocket dial context is nil")
	}
	configured, err := normalizeWebSocketOptions(options)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.ToLower(address), "wss://") && configured.TLSClientConfig == nil {
		configured.TLSClientConfig = InsecureWSSClientConfig()
		if parsed, parseErr := url.Parse(address); parseErr == nil {
			configured.TLSClientConfig.ServerName = wssServerName(parsed.Hostname())
		}
	}
	header := cloneHeader(configured.Header)
	if configured.Origin != "" {
		header.Set("Origin", configured.Origin)
	}
	_, dev := resolveBindOption(address, []BindOption{BindDevice(configured.BindDevice)})
	dialer := websocket.Dialer{
		TLSClientConfig: cloneTLSConfig(configured.TLSClientConfig),
		NetDialContext:  (&net.Dialer{Control: bindDeviceControl(dev)}).DialContext,
	}
	connection, _, err := dialer.DialContext(ctx, address, header)
	if err != nil {
		return nil, fmt.Errorf("dial websocket %q: %w", address, err)
	}
	channel, err := NewWebSocketPacketChannel(connection, configured.MaxMessageSize)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return channel, nil
}

// DialWS is a short alias for DialWebSocket.
func DialWS(ctx context.Context, address string, options ...WebSocketOptions) (*WebSocketPacketChannel, error) {
	return DialWebSocket(ctx, address, options...)
}

func normalizeWebSocketOptions(options []WebSocketOptions) (WebSocketOptions, error) {
	var configured WebSocketOptions
	if len(options) > 1 {
		return configured, fmt.Errorf("websocket options supplied more than once")
	}
	if len(options) == 1 {
		configured = options[0]
	}
	if configured.MaxMessageSize == 0 {
		configured.MaxMessageSize = protocol.DefaultMaxStreamFrameSize
	}
	if configured.MaxMessageSize < protocol.PeerManagerHeaderSize {
		return configured, fmt.Errorf("maximum websocket message size %d is too small", configured.MaxMessageSize)
	}
	return configured, nil
}

func cloneHeader(header http.Header) http.Header {
	if header == nil {
		return make(http.Header)
	}
	return header.Clone()
}

func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}
	return config.Clone()
}

func interruptWebSocketReadOnCancel(ctx context.Context, connection *websocket.Conn) func() {
	stop := context.AfterFunc(ctx, func() { _ = connection.SetReadDeadline(time.Now()) })
	return func() { stop() }
}

func interruptWebSocketWriteOnCancel(ctx context.Context, connection *websocket.Conn) func() {
	stop := context.AfterFunc(ctx, func() { _ = connection.SetWriteDeadline(time.Now()) })
	return func() { stop() }
}

func setWebSocketReadDeadline(ctx context.Context, connection *websocket.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		return connection.SetReadDeadline(deadline)
	}
	return connection.SetReadDeadline(time.Time{})
}

func setWebSocketWriteDeadline(ctx context.Context, connection *websocket.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		return connection.SetWriteDeadline(deadline)
	}
	return connection.SetWriteDeadline(time.Time{})
}

func mapWebSocketContextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
		return net.ErrClosed
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}

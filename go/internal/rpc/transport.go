// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// Handler processes one management RPC request.
type Handler func(context.Context, RpcPacket) (RpcPacket, error)

// Server serves management RPC requests over EasyTier TCP peer frames.
// A Server is configured with NewServer before it is used.
type Server struct {
	handler   Handler
	whitelist []netip.Prefix

	mu          sync.Mutex
	listener    net.Listener
	closed      bool
	closeErr    error
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup
}

// NewServer creates a management RPC server. whitelist must be non-empty so a
// management endpoint is never accidentally exposed to every source address.
func NewServer(whitelist []netip.Prefix, handler Handler) (*Server, error) {
	if len(whitelist) == 0 {
		return nil, fmt.Errorf("management RPC CIDR whitelist must be supplied")
	}
	if handler == nil {
		return nil, fmt.Errorf("management RPC handler is nil")
	}

	prefixes := make([]netip.Prefix, len(whitelist))
	for i, prefix := range whitelist {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("management RPC whitelist entry %d is invalid", i)
		}
		prefixes[i] = prefix.Masked()
	}
	return &Server{
		handler:     handler,
		whitelist:   prefixes,
		connections: make(map[net.Conn]struct{}),
	}, nil
}

// Listen binds the server to a TCP address. It may be called once.
func (s *Server) Listen(address string) error {
	if s == nil {
		return fmt.Errorf("management RPC server is nil")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen management RPC on %q: %w", address, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = listener.Close()
		return net.ErrClosed
	}
	if s.listener != nil {
		_ = listener.Close()
		return fmt.Errorf("management RPC server is already listening")
	}
	s.listener = listener
	return nil
}

// Addr returns the bound listener address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve accepts connections until ctx is canceled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("management RPC server is nil")
	}
	if ctx == nil {
		return fmt.Errorf("management RPC serve context is nil")
	}
	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()
	if listener == nil {
		return fmt.Errorf("management RPC server is not listening")
	}

	stopClose := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stopClose()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || s.isClosed() {
				s.wg.Wait()
				return nil
			}
			return fmt.Errorf("accept management RPC connection: %w", err)
		}
		if !s.registerConnection(connection) {
			_ = connection.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.unregisterConnection(connection)
			defer connection.Close()
			s.serveConnection(ctx, connection)
		}()
	}
}

func (s *Server) serveConnection(ctx context.Context, connection net.Conn) {
	if !s.allows(connection.RemoteAddr()) {
		return
	}
	merger := NewFragmentMerger()
	for {
		packet, err := protocol.ReadStreamFrame(connection, protocol.DefaultMaxStreamFrameSize)
		if err != nil {
			return
		}
		if packet.Header.PacketType != protocol.PacketTypeRPCRequest {
			return
		}
		fragment, err := UnmarshalRpcPacket(packet.Payload)
		if err != nil || !fragment.IsRequest {
			return
		}
		request, err := merger.Add(fragment)
		if err != nil {
			return
		}
		if request == nil {
			continue
		}

		response, err := s.handler(ctx, *request)
		if err != nil {
			body, marshalErr := jsonError(err)
			if marshalErr != nil {
				return
			}
			response = RpcPacket{Descriptor: request.Descriptor, Body: body}
		}
		response.FromPeer = request.ToPeer
		response.ToPeer = request.FromPeer
		response.TransactionID = request.TransactionID
		response.IsRequest = false
		if response.Descriptor == nil && request.Descriptor != nil {
			descriptor := *request.Descriptor
			response.Descriptor = &descriptor
		}
		descriptor := RpcDescriptor{}
		if response.Descriptor != nil {
			descriptor = *response.Descriptor
		}
		packets, err := BuildRPCPackets(BuildRPCPacketArgs{
			FromPeer:        request.ToPeer,
			ToPeer:          request.FromPeer,
			RPCDesc:         descriptor,
			TransactionID:   request.TransactionID,
			Content:         response.Body,
			TraceID:         response.TraceID,
			CompressionInfo: compressionInfo(response),
		})
		if err != nil {
			return
		}
		for _, responsePacket := range packets {
			if err := protocol.WriteStreamFrame(connection, responsePacket); err != nil {
				return
			}
		}
	}
}

// Close stops accepting connections and interrupts active requests. It is
// idempotent.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		err := s.closeErr
		s.mu.Unlock()
		return err
	}
	s.closed = true
	if s.listener != nil {
		s.closeErr = s.listener.Close()
	}
	connections := make([]net.Conn, 0, len(s.connections))
	for connection := range s.connections {
		connections = append(connections, connection)
	}
	err := s.closeErr
	s.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	return err
}

func (s *Server) allows(remote net.Addr) bool {
	tcpAddress, ok := remote.(*net.TCPAddr)
	if !ok {
		return false
	}
	address, ok := netip.AddrFromSlice(tcpAddress.IP)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, prefix := range s.whitelist {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) registerConnection(connection net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.connections[connection] = struct{}{}
	return true
}

func (s *Server) unregisterConnection(connection net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.connections, connection)
}

// Call sends one management RPC request and waits for its response.
func Call(ctx context.Context, address string, request RpcPacket) (RpcPacket, error) {
	if ctx == nil {
		return RpcPacket{}, fmt.Errorf("management RPC call context is nil")
	}
	if !request.IsRequest {
		return RpcPacket{}, fmt.Errorf("management RPC packet is not a request")
	}
	if request.Descriptor == nil {
		return RpcPacket{}, fmt.Errorf("management RPC request descriptor is nil")
	}

	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return RpcPacket{}, mapCallContextError(ctx, err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return RpcPacket{}, fmt.Errorf("set management RPC deadline: %w", err)
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()

	requestPackets, err := BuildRPCPackets(BuildRPCPacketArgs{
		FromPeer:        request.FromPeer,
		ToPeer:          request.ToPeer,
		RPCDesc:         *request.Descriptor,
		TransactionID:   request.TransactionID,
		IsRequest:       true,
		Content:         request.Body,
		TraceID:         request.TraceID,
		CompressionInfo: compressionInfo(request),
	})
	if err != nil {
		return RpcPacket{}, fmt.Errorf("build management RPC request: %w", err)
	}
	for _, requestPacket := range requestPackets {
		if err := protocol.WriteStreamFrame(connection, requestPacket); err != nil {
			return RpcPacket{}, mapCallContextError(ctx, err)
		}
	}
	merger := NewFragmentMerger()
	for {
		responsePacket, readErr := protocol.ReadStreamFrame(connection, protocol.DefaultMaxStreamFrameSize)
		if readErr != nil {
			return RpcPacket{}, mapCallContextError(ctx, readErr)
		}
		if responsePacket.Header.PacketType != protocol.PacketTypeRPCResponse {
			return RpcPacket{}, fmt.Errorf("management RPC response has peer packet type %d", responsePacket.Header.PacketType)
		}
		if responsePacket.Header.FromPeerID != request.ToPeer || responsePacket.Header.ToPeerID != request.FromPeer {
			return RpcPacket{}, fmt.Errorf("management RPC response peer IDs do not match request")
		}
		fragment, parseErr := UnmarshalRpcPacket(responsePacket.Payload)
		if parseErr != nil {
			return RpcPacket{}, fmt.Errorf("unmarshal management RPC response: %w", parseErr)
		}
		response, mergeErr := merger.Add(fragment)
		if mergeErr != nil {
			return RpcPacket{}, fmt.Errorf("merge management RPC response: %w", mergeErr)
		}
		if response == nil {
			continue
		}
		if response.IsRequest {
			return RpcPacket{}, fmt.Errorf("management RPC response is marked as a request")
		}
		if response.TransactionID != request.TransactionID || response.FromPeer != request.ToPeer || response.ToPeer != request.FromPeer {
			return RpcPacket{}, fmt.Errorf("management RPC response does not match request")
		}
		return *response, nil
	}
}

func compressionInfo(packet RpcPacket) RpcCompressionInfo {
	if packet.CompressionInfo == nil {
		return RpcCompressionInfo{}
	}
	return *packet.CompressionInfo
}

func jsonError(err error) ([]byte, error) {
	return json.Marshal(struct {
		Error string `json:"error"`
	}{Error: err.Error()})
}

func mapCallContextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}

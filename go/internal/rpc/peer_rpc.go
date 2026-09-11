// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const (
	// peerRpcPacketMTU is the maximum payload of one RPC wire piece. Bodies
	// larger than this are fragmented, mirroring the Rust RPC_PACKET_CONTENT_MTU.
	peerRpcPacketMTU = 1300

	// envelopeOk / envelopeErr are the first byte of a response body.
	envelopeOk  = 0
	envelopeErr = 1
)

// ErrNoService is returned when an RPC request does not match any registered
// service. Runtime dispatchers use it to fall back to their default handler.
var ErrNoService = errors.New("no rpc service registered")

// RpcTransport is the packet transport a PeerRpcManager runs over.
type RpcTransport interface {
	MyPeerID() uint32
	Send(ctx context.Context, dstPeerID uint32, packet protocol.Packet) error
}

// RpcService is one callable service registered on an RpcTransport domain.
type RpcService interface {
	// ServiceName returns the proto service name used in the descriptor.
	ServiceName() string
	// HandleMethod dispatches one method invocation. It returns the response
	// body, or an error that is delivered to the caller as an error envelope.
	HandleMethod(methodIndex uint32, ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error)
}

// registrationKey is the descriptor lookup key for one RPC service.
type registrationKey struct {
	domain      string
	serviceName string
}

type transactChannel struct {
	response chan []byte
	stop     chan struct{}
}

// PeerRpcManager runs bidirectional peer RPC over a packet transport. It owns
// a service registry, a transaction-scoped client, and reassembly of fragmented
// requests and responses.
type PeerRpcManager struct {
	localPeerID uint32
	transport   RpcTransport

	mu              sync.Mutex
	registry        map[registrationKey]RpcService
	transactions    map[int64]*transactChannel
	requestFrag     *FragmentMerger
	responseFrag    *FragmentMerger
	nextTransaction atomic.Int64

	closed atomic.Bool
}

func NewPeerRpcManager(transport RpcTransport) (*PeerRpcManager, error) {
	if transport == nil {
		return nil, errors.New("peer rpc transport is required")
	}
	if transport.MyPeerID() == 0 {
		return nil, errors.New("peer rpc transport peer ID must not be zero")
	}
	return &PeerRpcManager{
		localPeerID:  transport.MyPeerID(),
		transport:    transport,
		registry:     make(map[registrationKey]RpcService),
		transactions: make(map[int64]*transactChannel),
		requestFrag:  NewFragmentMerger(),
		responseFrag: NewFragmentMerger(),
	}, nil
}

// Register installs a service under a domain (typically the network name).
func (m *PeerRpcManager) Register(domain string, svc RpcService) error {
	if m == nil {
		return errors.New("nil peer rpc manager")
	}
	if domain == "" {
		return errors.New("rpc service domain is required")
	}
	if svc == nil {
		return errors.New("rpc service is nil")
	}
	if svc.ServiceName() == "" {
		return errors.New("rpc service name is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed.Load() {
		return errors.New("peer rpc manager is closed")
	}
	m.registry[registrationKey{domain: domain, serviceName: svc.ServiceName()}] = svc
	return nil
}

// Unregister removes a previously registered service.
func (m *PeerRpcManager) Unregister(domain, serviceName string) {
	m.mu.Lock()
	delete(m.registry, registrationKey{domain: domain, serviceName: serviceName})
	m.mu.Unlock()
}

func (m *PeerRpcManager) lookup(key registrationKey) RpcService {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.registry[key]
}

func (m *PeerRpcManager) defaultProtoName() string {
	return "EasyTier"
}

// Call invokes methodIndex on the service serviceName at dstPeerID within
// domain. It waits for a matching response or ctx completion.
func (m *PeerRpcManager) Call(ctx context.Context, dstPeerID uint32, domain, serviceName string, methodIndex uint32, requestBody []byte) ([]byte, error) {
	if m == nil {
		return nil, errors.New("nil peer rpc manager")
	}
	if ctx == nil {
		return nil, errors.New("rpc call context is nil")
	}
	if dstPeerID == 0 {
		return nil, errors.New("rpc call destination peer is required")
	}
	if domain == "" {
		return nil, errors.New("rpc call domain is required")
	}
	if serviceName == "" {
		return nil, errors.New("rpc call service name is required")
	}

	transactionID := m.nextTransaction.Add(1)
	channel := &transactChannel{
		response: make(chan []byte, 1),
		stop:     make(chan struct{}),
	}
	m.mu.Lock()
	if m.closed.Load() {
		m.mu.Unlock()
		return nil, errors.New("peer rpc manager is closed")
	}
	m.transactions[transactionID] = channel
	m.mu.Unlock()

	descriptor := &RpcDescriptor{
		DomainName:  domain,
		ProtoName:   m.defaultProtoName(),
		ServiceName: serviceName,
		MethodIndex: methodIndex,
	}

	if err := m.sendFragmented(ctx, dstPeerID, transactionID, descriptor, requestBody, true); err != nil {
		m.dropTransaction(transactionID)
		return nil, err
	}

	select {
	case body := <-channel.response:
		m.dropTransaction(transactionID)
		return decodeResponseEnvelope(body)
	case <-channel.stop:
		m.dropTransaction(transactionID)
		return nil, errors.New("peer rpc transaction was replaced")
	case <-ctx.Done():
		m.dropTransaction(transactionID)
		return nil, ctx.Err()
	}
}

func (m *PeerRpcManager) dropTransaction(transactionID int64) {
	m.mu.Lock()
	delete(m.transactions, transactionID)
	m.mu.Unlock()
}

func (m *PeerRpcManager) sendFragmented(ctx context.Context, dstPeerID uint32, transactionID int64, descriptor *RpcDescriptor, body []byte, isRequest bool) error {
	if len(body) == 0 && !isRequest {
		body = []byte{}
	}
	totalPieces := uint32(1)
	if len(body) > peerRpcPacketMTU {
		totalPieces = uint32((len(body) + peerRpcPacketMTU - 1) / peerRpcPacketMTU)
	}
	for piece := uint32(0); piece < totalPieces; piece++ {
		start, end := int(piece)*peerRpcPacketMTU, int(piece+1)*peerRpcPacketMTU
		if end > len(body) {
			end = len(body)
		}
		pieceBody := body[start:end]
		packet := RpcPacket{
			FromPeer:      m.localPeerID,
			ToPeer:        dstPeerID,
			TransactionID: transactionID,
			Descriptor:    descriptor,
			Body:          pieceBody,
			IsRequest:     isRequest,
			TotalPieces:   totalPieces,
			PieceIdx:      piece,
		}
		if piece != 0 {
			packet.Descriptor = nil
		}
		wire, err := packet.Marshal()
		if err != nil {
			return fmt.Errorf("marshal rpc packet: %w", err)
		}
		var packetType uint8 = protocol.PacketTypeRPCRequest
		if !isRequest {
			packetType = protocol.PacketTypeRPCResponse
		}
		out := protocol.Packet{
			Header: protocol.PeerManagerHeader{
				FromPeerID: m.localPeerID,
				ToPeerID:   dstPeerID,
				PacketType: packetType,
			},
			Payload: wire,
		}
		if err := m.transport.Send(ctx, dstPeerID, out); err != nil {
			return err
		}
	}
	return nil
}

// HandlePacket processes one locally-destined RPC packet from the transport.
// It reassembles fragmented messages, dispatches requests, and completes
// pending client calls for responses.
func (m *PeerRpcManager) HandlePacket(ctx context.Context, packet protocol.Packet) error {
	if m == nil {
		return errors.New("nil peer rpc manager")
	}
	if packet.Header.PacketType != protocol.PacketTypeRPCRequest && packet.Header.PacketType != protocol.PacketTypeRPCResponse {
		return fmt.Errorf("not an rpc packet type: %d", packet.Header.PacketType)
	}

	body, err := UnmarshalRpcPacket(packet.Payload)
	if err != nil {
		return fmt.Errorf("unmarshal rpc packet: %w", err)
	}

	if body.TotalPieces != 0 && body.TotalPieces > 1 {
		var complete *RpcPacket
		if packet.Header.PacketType == protocol.PacketTypeRPCRequest {
			complete, err = m.requestFrag.Add(body)
		} else {
			complete, err = m.responseFrag.Add(body)
		}
		if err != nil {
			return err
		}
		if complete == nil {
			return nil
		}
		body = *complete
	}

	if body.IsRequest || packet.Header.PacketType == protocol.PacketTypeRPCRequest {
		return m.dispatchRequest(ctx, body)
	}
	return m.completeResponse(ctx, body)
}

func (m *PeerRpcManager) dispatchRequest(ctx context.Context, request RpcPacket) error {
	if request.Descriptor == nil {
		return m.sendErrorResponse(ctx, request, errors.New("request is missing a descriptor"))
	}
	key := registrationKey{
		domain:      request.Descriptor.DomainName,
		serviceName: request.Descriptor.ServiceName,
	}
	svc := m.lookup(key)
	if svc == nil {
		// No service claims this request. Deliver an error envelope so the
		// remote caller's transaction is completed instead of hanging.
		return m.sendErrorResponse(ctx, request, fmt.Errorf("%w: %s", ErrNoService, key.serviceName))
	}

	responseBody, err := svc.HandleMethod(request.Descriptor.MethodIndex, ctx, request.FromPeer, request.Body)
	if err != nil {
		return m.sendErrorResponse(ctx, request, err)
	}
	return m.sendResponse(ctx, request, responseBody)
}

func (m *PeerRpcManager) sendResponse(ctx context.Context, request RpcPacket, responseBody []byte) error {
	descriptor := request.Descriptor
	response := RpcPacket{
		FromPeer:      m.localPeerID,
		ToPeer:        request.FromPeer,
		TransactionID: request.TransactionID,
		Descriptor:    descriptor,
		Body:          append([]byte{envelopeOk}, responseBody...),
		IsRequest:     false,
		TotalPieces:   1,
	}
	wire, err := response.Marshal()
	if err != nil {
		return fmt.Errorf("marshal rpc response: %w", err)
	}
	out := protocol.Packet{
		Header: protocol.PeerManagerHeader{
			FromPeerID: m.localPeerID,
			ToPeerID:   request.FromPeer,
			PacketType: protocol.PacketTypeRPCResponse,
		},
		Payload: wire,
	}
	return m.transport.Send(ctx, request.FromPeer, out)
}

func (m *PeerRpcManager) sendErrorResponse(ctx context.Context, request RpcPacket, err error) error {
	response := RpcPacket{
		FromPeer:      m.localPeerID,
		ToPeer:        request.FromPeer,
		TransactionID: request.TransactionID,
		Descriptor:    request.Descriptor,
		Body:          append([]byte{envelopeErr}, []byte(err.Error())...),
		IsRequest:     false,
		TotalPieces:   1,
	}
	wire, marshalErr := response.Marshal()
	if marshalErr != nil {
		return fmt.Errorf("marshal rpc error response: %w", marshalErr)
	}
	out := protocol.Packet{
		Header: protocol.PeerManagerHeader{
			FromPeerID: m.localPeerID,
			ToPeerID:   request.FromPeer,
			PacketType: protocol.PacketTypeRPCResponse,
		},
		Payload: wire,
	}
	return m.transport.Send(ctx, request.FromPeer, out)
}

func (m *PeerRpcManager) completeResponse(ctx context.Context, response RpcPacket) error {
	m.mu.Lock()
	channel := m.transactions[response.TransactionID]
	m.mu.Unlock()
	if channel == nil {
		return nil
	}
	select {
	case channel.response <- response.Body:
	case <-ctx.Done():
	case <-channel.stop:
	default:
		// The caller has already moved on; drop the late response.
	}
	return nil
}

// Close rejects new calls and unblocks any in-flight callers.
func (m *PeerRpcManager) Close() {
	if m == nil {
		return
	}
	if m.closed.Swap(true) {
		return
	}
	m.mu.Lock()
	for _, channel := range m.transactions {
		close(channel.stop)
	}
	m.transactions = make(map[int64]*transactChannel)
	m.mu.Unlock()
}

func decodeResponseEnvelope(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, errors.New("empty rpc response")
	}
	switch body[0] {
	case envelopeErr:
		return nil, errors.New(string(body[1:]))
	case envelopeOk:
		return body[1:], nil
	default:
		return nil, fmt.Errorf("unknown rpc response envelope type %d", body[0])
	}
}

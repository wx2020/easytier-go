// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package punch

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/stun"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// ServiceName is the proto service name used in RPC descriptors.
const ServiceName = "UdpHolePunchRpc"

// Method indices follow the proto service declaration order.
const (
	MethodSelectPunchListener        uint32 = 0
	MethodSendPunchPacketCone        uint32 = 1
	MethodSendPunchPacketHardSym     uint32 = 2
	MethodSendPunchPacketEasySym     uint32 = 3
	MethodSendPunchPacketBothEasySym uint32 = 4
)

// Symmetric punch pacing constants.
const (
	// hardSymMaxPacketsBase bounds one random punch round.
	hardSymMaxPacketsBase = 180
	// symPacketSendInterval paces sequential port predictions.
	symPacketSendInterval = time.Millisecond
	// bothEasySymMaxWait caps the remote wait window.
	bothEasySymMaxWait = 8 * time.Second
	// bothEasySymTick paces the both-easy-sym send loop.
	bothEasySymTick = 100 * time.Millisecond
)

// Service implements the UdpHolePunchRpc server side.
type Service struct {
	pool *ListenerPool
	stun stun.Source

	// symMu serializes symmetric punch rounds for this node.
	symMu symMutex

	bothMu       sync.Mutex
	bothTaskDone chan struct{}
}

// symMutex is a try-lockable mutex.
type symMutex struct {
	mu sync.Mutex
}

// tryLock attempts to acquire the mutex without blocking.
func (m *symMutex) tryLock() bool {
	return m.mu.TryLock()
}

func (m *symMutex) unlock() { m.mu.Unlock() }

// NewService builds the punch RPC service over a listener pool.
func NewService(pool *ListenerPool, stunSource stun.Source) *Service {
	return &Service{pool: pool, stun: stunSource}
}

// ServiceName implements rpc.RpcService.
func (s *Service) ServiceName() string { return ServiceName }

// HandleMethod implements rpc.RpcService with protojson bodies.
func (s *Service) HandleMethod(methodIndex uint32, ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
	switch methodIndex {
	case MethodSelectPunchListener:
		var request peer_rpc.SelectPunchListenerRequest
		if err := unmarshalRequest(requestBody, &request); err != nil {
			return nil, err
		}
		return s.handleSelectPunchListener(ctx, &request)
	case MethodSendPunchPacketCone:
		var request peer_rpc.SendPunchPacketConeRequest
		if err := unmarshalRequest(requestBody, &request); err != nil {
			return nil, err
		}
		return s.handleSendPunchPacketCone(ctx, &request)
	case MethodSendPunchPacketHardSym:
		var request peer_rpc.SendPunchPacketHardSymRequest
		if err := unmarshalRequest(requestBody, &request); err != nil {
			return nil, err
		}
		return s.handleSendPunchPacketHardSym(ctx, &request)
	case MethodSendPunchPacketEasySym:
		var request peer_rpc.SendPunchPacketEasySymRequest
		if err := unmarshalRequest(requestBody, &request); err != nil {
			return nil, err
		}
		return s.handleSendPunchPacketEasySym(ctx, &request)
	case MethodSendPunchPacketBothEasySym:
		var request peer_rpc.SendPunchPacketBothEasySymRequest
		if err := unmarshalRequest(requestBody, &request); err != nil {
			return nil, err
		}
		return s.handleSendPunchPacketBothEasySym(ctx, &request)
	default:
		return nil, fmt.Errorf("unknown %s method %d", ServiceName, methodIndex)
	}
}

func unmarshalRequest(body []byte, request proto.Message) error {
	if len(body) == 0 {
		return nil
	}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(body, request); err != nil {
		return fmt.Errorf("decode punch rpc request: %w", err)
	}
	return nil
}

func marshalResponse(response proto.Message) ([]byte, error) {
	body, err := protojson.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("encode punch rpc response: %w", err)
	}
	return body, nil
}

func (s *Service) handleSelectPunchListener(ctx context.Context, request *peer_rpc.SelectPunchListenerRequest) ([]byte, error) {
	mapped, err := s.pool.SelectListener(ctx, request.GetForceNew(), request.GetPreferPortMapping())
	if err != nil {
		return nil, err
	}
	response := &peer_rpc.SelectPunchListenerResponse{}
	response.ListenerMappedAddr, err = addrPortToProto(mapped)
	if err != nil {
		return nil, err
	}
	return marshalResponse(response)
}

func (s *Service) handleSendPunchPacketCone(ctx context.Context, request *peer_rpc.SendPunchPacketConeRequest) ([]byte, error) {
	listenerMapped, err := protoToAddrPort(request.GetListenerMappedAddr())
	if err != nil {
		return nil, err
	}
	socket, ok := s.pool.FindListener(listenerMapped)
	if !ok {
		return nil, errors.New("send punch packet cone failed to find listener")
	}
	dest, err := protoToAddrPort(request.GetDestAddr())
	if err != nil {
		return nil, err
	}
	if dest.Addr().IsUnspecified() || dest.Addr().IsMulticast() {
		return nil, errors.New("send punch packet cone dest address is malformed")
	}

	target := &net.UDPAddr{IP: net.IP(dest.Addr().AsSlice()), Port: int(dest.Port())}
	packetsPerBatch := int(request.GetPacketCountPerBatch())
	batches := int(request.GetPacketBatchCount())
	interval := time.Duration(request.GetPacketIntervalMs()) * time.Millisecond
	tid := request.GetTransactionId()

	for batch := 0; batch < batches; batch++ {
		for i := 0; i < packetsPerBatch; i++ {
			packet, err := NewHolePunchPacket(tid, HolePunchBodyLen)
			if err != nil {
				return nil, err
			}
			if _, err := socket.WriteToUDP(packet, target); err != nil {
				return nil, fmt.Errorf("send cone punch packet: %w", err)
			}
		}
		if batch+1 < batches && interval > 0 {
			if err := Sleep(ctx, interval); err != nil {
				return nil, err
			}
		}
	}
	return marshalResponse(&common.Void{})
}

// sendSymmetricHolePunchPacket sends up to maxPackets punch datagrams across
// the ports slice starting at portStartIdx, three datagrams per port per
// public IP, pacing one millisecond per port. It returns the next port index.
func sendSymmetricHolePunchPacket(ctx context.Context, ports []uint16, socket *net.UDPConn, transactionID uint32, publicIPs []netip.Addr, portStartIdx int, maxPackets int) (int, error) {
	if len(ports) == 0 || len(publicIPs) == 0 {
		return portStartIdx, errors.New("symmetric punch requires ports and public IPs")
	}
	sent := 0
	idx := portStartIdx
	for sent < maxPackets {
		port := ports[idx%len(ports)]
		for _, ip := range publicIPs {
			packet, err := NewHolePunchPacket(transactionID, HolePunchBodyLen)
			if err != nil {
				return idx % len(ports), err
			}
			target := &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(port)}
			for i := 0; i < 3; i++ {
				if _, err := socket.WriteToUDP(packet, target); err != nil {
					return idx % len(ports), fmt.Errorf("send symmetric punch packet: %w", err)
				}
			}
			sent++
		}
		idx++
		if err := Sleep(ctx, symPacketSendInterval); err != nil {
			return idx % len(ports), err
		}
	}
	return idx % len(ports), nil
}

func (s *Service) handleSendPunchPacketHardSym(ctx context.Context, request *peer_rpc.SendPunchPacketHardSymRequest) ([]byte, error) {
	if !s.symMu.tryLock() {
		return nil, errors.New("sym punch lock is busy")
	}
	defer s.symMu.unlock()

	listenerMapped, err := protoToAddrPort(request.GetListenerMappedAddr())
	if err != nil {
		return nil, err
	}
	socket, ok := s.pool.FindListener(listenerMapped)
	if !ok {
		return nil, errors.New("send punch packet hard sym failed to find listener")
	}
	publicIPs, err := protoToIPv4List(request.GetPublicIps())
	if err != nil {
		return nil, err
	}

	round := max32(request.GetRound(), 1)
	maxPackets := 600 + rand.Intn(200)
	if round > 2 {
		shrunk := int(float64(maxPackets) * 2 / float64(round))
		if shrunk < hardSymMaxPacketsBase {
			shrunk = hardSymMaxPacketsBase
		}
		maxPackets = shrunk
	}

	var nextPortIndex int
	for i := 0; i < 2; i++ {
		nextPortIndex, err = sendSymmetricHolePunchPacket(ctx, ShuffledPortVec(), socket, request.GetTransactionId(), publicIPs, int(request.GetPortIndex()), maxPackets)
		if err != nil {
			return nil, err
		}
	}
	return marshalResponse(&peer_rpc.SendPunchPacketHardSymResponse{NextPortIndex: uint32(nextPortIndex)})
}

func (s *Service) handleSendPunchPacketEasySym(ctx context.Context, request *peer_rpc.SendPunchPacketEasySymRequest) ([]byte, error) {
	if !s.symMu.tryLock() {
		return nil, errors.New("sym punch lock is busy")
	}
	defer s.symMu.unlock()

	listenerMapped, err := protoToAddrPort(request.GetListenerMappedAddr())
	if err != nil {
		return nil, err
	}
	socket, ok := s.pool.FindListener(listenerMapped)
	if !ok {
		return nil, errors.New("send punch packet easy sym failed to find listener")
	}
	publicIPs, err := protoToIPv4List(request.GetPublicIps())
	if err != nil {
		return nil, err
	}

	basePort := request.GetBasePortNum()
	maxPort := max32(request.GetMaxPortNum(), 1)
	incremental := request.GetIsIncremental()

	var portStart, portEnd uint32
	if incremental {
		portStart = basePort + 1
		portEnd = basePort + maxPort
	} else {
		portStart = saturatingSubU32(basePort, maxPort)
		portEnd = basePort - 1
	}
	if portEnd <= portStart {
		return nil, errors.New("send punch packet easy sym invalid port range")
	}

	ports := make([]uint16, 0, portEnd-portStart+1)
	for port := portStart; port <= portEnd; port++ {
		ports = append(ports, uint16(port))
	}

	for i := 0; i < 2; i++ {
		if _, err := sendSymmetricHolePunchPacket(ctx, ports, socket, request.GetTransactionId(), publicIPs, 0, len(ports)); err != nil {
			return nil, err
		}
	}
	return marshalResponse(&common.Void{})
}

func (s *Service) handleSendPunchPacketBothEasySym(ctx context.Context, request *peer_rpc.SendPunchPacketBothEasySymRequest) ([]byte, error) {
	// Single flight: a second concurrent request reports busy.
	s.bothMu.Lock()
	if s.bothTaskDone != nil {
		select {
		case <-s.bothTaskDone:
			s.bothTaskDone = nil
		default:
			s.bothMu.Unlock()
			return marshalResponse(&peer_rpc.SendPunchPacketBothEasySymResponse{IsBusy: true})
		}
	}
	s.bothMu.Unlock()

	mapped, err := s.stun.GetUDPPortMapping(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("get udp port mapping: %w", err)
	}
	publicIP, err := protoToIPv4(request.GetPublicIp())
	if err != nil {
		return nil, err
	}

	tid := request.GetTransactionId()
	socketCount := int(request.GetUdpSocketCount())
	if socketCount <= 0 {
		return nil, errors.New("udp socket count must be positive")
	}
	waitTime := time.Duration(request.GetWaitTimeMs()) * time.Millisecond
	if waitTime > bothEasySymMaxWait {
		waitTime = bothEasySymMaxWait
	}
	dstPort := uint16(request.GetDstPortNum())

	done := make(chan struct{})
	s.bothMu.Lock()
	s.bothTaskDone = done
	s.bothMu.Unlock()

	array := NewUdpSocketArray(socketCount)
	if err := array.Start(); err != nil {
		array.Close()
		close(done)
		return nil, err
	}
	array.AddInterestTID(tid)

	go func() {
		defer close(done)
		defer array.Close()
		s.runBothEasySymTask(ctx, array, tid, publicIP, dstPort, waitTime)
	}()

	response := &peer_rpc.SendPunchPacketBothEasySymResponse{}
	response.BaseMappedAddr, err = addrPortToProto(mapped)
	if err != nil {
		return nil, err
	}
	return marshalResponse(response)
}

// runBothEasySymTask sends punch packets toward the peer's predicted port
// while adopting captured sockets as temporary listeners on the same port.
func (s *Service) runBothEasySymTask(ctx context.Context, array *UdpSocketArray, tid uint32, publicIP netip.Addr, dstPort uint16, waitTime time.Duration) {
	punchPacket, err := NewHolePunchPacket(tid, HolePunchBodyLen)
	if err != nil {
		return
	}
	target := &net.UDPAddr{IP: net.IP(publicIP.AsSlice()), Port: int(dstPort)}

	type adoptedListener struct {
		listener *PunchListener
		remote   *net.UDPAddr
	}

	deadline := time.Now().Add(waitTime)
	var adopted []adoptedListener
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := array.SendWithAll(punchPacket, target); err != nil {
			return
		}
		if err := Sleep(ctx, bothEasySymTick); err != nil {
			return
		}
		for {
			captured, ok := array.TryFetchPunchedSocket(tid)
			if !ok {
				break
			}
			// Adopt the port: the captured socket is released so a fresh
			// listener can bind it and upgrade incoming SYNs to sessions.
			local, err := netip.ParseAddrPort(captured.Socket.LocalAddr().String())
			_ = captured.Socket.Close()
			if err != nil {
				continue
			}
			listener, err := s.pool.NewExternalListener(ctx, local.Port())
			if err != nil {
				continue
			}
			adopted = append(adopted, adoptedListener{listener: listener, remote: captured.Remote})
		}
		for i := range adopted {
			_, _ = adopted[i].listener.Socket().WriteToUDP(punchPacket, adopted[i].remote)
		}
	}

	for _, entry := range adopted {
		if entry.listener.ConnCount() > 0 {
			s.pool.AddListener(entry.listener)
		} else {
			_ = entry.listener.service.Close()
		}
	}
}

func protoToIPv4List(addresses []*common.Ipv4Addr) ([]netip.Addr, error) {
	if len(addresses) == 0 {
		return nil, errors.New("public ip list is empty")
	}
	ips := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		ip, err := protoToIPv4(address)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func saturatingSubU32(a, b uint32) uint32 {
	if a < b {
		return 0
	}
	return a - b
}

// ShuffledPortVec returns the valid UDP port range in random order. The same
// shuffle is shared per process for hard symmetric punching.
var shuffledPorts = sync.OnceValue(func() []uint16 {
	ports := make([]uint16, 1<<16-1)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	rand.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
	return ports
})

// ShuffledPortVec exposes the shared shuffled port list.
func ShuffledPortVec() []uint16 { return shuffledPorts() }

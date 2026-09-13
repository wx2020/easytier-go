// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package tcphole

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
)

// ServiceName is the proto service name for the TCP punch exchange.
const ServiceName = "TcpHolePunchRpc"

// MethodExchangeMappedAddr is the only method of the service.
const MethodExchangeMappedAddr uint32 = 0

// Timing constants mirroring the reference TCP punch behavior.
const (
	// connectAttemptTimeout bounds one simultaneous-connect dial.
	connectAttemptTimeout = 3 * time.Second
	// connectLoopDeadline caps the whole connect loop.
	connectLoopDeadline = 10 * time.Second
	// initiatorAcceptWindow bounds the fallback accept phase.
	initiatorAcceptWindow = 10 * time.Second
	// exchangeRPCTimeout bounds the mapped address exchange.
	exchangeRPCTimeout = 6 * time.Second
	// maxServerAttempts is the responder's simultaneous connect budget.
	maxServerAttempts = 5
	// maxInitiatorAttempts is the initiator's connect budget before fallback.
	maxInitiatorAttempts = 1
	// BlacklistTimeout is how long an unresponsive peer stays excluded.
	BlacklistTimeout = time.Hour
)

// initiated by this node; server-side ones were accepted from the remote.
type Handoff struct {
	OnClientConn func(ctx context.Context, conn net.Conn) error
	OnServerConn func(ctx context.Context, conn net.Conn) error
}

// Service implements the TcpHolePunchRpc responder.
type Service struct {
	stun      stun.Source
	handoff   Handoff
	blacklist *timedSet
}

// NewService builds the TCP punch responder.
func NewService(stunSource stun.Source, handoff Handoff) *Service {
	return &Service{stun: stunSource, handoff: handoff, blacklist: newTimedSet(BlacklistTimeout)}
}

// ServiceName implements rpc.RpcService.
func (s *Service) ServiceName() string { return ServiceName }

// HandleMethod implements rpc.RpcService.
func (s *Service) HandleMethod(methodIndex uint32, ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
	if methodIndex != MethodExchangeMappedAddr {
		return nil, fmt.Errorf("unknown %s method %d", ServiceName, methodIndex)
	}
	var request peer_rpc.TcpHolePunchRequest
	if len(requestBody) > 0 {
		if err := (protojson.UnmarshalOptions{}).Unmarshal(requestBody, &request); err != nil {
			return nil, fmt.Errorf("decode tcp hole punch request: %w", err)
		}
	}
	response, err := s.exchangeMappedAddr(ctx, &request)
	if err != nil {
		return nil, err
	}
	body, err := protojson.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("encode tcp hole punch response: %w", err)
	}
	return body, nil
}

func (s *Service) exchangeMappedAddr(ctx context.Context, request *peer_rpc.TcpHolePunchRequest) (*peer_rpc.TcpHolePunchResponse, error) {
	info := s.stun.GetStunInfo()
	if info.GetTcpNatType() == common.NatType_Unknown {
		return nil, errors.New("tcp nat type unknown not supported")
	}

	connectorMapped, err := protoToAddrPort(request.GetConnectorMappedAddr())
	if err != nil {
		return nil, err
	}
	if connectorMapped.Addr().IsUnspecified() || connectorMapped.Addr().IsMulticast() {
		return nil, errors.New("connector_mapped_addr is malformed")
	}

	localPort, err := selectLocalPort(connectorMapped.Addr().Is6())
	if err != nil {
		return nil, err
	}
	mapped, err := s.stun.GetTCPPortMapping(ctx, localPort)
	if err != nil {
		return nil, fmt.Errorf("get tcp port mapping: %w", err)
	}

	// Respond first; the simultaneous connect runs in the background so the
	// initiator learns our mapped address before we start dialing.
	go func() {
		dialCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), connectLoopDeadline+time.Second)
		defer cancel()
		_ = connectToRemote(dialCtx, connectorMapped, localPort, maxServerAttempts, s.handoff.OnClientConn)
	}()

	response := &peer_rpc.TcpHolePunchResponse{}
	response.ListenerMappedAddr, err = addrPortToProto(mapped)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Initiator drives the TCP punch from the initiating side.
type Initiator struct {
	RPC       caller
	Domain    string
	Stun      stun.Source
	Blacklist *timedSet
	Handoff   Handoff
}

// caller is the peer RPC surface the initiator needs.
type caller interface {
	Call(ctx context.Context, dstPeerID uint32, domain, serviceName string, methodIndex uint32, requestBody []byte) ([]byte, error)
}

// NewInitiator builds a TCP punch initiator.
func NewInitiator(rpcCaller caller, domain string, stunSource stun.Source, handoff Handoff) *Initiator {
	return &Initiator{
		RPC:       rpcCaller,
		Domain:    domain,
		Stun:      stunSource,
		Blacklist: newTimedSet(BlacklistTimeout),
		Handoff:   handoff,
	}
}

// isSymmetricTCPNat reports whether the TCP NAT defeats simultaneous connect.
func isSymmetricTCPNat(natType common.NatType) bool {
	switch natType {
	case common.NatType_Symmetric, common.NatType_SymmetricEasyInc, common.NatType_SymmetricEasyDec:
		return true
	default:
		return false
	}
}

// PunchPeer runs the initiator retry loop for one peer. It returns once a
// connection was handed off, the peer blacklists us, or ctx ends.
func (i *Initiator) PunchPeer(ctx context.Context, dstPeerID uint32) {
	backoff := []time.Duration{time.Second, time.Second, 4 * time.Second, 8 * time.Second}
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return
		}
		if i.Blacklist.contains(dstPeerID) {
			return
		}
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff[min(attempt-1, len(backoff)-1)]):
			}
		}
		if err := i.punchOnce(ctx, dstPeerID); err == nil {
			return
		}
	}
}

func (i *Initiator) punchOnce(ctx context.Context, dstPeerID uint32) error {
	info := i.Stun.GetStunInfo()
	myTCPNat := info.GetTcpNatType()
	if myTCPNat == common.NatType_Unknown || isSymmetricTCPNat(myTCPNat) {
		// Nothing to punch from here; treat as a clean no-op.
		return nil
	}

	localPort, err := selectLocalPort(false)
	if err != nil {
		return err
	}
	mapped, err := i.Stun.GetTCPPortMapping(ctx, localPort)
	if err != nil {
		return fmt.Errorf("get tcp port mapping: %w", err)
	}

	requestBody, err := protojson.Marshal(&peer_rpc.TcpHolePunchRequest{
		ConnectorMappedAddr: mustAddrPortToProto(mapped),
	})
	if err != nil {
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, exchangeRPCTimeout)
	responseBody, err := i.RPC.Call(callCtx, dstPeerID, i.Domain, ServiceName, MethodExchangeMappedAddr, requestBody)
	cancel()
	if err != nil {
		i.Blacklist.insert(dstPeerID)
		return err
	}
	var response peer_rpc.TcpHolePunchResponse
	if err := (protojson.UnmarshalOptions{}).Unmarshal(responseBody, &response); err != nil {
		return fmt.Errorf("decode tcp hole punch response: %w", err)
	}
	remoteMapped, err := protoToAddrPort(response.GetListenerMappedAddr())
	if err != nil {
		return err
	}

	if err := connectToRemote(ctx, remoteMapped, localPort, maxInitiatorAttempts, i.Handoff.OnServerConn); err == nil {
		return nil
	}

	// Simultaneous connect failed; fall back to accepting the remote's
	// connection on the same local port.
	return acceptOnce(ctx, localPort, initiatorAcceptWindow, i.Handoff.OnServerConn)
}

// selectLocalPort picks an ephemeral TCP port by binding and releasing it.
func selectLocalPort(isV6 bool) (uint16, error) {
	network, addr := "tcp4", "0.0.0.0:0"
	if isV6 {
		network, addr = "tcp6", "[::]:0"
	}
	listener, err := net.Listen(network, addr)
	if err != nil {
		return 0, fmt.Errorf("select local tcp port: %w", err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.Close()
	return port, nil
}

// connectToRemote runs the simultaneous connect loop, handing every
// established connection to handoff.
func connectToRemote(ctx context.Context, remote netip.AddrPort, localPort uint16, maxAttempts int, handoff func(context.Context, net.Conn) error) error {
	if handoff == nil {
		return errors.New("tcp punch handoff is missing")
	}
	localAddr := &net.TCPAddr{Port: int(localPort)}
	if remote.Addr().Is4() {
		localAddr.IP = net.IPv4zero
	} else {
		localAddr.IP = net.IPv6zero
	}
	remoteAddr := &net.TCPAddr{IP: net.IP(remote.Addr().AsSlice()), Port: int(remote.Port())}

	start := time.Now()
	for attempts := 0; attempts < maxAttempts && time.Since(start) < connectLoopDeadline; attempts++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		dialer := net.Dialer{LocalAddr: localAddr, Timeout: connectAttemptTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", remoteAddr.String())
		if err == nil {
			if handoffErr := handoff(ctx, conn); handoffErr != nil {
				_ = conn.Close()
				continue
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(10+rand.Intn(90)) * time.Millisecond):
		}
	}
	return errors.New("tcp hole punch connect loop timeout")
}

// acceptOnce listens on localPort and hands the first accepted connection to
// handoff within window.
func acceptOnce(ctx context.Context, localPort uint16, window time.Duration, handoff func(context.Context, net.Conn) error) error {
	if handoff == nil {
		return errors.New("tcp punch handoff is missing")
	}
	listener, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", localPort))
	if err != nil {
		return fmt.Errorf("tcp punch fallback listen: %w", err)
	}
	defer listener.Close()

	acceptCtx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	go func() {
		<-acceptCtx.Done()
		_ = listener.Close()
	}()

	conn, err := listener.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("tcp punch fallback accept: %w", err)
	}
	if handoffErr := handoff(acceptCtx, conn); handoffErr != nil {
		_ = conn.Close()
		return handoffErr
	}
	return nil
}

type timedSet struct {
	timeout time.Duration

	mu      sync.Mutex
	entries map[uint32]time.Time
}

func newTimedSet(timeout time.Duration) *timedSet {
	return &timedSet{timeout: timeout, entries: make(map[uint32]time.Time)}
}

func (s *timedSet) insert(peerID uint32) {
	s.mu.Lock()
	s.entries[peerID] = time.Now()
	s.mu.Unlock()
}

func (s *timedSet) contains(peerID uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	inserted, ok := s.entries[peerID]
	if !ok {
		return false
	}
	if time.Since(inserted) >= s.timeout {
		delete(s.entries, peerID)
		return false
	}
	return true
}

func addrPortToProto(addr netip.AddrPort) (*common.SocketAddr, error) {
	if !addr.IsValid() {
		return nil, errors.New("socket address is invalid")
	}
	if addr.Addr().Is4() {
		raw := addr.Addr().As4()
		return &common.SocketAddr{
			Ip:   &common.SocketAddr_Ipv4{Ipv4: &common.Ipv4Addr{Addr: uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])}},
			Port: uint32(addr.Port()),
		}, nil
	}
	raw := addr.Addr().As16()
	return &common.SocketAddr{
		Ip: &common.SocketAddr_Ipv6{Ipv6: &common.Ipv6Addr{
			Part1: uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3]),
			Part2: uint32(raw[4])<<24 | uint32(raw[5])<<16 | uint32(raw[6])<<8 | uint32(raw[7]),
			Part3: uint32(raw[8])<<24 | uint32(raw[9])<<16 | uint32(raw[10])<<8 | uint32(raw[11]),
			Part4: uint32(raw[12])<<24 | uint32(raw[13])<<16 | uint32(raw[14])<<8 | uint32(raw[15]),
		}},
		Port: uint32(addr.Port()),
	}, nil
}

func protoToAddrPort(addr *common.SocketAddr) (netip.AddrPort, error) {
	if addr == nil {
		return netip.AddrPort{}, errors.New("socket address is missing")
	}
	switch value := addr.Ip.(type) {
	case *common.SocketAddr_Ipv4:
		if value.Ipv4 == nil {
			return netip.AddrPort{}, errors.New("IPv4 socket address is empty")
		}
		raw := [4]byte{
			byte(value.Ipv4.Addr >> 24), byte(value.Ipv4.Addr >> 16), byte(value.Ipv4.Addr >> 8), byte(value.Ipv4.Addr),
		}
		return netip.AddrPortFrom(netip.AddrFrom4(raw), uint16(addr.Port)), nil
	case *common.SocketAddr_Ipv6:
		if value.Ipv6 == nil {
			return netip.AddrPort{}, errors.New("IPv6 socket address is empty")
		}
		raw := [16]byte{
			byte(value.Ipv6.Part1 >> 24), byte(value.Ipv6.Part1 >> 16), byte(value.Ipv6.Part1 >> 8), byte(value.Ipv6.Part1),
			byte(value.Ipv6.Part2 >> 24), byte(value.Ipv6.Part2 >> 16), byte(value.Ipv6.Part2 >> 8), byte(value.Ipv6.Part2),
			byte(value.Ipv6.Part3 >> 24), byte(value.Ipv6.Part3 >> 16), byte(value.Ipv6.Part3 >> 8), byte(value.Ipv6.Part3),
			byte(value.Ipv6.Part4 >> 24), byte(value.Ipv6.Part4 >> 16), byte(value.Ipv6.Part4 >> 8), byte(value.Ipv6.Part4),
		}
		return netip.AddrPortFrom(netip.AddrFrom16(raw), uint16(addr.Port)), nil
	default:
		return netip.AddrPort{}, errors.New("socket address has no IP")
	}
}

func mustAddrPortToProto(addr netip.AddrPort) *common.SocketAddr {
	value, err := addrPortToProto(addr)
	if err != nil {
		return nil
	}
	return value
}

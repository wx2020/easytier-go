// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package punch

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/nat"
	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/stun"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Client strategy tuning constants mirroring the reference behavior.
const (
	// ConePunchSocketCount is the array size for cone punching.
	ConePunchSocketCount = 1
	// HardSymSocketCount is the array size for hard symmetric punching.
	HardSymSocketCount = 84
	// BothEasySymSocketCount is the array size for both easy symmetric.
	BothEasySymSocketCount = 25
	// bothEasySymDSTPortOffset is the port prediction offset.
	bothEasySymDSTPortOffset = 20
	// bothEasySymRemoteWaitMS is the remote wait window.
	bothEasySymRemoteWaitMS = 5000
	// easySymMaxPorts is the prediction span for easy symmetric punching.
	easySymMaxPorts = 50
	// coneBatches / conePerBatch / coneIntervalMS shape the remote cone burst.
	coneBatches    = 5
	conePerBatch   = 2
	coneIntervalMS = 400
	// punchProbeInterval paces the local punched-socket polling loop.
	punchProbeInterval = 200 * time.Millisecond
	// punchTailWait keeps polling briefly after the RPC task finishes.
	punchTailWait = time.Second
)

// Clients drives the three punch strategies from the client side.
type Clients struct {
	RPC       *rpc.PeerRpcManager
	Domain    string
	MyPeerID  uint32
	Stun      stun.Source
	Mapper    PortMapper
	Blacklist *TimedSet

	// ManagedLocalAddr optionally reports whether a candidate local source
	// address belongs to the overlay (such traffic must not be punched).
	ManagedLocalAddr func(netip.AddrPort) bool

	symMu      symMutex
	arrayMu    sync.Mutex
	udpArray   *UdpSocketArray
	arrayReady bool
}

// LockSym serializes symmetric punch rounds across strategies.
func (c *Clients) LockSym() { c.symMu.mu.Lock() }

// UnlockSym releases the symmetric punch serialization.
func (c *Clients) UnlockSym() { c.symMu.mu.Unlock() }

// callMethod performs one protojson peer RPC call, blacklisting the peer for
// an hour when the remote does not implement the service.
func (c *Clients) callMethod(ctx context.Context, dstPeerID uint32, method uint32, request proto.Message) ([]byte, error) {
	body, err := protojson.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode punch rpc request: %w", err)
	}
	response, err := c.RPC.Call(ctx, dstPeerID, c.Domain, ServiceName, method, body)
	if err != nil {
		if errors.Is(err, rpc.ErrNoService) {
			c.Blacklist.Insert(dstPeerID)
		}
		return nil, err
	}
	return response, nil
}

func randomUint32() uint32 {
	var raw [4]byte
	_, _ = cryptorand.Read(raw[:])
	return binary.LittleEndian.Uint32(raw[:])
}

// resolveLocalMappedAddr resolves the public address of a local socket,
// preferring a router port mapping over STUN.
func (c *Clients) resolveLocalMappedAddr(ctx context.Context, socket *net.UDPConn) (netip.AddrPort, error) {
	if c.Mapper != nil {
		local, err := netip.ParseAddrPort(socket.LocalAddr().String())
		if err == nil {
			if mapped, mapErr := c.Mapper.AcquireUDPLease(ctx, local.Port()); mapErr == nil {
				return mapped, nil
			}
		}
	}
	return c.Stun.GetUDPPortMappingWithSocket(ctx, socket)
}

// tryConnectWithSocket upgrades a punched socket into a tunnel session by
// performing the UDP SYN/SACK handshake toward the remote mapped address.
func (c *Clients) tryConnectWithSocket(ctx context.Context, socket *net.UDPConn, remote netip.AddrPort) (*transport.UDPSession, error) {
	if c.ManagedLocalAddr != nil {
		local, err := netip.ParseAddrPort(socket.LocalAddr().String())
		if err == nil && c.ManagedLocalAddr(local) {
			return nil, errors.New("local address is overlay managed")
		}
	}
	return transport.DialUDPWithSocket(ctx, socket, &net.UDPAddr{IP: net.IP(remote.Addr().AsSlice()), Port: int(remote.Port())})
}

// prepareSymArray lazily creates the shared symmetric socket array.
func (c *Clients) prepareSymArray() (*UdpSocketArray, error) {
	c.arrayMu.Lock()
	defer c.arrayMu.Unlock()
	if c.udpArray != nil {
		return c.udpArray, nil
	}
	array := NewUdpSocketArray(HardSymSocketCount)
	if err := array.Start(); err != nil {
		array.Close()
		return nil, err
	}
	c.udpArray = array
	return array, nil
}

// ClearUDPArray discards the shared symmetric socket array.
func (c *Clients) ClearUDPArray() {
	c.arrayMu.Lock()
	defer c.arrayMu.Unlock()
	if c.udpArray != nil {
		c.udpArray.Close()
		c.udpArray = nil
	}
}

// ConePunch executes one cone-to-cone punch round. A nil session with a nil
// error means the round found no tunnel (regular failure), while a non-nil
// error reports a hard failure that should roll the retry backoff.
func (c *Clients) ConePunch(ctx context.Context, dstPeerID uint32) (*transport.UDPSession, error) {
	if c.Blacklist.Contains(dstPeerID) {
		return nil, nil
	}

	tid := randomUint32()
	array := NewUdpSocketArray(ConePunchSocketCount)
	defer array.Close()

	selectResponse, err := c.callMethod(ctx, dstPeerID, MethodSelectPunchListener, &peer_rpc.SelectPunchListenerRequest{
		ForceNew:          false,
		PreferPortMapping: true,
	})
	if err != nil {
		return nil, err
	}
	var selectReply peer_rpc.SelectPunchListenerResponse
	if err := (protojson.UnmarshalOptions{}).Unmarshal(selectResponse, &selectReply); err != nil {
		return nil, fmt.Errorf("decode select punch listener response: %w", err)
	}
	remoteMapped, err := protoToAddrPort(selectReply.GetListenerMappedAddr())
	if err != nil {
		return nil, err
	}

	localSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, fmt.Errorf("bind cone punch socket: %w", err)
	}
	localMapped, err := c.resolveLocalMappedAddr(ctx, localSocket)
	if err != nil {
		_ = localSocket.Close()
		return nil, fmt.Errorf("resolve cone punch local public address: %w", err)
	}

	if err := array.AddSocket(localSocket); err != nil {
		_ = localSocket.Close()
		return nil, err
	}
	array.AddInterestTID(tid)
	defer array.RemoveInterestTID(tid)

	packet, err := NewHolePunchPacket(tid, HolePunchBodyLen)
	if err != nil {
		return nil, err
	}
	remoteTarget := &net.UDPAddr{IP: net.IP(remoteMapped.Addr().AsSlice()), Port: int(remoteMapped.Port())}
	sendFromLocal := func() error {
		return array.SendWithAll(packet, remoteTarget)
	}
	if err := sendFromLocal(); err != nil {
		return nil, err
	}

	punchDone := make(chan struct{})
	punchCtx, punchCancel := context.WithTimeout(ctx, 4*time.Second)
	go func() {
		defer close(punchDone)
		defer punchCancel()
		_, _ = c.callMethod(punchCtx, dstPeerID, MethodSendPunchPacketCone, &peer_rpc.SendPunchPacketConeRequest{
			ListenerMappedAddr:  mustAddrPortToProto(remoteMapped),
			DestAddr:            mustAddrPortToProto(localMapped),
			TransactionId:       tid,
			PacketCountPerBatch: conePerBatch,
			PacketBatchCount:    coneBatches,
			PacketIntervalMs:    coneIntervalMS,
		})
	}()

	var finishTime time.Time
	for finishTime.IsZero() || time.Since(finishTime) < punchTailWait {
		if err := Sleep(ctx, punchProbeInterval); err != nil {
			return nil, err
		}
		select {
		case <-punchDone:
			if finishTime.IsZero() {
				finishTime = time.Now()
			}
		default:
		}

		captured, ok := array.TryFetchPunchedSocket(tid)
		if !ok {
			if err := sendFromLocal(); err != nil {
				return nil, err
			}
			continue
		}
		for i := 0; i < 2; i++ {
			session, err := c.tryConnectWithSocket(ctx, captured.Socket, remoteMapped)
			if err == nil {
				return session, nil
			}
		}
		// The socket failed to connect; park it back so later probes can retry.
		_ = array.AddSocket(captured.Socket)
	}
	return nil, nil
}

// SymToConePunch runs one symmetric-to-cone punch round, combining the
// predictable (easy symmetric) and random (hard symmetric) strategies.
func (c *Clients) SymToConePunch(ctx context.Context, dstPeerID uint32, round uint32, lastPortIdx *uint32, myNatInfo nat.UdpNatType) (*transport.UDPSession, error) {
	if c.Blacklist.Contains(dstPeerID) {
		return nil, nil
	}

	array, err := c.prepareSymArray()
	if err != nil {
		return nil, err
	}

	selectResponse, err := c.callMethod(ctx, dstPeerID, MethodSelectPunchListener, &peer_rpc.SelectPunchListenerRequest{
		ForceNew:          false,
		PreferPortMapping: true,
	})
	if err != nil {
		return nil, err
	}
	var selectReply peer_rpc.SelectPunchListenerResponse
	if err := (protojson.UnmarshalOptions{}).Unmarshal(selectResponse, &selectReply); err != nil {
		return nil, fmt.Errorf("decode select punch listener response: %w", err)
	}
	remoteMapped, err := protoToAddrPort(selectReply.GetListenerMappedAddr())
	if err != nil {
		return nil, err
	}

	// A direct connect may succeed when the remote is effectively reachable.
	if direct, directErr := c.tryDirectConnect(ctx, remoteMapped); directErr == nil && direct != nil {
		return direct, nil
	}

	publicIPs := c.ipv4PublicIPs()
	if len(publicIPs) == 0 {
		return nil, errors.New("no public IPv4 available for symmetric punch")
	}

	tid := randomUint32()
	packet, err := NewHolePunchPacket(tid, HolePunchBodyLen)
	if err != nil {
		return nil, err
	}
	array.AddInterestTID(tid)
	defer array.RemoveInterestTID(tid)

	portIndex := uint32(0)
	if lastPortIdx != nil {
		portIndex = *lastPortIdx
	}
	remoteTarget := &net.UDPAddr{IP: net.IP(remoteMapped.Addr().AsSlice()), Port: int(remoteMapped.Port())}
	if err := array.SendWithAll(packet, remoteTarget); err != nil {
		return nil, err
	}

	basePort, hasBase := c.basePortForEasySym(ctx, myNatInfo)
	if hasBase {
		punchCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		punchDone := make(chan struct{})
		go func() {
			defer close(punchDone)
			defer cancel()
			_, _ = c.callMethod(punchCtx, dstPeerID, MethodSendPunchPacketEasySym, &peer_rpc.SendPunchPacketEasySymRequest{
				ListenerMappedAddr: mustAddrPortToProto(remoteMapped),
				PublicIps:          ipv4ListToProto(publicIPs),
				TransactionId:      tid,
				BasePortNum:        basePort,
				MaxPortNum:         easySymMaxPorts,
				IsIncremental:      mustIncrement(myNatInfo),
			})
		}()
		session, err := c.checkSymPunchResult(ctx, array, packet, tid, remoteMapped, punchDone)
		if err != nil {
			return nil, err
		}
		if session != nil {
			return session, nil
		}
	}

	punchCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	punchDone := make(chan struct{})
	var nextPortIndex *uint32
	go func() {
		defer close(punchDone)
		defer cancel()
		response, callErr := c.callMethod(punchCtx, dstPeerID, MethodSendPunchPacketHardSym, &peer_rpc.SendPunchPacketHardSymRequest{
			ListenerMappedAddr: mustAddrPortToProto(remoteMapped),
			PublicIps:          ipv4ListToProto(publicIPs),
			TransactionId:      tid,
			Round:              round,
			PortIndex:          portIndex,
		})
		if callErr != nil {
			return
		}
		var reply peer_rpc.SendPunchPacketHardSymResponse
		if err := (protojson.UnmarshalOptions{}).Unmarshal(response, &reply); err == nil {
			value := reply.GetNextPortIndex()
			nextPortIndex = &value
		}
	}()

	session, err := c.checkSymPunchResult(ctx, array, packet, tid, remoteMapped, punchDone)
	if err != nil {
		return nil, err
	}
	if lastPortIdx != nil {
		if nextPortIndex != nil {
			*lastPortIdx = *nextPortIndex
		} else {
			*lastPortIdx = randomUint32()
		}
	}
	return session, nil
}

// tryDirectConnect attempts a plain handshake from an ephemeral socket.
func (c *Clients) tryDirectConnect(ctx context.Context, remote netip.AddrPort) (*transport.UDPSession, error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	session, err := c.tryConnectWithSocket(ctx, socket, remote)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	return session, nil
}

func (c *Clients) ipv4PublicIPs() []netip.Addr {
	info := c.Stun.GetStunInfo()
	var ips []netip.Addr
	for _, raw := range info.GetPublicIp() {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is4() {
			continue
		}
		ips = append(ips, addr)
	}
	return ips
}

func (c *Clients) basePortForEasySym(ctx context.Context, myNatInfo nat.UdpNatType) (uint32, bool) {
	if !myNatInfo.IsEasySym() {
		return 0, false
	}
	mapped, err := c.Stun.GetUDPPortMapping(ctx, 0)
	if err != nil {
		return 0, false
	}
	return uint32(mapped.Port()), true
}

func mustIncrement(myNatInfo nat.UdpNatType) bool {
	incremental, _ := myNatInfo.IsIncremental()
	return incremental
}

// checkSymPunchResult polls the socket array for a captured socket while the
// remote punch RPC task runs, upgrading captures into tunnel sessions.
func (c *Clients) checkSymPunchResult(ctx context.Context, array *UdpSocketArray, packet []byte, tid uint32, remote netip.AddrPort, punchDone <-chan struct{}) (*transport.UDPSession, error) {
	remoteTarget := &net.UDPAddr{IP: net.IP(remote.Addr().AsSlice()), Port: int(remote.Port())}
	var finishTime time.Time
	for finishTime.IsZero() || time.Since(finishTime) < punchTailWait {
		if err := array.SendWithAll(packet, remoteTarget); err != nil {
			return nil, err
		}
		if err := Sleep(ctx, punchProbeInterval); err != nil {
			return nil, err
		}
		select {
		case <-punchDone:
			if finishTime.IsZero() {
				finishTime = time.Now()
			}
		default:
		}

		captured, ok := array.TryFetchPunchedSocket(tid)
		if !ok {
			continue
		}
		session, err := c.tryConnectWithSocket(ctx, captured.Socket, remote)
		if err == nil {
			return session, nil
		}
		// Re-arm the socket so later captures can retry the handshake.
		_ = array.AddSocket(captured.Socket)
	}
	return nil, nil
}

// BothEasySymPunch runs one both-easy-symmetric punch round. It reports
// whether the remote was busy with another punch.
func (c *Clients) BothEasySymPunch(ctx context.Context, dstPeerID uint32, myNatInfo, peerNatInfo nat.UdpNatType) (*transport.UDPSession, bool, error) {
	if c.Blacklist.Contains(dstPeerID) {
		return nil, false, nil
	}

	array := NewUdpSocketArray(BothEasySymSocketCount)
	defer array.Close()
	if err := array.Start(); err != nil {
		return nil, false, err
	}

	mapped, err := c.Stun.GetUDPPortMapping(ctx, 0)
	if err != nil {
		return nil, false, fmt.Errorf("get udp port mapping: %w", err)
	}
	if !mapped.Addr().Is4() {
		return nil, false, errors.New("both easy sym punch requires IPv4")
	}
	meIncremental, ok := myNatInfo.IsIncremental()
	if !ok {
		return nil, false, errors.New("both easy sym punch requires an easy symmetric local NAT")
	}
	peerIncremental, ok := peerNatInfo.IsIncremental()
	if !ok {
		return nil, false, errors.New("both easy sym punch requires an easy symmetric peer NAT")
	}

	tid := randomUint32()
	array.AddInterestTID(tid)

	dstPortNum := uint32(mapped.Port())
	if meIncremental {
		dstPortNum = saturatingAddU32(dstPortNum, bothEasySymDSTPortOffset)
	} else {
		dstPortNum = saturatingSubU32(dstPortNum, bothEasySymDSTPortOffset)
	}

	callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	response, err := c.callMethod(callCtx, dstPeerID, MethodSendPunchPacketBothEasySym, &peer_rpc.SendPunchPacketBothEasySymRequest{
		TransactionId:  tid,
		PublicIp:       mustIPv4ToProto(mapped.Addr()),
		DstPortNum:     dstPortNum,
		UdpSocketCount: BothEasySymSocketCount,
		WaitTimeMs:     bothEasySymRemoteWaitMS,
	})
	cancel()
	if err != nil {
		return nil, false, err
	}
	var reply peer_rpc.SendPunchPacketBothEasySymResponse
	if err := (protojson.UnmarshalOptions{}).Unmarshal(response, &reply); err != nil {
		return nil, false, fmt.Errorf("decode both easy sym response: %w", err)
	}
	if reply.GetIsBusy() {
		return nil, true, errors.New("remote is busy")
	}
	remoteMapped, err := protoToAddrPort(reply.GetBaseMappedAddr())
	if err != nil {
		return nil, false, err
	}

	remotePort := remoteMapped.Port()
	if peerIncremental {
		remotePort = remotePort + bothEasySymDSTPortOffset
	} else {
		remotePort = remotePort - bothEasySymDSTPortOffset
	}
	remoteTarget := netip.AddrPortFrom(remoteMapped.Addr(), remotePort)

	packet, err := NewHolePunchPacket(tid, HolePunchBodyLen)
	if err != nil {
		return nil, false, err
	}
	targetAddr := &net.UDPAddr{IP: net.IP(remoteTarget.Addr().AsSlice()), Port: int(remoteTarget.Port())}

	deadline := time.Now().Add(time.Duration(bothEasySymRemoteWaitMS+1000) * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if err := array.SendWithAll(packet, targetAddr); err != nil {
			return nil, false, err
		}
		if err := Sleep(ctx, bothEasySymTick); err != nil {
			return nil, false, err
		}
		captured, ok := array.TryFetchPunchedSocket(tid)
		if !ok {
			continue
		}
		for i := 0; i < 2; i++ {
			session, err := c.tryConnectWithSocket(ctx, captured.Socket, remoteTarget)
			if err == nil {
				return session, false, nil
			}
		}
		_ = array.AddSocket(captured.Socket)
	}
	return nil, false, nil
}

func mustAddrPortToProto(addr netip.AddrPort) *common.SocketAddr {
	value, err := addrPortToProto(addr)
	if err != nil {
		return nil
	}
	return value
}

func mustIPv4ToProto(addr netip.Addr) *common.Ipv4Addr {
	value, err := ipv4ToProto(addr)
	if err != nil {
		return nil
	}
	return value
}

func ipv4ListToProto(ips []netip.Addr) []*common.Ipv4Addr {
	values := make([]*common.Ipv4Addr, 0, len(ips))
	for _, ip := range ips {
		if value := mustIPv4ToProto(ip); value != nil {
			values = append(values, value)
		}
	}
	return values
}

func saturatingAddU32(a, b uint32) uint32 {
	sum := a + b
	if sum < a {
		return ^uint32(0)
	}
	return sum
}

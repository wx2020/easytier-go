// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peercenter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	peerrpc "github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
)

// RPC service and method identifiers for the peer-center service. They match
// the reference registry exactly: domain = network name, service name
// PeerCenterRpc in the peer_rpc proto package, and one-based method indexes
// following the proto service declaration order (ReportPeers, then
// GetGlobalPeerMap).
const (
	PeerCenterProtoName           = "peer_rpc.PeerCenterRpc"
	ServiceNamePeerCenter         = "PeerCenterRpc"
	MethodReportPeers      uint32 = 1
	MethodGetGlobalPeerMap uint32 = 2
)

// DefaultRPCDomain is the fallback scoping domain. The reference registers
// peer-center under the network name; callers should always pass it.
const DefaultRPCDomain = "peer_center"

// Scheduling constants mirror the Rust PeerCenterInstance jobs.
const (
	// getGlobalPeerMapInterval is the sleep between get_global_peer_map calls
	// after a successful fetch or digest match.
	getGlobalPeerMapInterval = 15 * time.Second
	// reportPeersInterval is the sleep between report_peers checks.
	reportPeersInterval = 5 * time.Second
	// digestResetAge is how long an unused global map digest is kept before
	// it is reset to force a fresh fetch.
	digestResetAge = 120 * time.Second
)

// Instance runs the peer-center client jobs and serves its RPC service over a
// PeerRpcManager. It is the Go counterpart of Rust PeerCenterInstance.
type Instance struct {
	provider PeerInfoProvider
	rpcMgr   *rpc.PeerRpcManager
	server   *Server
	domain   string

	getRunner    *Runner
	reportRunner *Runner
	ctx          context.Context

	mu             sync.Mutex
	globalPeerMap  map[uint32]GlobalPeerMapEntry
	digest         Digest
	updateTime     time.Time
	lastReportTime time.Time
	lastCenterPeer uint32
	lastReportSet  map[uint32]struct{}
}

// NewInstance creates a peer-center instance bound to one peer RPC manager.
// The provider and domain must be non-empty; the reference registers and
// calls peer-center under the network-name domain.
func NewInstance(provider PeerInfoProvider, mgr *rpc.PeerRpcManager, domain string) (*Instance, error) {
	if provider == nil {
		return nil, fmt.Errorf("peer center provider is required")
	}
	if mgr == nil {
		return nil, fmt.Errorf("peer center rpc manager is required")
	}
	if domain == "" {
		domain = DefaultRPCDomain
	}
	return &Instance{
		provider: provider,
		rpcMgr:   mgr,
		server:   NewServer(),
		domain:   domain,
	}, nil
}

// Server exposes the instance's backing report/get data store.
func (i *Instance) Server() *Server { return i.server }

// RpcService returns the RPC service object to register on the PeerRpcManager
// (under the network-name domain) implementing the peer-center protocol.
func (i *Instance) RpcService() rpc.RpcService {
	return &centerRpcService{instance: i}
}

// GlobalPeerMap returns a snapshot of the last fetched global peer map.
func (i *Instance) GlobalPeerMap() map[uint32]GlobalPeerMapEntry {
	i.mu.Lock()
	defer i.mu.Unlock()
	result := make(map[uint32]GlobalPeerMapEntry, len(i.globalPeerMap))
	for peerID, entry := range i.globalPeerMap {
		peers := make(map[uint32]DirectPeerInfo, len(entry.DirectPeers))
		for dstPeerID, info := range entry.DirectPeers {
			peers[dstPeerID] = info
		}
		result[peerID] = GlobalPeerMapEntry{DirectPeers: peers}
	}
	return result
}

// Digest returns the digest associated with the last fetched global peer map.
func (i *Instance) Digest() Digest {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.digest
}

// getJob runs one get_global_peer_map iteration.
func (i *Instance) getJob(ctx context.Context, centerPeer uint32) JobResult {
	if ctx == nil {
		return JobResult{Err: fmt.Errorf("peer center get job context is nil")}
	}

	if centerPeer == i.provider.MyPeerID() {
		return JobResult{SleepTime: i.serveFromCenter()}
	}

	i.mu.Lock()
	if !i.updateTime.IsZero() && time.Since(i.updateTime) > digestResetAge {
		i.digest = 0
	}
	digest := i.digest
	i.mu.Unlock()

	requestBody, err := proto.Marshal(&peerrpc.GetGlobalPeerMapRequest{Digest: uint64(digest)})
	if err != nil {
		return JobResult{Err: err}
	}
	responseBody, err := i.callMethod(ctx, centerPeer, MethodGetGlobalPeerMap, requestBody)
	if err != nil {
		return JobResult{Err: err}
	}
	response := &peerrpc.GetGlobalPeerMapResponse{}
	if err := proto.Unmarshal(responseBody, response); err != nil {
		return JobResult{Err: fmt.Errorf("decode get_global_peer_map response: %w", err)}
	}
	// The reference has no explicit no-update flag: a digest that matches
	// the local one means the map is current (the digest is only compared
	// within one implementation, so cross-implementation fetches simply
	// never short-circuit). GetDigest() yields 0 for the optional-absent
	// case, which matches the initial local digest of 0.
	if Digest(response.GetDigest()) == digest {
		return JobResult{SleepTime: getGlobalPeerMapInterval}
	}

	i.mu.Lock()
	i.globalPeerMap = globalPeerMapFromProto(response)
	i.digest = Digest(response.GetDigest())
	i.updateTime = time.Now()
	i.mu.Unlock()
	return JobResult{SleepTime: getGlobalPeerMapInterval}
}

// reportJob runs one report_peers iteration.
func (i *Instance) reportJob(ctx context.Context, centerPeer uint32) JobResult {
	if ctx == nil {
		return JobResult{Err: fmt.Errorf("peer center report job context is nil")}
	}

	peers := i.provider.ListDirectPeers()
	myPeerID := i.provider.MyPeerID()
	peerSet := make(map[uint32]struct{}, len(peers))
	for peerID := range peers {
		peerSet[peerID] = struct{}{}
	}

	i.mu.Lock()
	lastCenter := i.lastCenterPeer
	lastSet := i.lastReportSet
	lastReport := i.lastReportTime
	i.mu.Unlock()

	if !lastReport.IsZero() &&
		time.Since(lastReport) < reportPeersInterval &&
		centerPeer == lastCenter &&
		samePeerSet(lastSet, peerSet) {
		return JobResult{SleepTime: reportPeersInterval}
	}

	if centerPeer == myPeerID {
		i.server.ReportPeers(myPeerID, peers)
		i.mu.Lock()
		i.lastCenterPeer = centerPeer
		i.lastReportSet = peerSet
		i.lastReportTime = time.Now()
		i.mu.Unlock()
		return JobResult{SleepTime: reportPeersInterval}
	}

	request := &peerrpc.ReportPeersRequest{
		MyPeerId:  myPeerID,
		PeerInfos: peerInfoForGlobalMapProto(peers),
	}
	requestBody, err := proto.Marshal(request)
	if err != nil {
		return JobResult{Err: err}
	}
	if _, err := i.callMethod(ctx, centerPeer, MethodReportPeers, requestBody); err != nil {
		return JobResult{Err: err}
	}

	i.mu.Lock()
	i.lastCenterPeer = centerPeer
	i.lastReportSet = peerSet
	i.lastReportTime = time.Now()
	i.mu.Unlock()
	return JobResult{SleepTime: reportPeersInterval}
}

func (i *Instance) callMethod(ctx context.Context, centerPeer uint32, method uint32, requestBody []byte) ([]byte, error) {
	return i.rpcMgr.CallDescriptor(ctx, centerPeer, &rpc.RpcDescriptor{
		DomainName:  i.domain,
		ProtoName:   PeerCenterProtoName,
		ServiceName: ServiceNamePeerCenter,
		MethodIndex: method,
	}, requestBody)
}

// serveFromCenter refreshes the local view from the local server store when
// this node is itself the center. It returns the job sleep for the get job.
func (i *Instance) serveFromCenter() time.Duration {
	i.mu.Lock()
	digest := i.digest
	i.mu.Unlock()

	_, serverDigest, noUpdate := i.server.GetGlobalPeerMap(digest)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.digest = serverDigest
	if noUpdate {
		return getGlobalPeerMapInterval
	}
	i.globalPeerMap = i.server.Snapshot()
	i.updateTime = time.Now()
	return getGlobalPeerMapInterval
}

// Start registers the RPC service and starts the two periodic job runners.
func (i *Instance) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("peer center start context is nil")
	}
	if err := i.rpcMgr.Register(i.domain, i.RpcService()); err != nil {
		return fmt.Errorf("register peer center rpc service: %w", err)
	}

	i.ctx = ctx
	i.getRunner = NewRunner(i.provider.MyPeerID(), i.provider.ListRoutes, i.getJob)
	i.reportRunner = NewRunner(i.provider.MyPeerID(), i.provider.ListRoutes, i.reportJob)
	i.getRunner.Start()
	i.reportRunner.Start()
	return nil
}

// Stop stops both job runners and unregisters the RPC service.
func (i *Instance) Stop() {
	if i.getRunner != nil {
		i.getRunner.Stop()
	}
	if i.reportRunner != nil {
		i.reportRunner.Stop()
	}
	i.rpcMgr.Unregister(i.domain, ServiceNamePeerCenter)
}

// Context returns the instance lifecycle context.
func (i *Instance) Context() context.Context { return i.ctx }

func samePeerSet(a, b map[uint32]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for peerID := range a {
		if _, ok := b[peerID]; !ok {
			return false
		}
	}
	return true
}

// peerInfoForGlobalMapProto converts direct-peer latency snapshots into the
// reference PeerInfoForGlobalMap message.
func peerInfoForGlobalMapProto(peers map[uint32]DirectPeerInfo) *peerrpc.PeerInfoForGlobalMap {
	if len(peers) == 0 {
		return nil
	}
	direct := make(map[uint32]*peerrpc.DirectConnectedPeerInfo, len(peers))
	for peerID, info := range peers {
		direct[peerID] = &peerrpc.DirectConnectedPeerInfo{LatencyMs: info.LatencyMS}
	}
	return &peerrpc.PeerInfoForGlobalMap{DirectPeers: direct}
}

// globalPeerMapFromProto converts a reference GetGlobalPeerMapResponse into
// the instance's per-source global map snapshot.
func globalPeerMapFromProto(response *peerrpc.GetGlobalPeerMapResponse) map[uint32]GlobalPeerMapEntry {
	result := make(map[uint32]GlobalPeerMapEntry, len(response.GetGlobalPeerMap()))
	for srcPeerID, group := range response.GetGlobalPeerMap() {
		peers := make(map[uint32]DirectPeerInfo, len(group.GetDirectPeers()))
		for dstPeerID, info := range group.GetDirectPeers() {
			peers[dstPeerID] = DirectPeerInfo{LatencyMS: info.GetLatencyMs()}
		}
		result[srcPeerID] = GlobalPeerMapEntry{DirectPeers: peers}
	}
	return result
}

// centerRpcService implements rpc.RpcService for the peer-center protocol.
type centerRpcService struct {
	instance *Instance
}

func (s *centerRpcService) ServiceName() string { return ServiceNamePeerCenter }

func (s *centerRpcService) HandleMethod(methodIndex uint32, ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
	switch methodIndex {
	case MethodReportPeers:
		request := &peerrpc.ReportPeersRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode report_peers request: %w", err)
		}
		if request.GetMyPeerId() == 0 {
			return nil, fmt.Errorf("report_peers request is missing my_peer_id")
		}
		peers := make(map[uint32]DirectPeerInfo, len(request.GetPeerInfos().GetDirectPeers()))
		for peerID, info := range request.GetPeerInfos().GetDirectPeers() {
			peers[peerID] = DirectPeerInfo{LatencyMS: info.GetLatencyMs()}
		}
		s.instance.server.ReportPeers(request.GetMyPeerId(), peers)
		_ = fromPeerID
		return proto.Marshal(&peerrpc.ReportPeersResponse{})
	case MethodGetGlobalPeerMap:
		request := &peerrpc.GetGlobalPeerMapRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode get_global_peer_map request: %w", err)
		}
		return s.handleGetGlobalPeerMap(Digest(request.GetDigest()))
	default:
		return nil, fmt.Errorf("unknown peer center rpc method %d", methodIndex)
	}
}

func (s *centerRpcService) handleGetGlobalPeerMap(requestDigest Digest) ([]byte, error) {
	globalMap, serverDigest, noUpdate := s.instance.server.GetGlobalPeerMap(requestDigest)
	response := &peerrpc.GetGlobalPeerMapResponse{}
	digest := uint64(serverDigest)
	response.Digest = &digest
	if !noUpdate {
		response.GlobalPeerMap = make(map[uint32]*peerrpc.PeerInfoForGlobalMap, len(globalMap))
		for pair, info := range globalMap {
			group, ok := response.GlobalPeerMap[pair.Source]
			if !ok {
				group = &peerrpc.PeerInfoForGlobalMap{DirectPeers: make(map[uint32]*peerrpc.DirectConnectedPeerInfo)}
				response.GlobalPeerMap[pair.Source] = group
			}
			group.DirectPeers[pair.Dest] = &peerrpc.DirectConnectedPeerInfo{LatencyMs: info.LatencyMS}
		}
	}
	body, err := proto.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("encode get_global_peer_map response: %w", err)
	}
	return body, nil
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peercenter

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/rpc"
)

// RPC service and method identifiers for the peer-center service.
const (
	ServiceNamePeerCenter         = "peer_center"
	MethodGetGlobalPeerMap uint32 = 0
	MethodReportPeers      uint32 = 1
)

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
// The provider must be non-nil.
func NewInstance(provider PeerInfoProvider, mgr *rpc.PeerRpcManager) (*Instance, error) {
	if provider == nil {
		return nil, fmt.Errorf("peer center provider is required")
	}
	if mgr == nil {
		return nil, fmt.Errorf("peer center rpc manager is required")
	}
	return &Instance{
		provider: provider,
		rpcMgr:   mgr,
		server:   NewServer(),
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

	requestBody, err := json.Marshal(getGlobalPeerMapRequest{Digest: digest})
	if err != nil {
		return JobResult{Err: err}
	}
	responseBody, err := i.callMethod(ctx, centerPeer, MethodGetGlobalPeerMap, requestBody)
	if err != nil {
		return JobResult{Err: err}
	}
	var response getGlobalPeerMapResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return JobResult{Err: fmt.Errorf("decode get_global_peer_map response: %w", err)}
	}
	if response.NoUpdate {
		return JobResult{SleepTime: getGlobalPeerMapInterval}
	}

	i.mu.Lock()
	i.globalPeerMap = peerMapFromResponse(response)
	i.digest = response.Digest
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

	requestBody, err := json.Marshal(reportPeersRequest{
		MyPeerID: myPeerID,
		Peers:    peers,
	})
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
	return i.rpcMgr.Call(ctx, centerPeer, rpcDomain, ServiceNamePeerCenter, method, requestBody)
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
	if err := i.rpcMgr.Register(rpcDomain, i.RpcService()); err != nil {
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
	i.rpcMgr.Unregister(rpcDomain, ServiceNamePeerCenter)
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

func peerMapFromResponse(response getGlobalPeerMapResponse) map[uint32]GlobalPeerMapEntry {
	result := make(map[uint32]GlobalPeerMapEntry, len(response.GlobalPeerMap))
	for srcPeerID, group := range response.GlobalPeerMap {
		peers := make(map[uint32]DirectPeerInfo, len(group))
		for dstPeerID, info := range group {
			peers[dstPeerID] = info
		}
		result[srcPeerID] = GlobalPeerMapEntry{DirectPeers: peers}
	}
	return result
}

// rpcDomain is the scoping domain used for the peer-center RPC service. Both
// the center client and the center server register and call under this domain
// so descriptors always match.
const rpcDomain = "peer_center"

// centerRpcService implements rpc.RpcService for the peer-center protocol.
type centerRpcService struct {
	instance *Instance
}

func (s *centerRpcService) ServiceName() string { return ServiceNamePeerCenter }

func (s *centerRpcService) HandleMethod(methodIndex uint32, ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
	switch methodIndex {
	case MethodGetGlobalPeerMap:
		var request getGlobalPeerMapRequest
		if err := json.Unmarshal(requestBody, &request); err != nil {
			return nil, fmt.Errorf("decode get_global_peer_map request: %w", err)
		}
		return s.handleGetGlobalPeerMap(request.Digest)
	case MethodReportPeers:
		var request reportPeersRequest
		if err := json.Unmarshal(requestBody, &request); err != nil {
			return nil, fmt.Errorf("decode report_peers request: %w", err)
		}
		if request.MyPeerID == 0 {
			return nil, fmt.Errorf("report_peers request is missing my_peer_id")
		}
		s.instance.server.ReportPeers(request.MyPeerID, request.Peers)
		_ = fromPeerID
		return []byte(`{}`), nil
	default:
		return nil, fmt.Errorf("unknown peer center rpc method %d", methodIndex)
	}
}

func (s *centerRpcService) handleGetGlobalPeerMap(requestDigest Digest) ([]byte, error) {
	globalMap, serverDigest, noUpdate := s.instance.server.GetGlobalPeerMap(requestDigest)
	response := getGlobalPeerMapResponse{
		Digest: serverDigest,
	}
	if noUpdate {
		response.NoUpdate = true
	} else {
		response.GlobalPeerMap = make(map[uint32]map[uint32]DirectPeerInfo, len(globalMap))
		for pair, info := range globalMap {
			group, ok := response.GlobalPeerMap[pair.Source]
			if !ok {
				group = make(map[uint32]DirectPeerInfo)
				response.GlobalPeerMap[pair.Source] = group
			}
			group[pair.Dest] = info
		}
	}
	body, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("encode get_global_peer_map response: %w", err)
	}
	return body, nil
}

type getGlobalPeerMapRequest struct {
	Digest Digest `json:"digest"`
}

type reportPeersRequest struct {
	MyPeerID uint32                    `json:"my_peer_id"`
	Peers    map[uint32]DirectPeerInfo `json:"peers"`
}

type getGlobalPeerMapResponse struct {
	GlobalPeerMap map[uint32]map[uint32]DirectPeerInfo `json:"global_peer_map,omitempty"`
	Digest        Digest                               `json:"digest"`
	NoUpdate      bool                                 `json:"no_update"`
}

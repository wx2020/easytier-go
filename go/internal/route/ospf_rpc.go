// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	peerrpc "github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
)

// OSPF RPC method indexes. The reference service exposes exactly one method,
// SyncRouteInfo, and method indexes are one-based in the reference RPC
// descriptor, so the wire index is 1.
const (
	// MethodOSPFRouteSync carries one SyncRouteInfoRequest protobuf.
	MethodOSPFRouteSync uint32 = 1
)

// ospfAnnounceTimeout bounds one per-neighbor sync RPC.
const ospfAnnounceTimeout = 3 * time.Second

// NewOSPFService exposes the flooder over peer-RPC under the reference
// service identity: remote neighbors call SyncRouteInfo with a
// SyncRouteInfoRequest protobuf, which is converted to an LSA and installed
// via Flooder.Receive (deduped, then relayed).
func NewOSPFService(flooder *Flooder) *rpc.FuncService {
	service := rpc.NewFuncService(rpc.ServiceNameOSPFRoute)
	service.OnMethod(MethodOSPFRouteSync, func(ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
		if flooder == nil {
			return nil, fmt.Errorf("ospf flooder is not configured")
		}
		if len(requestBody) > MaxSyncRouteInfoRequestSize {
			return nil, fmt.Errorf("ospf sync request size %d exceeds limit %d", len(requestBody), MaxSyncRouteInfoRequestSize)
		}
		request := &peerrpc.SyncRouteInfoRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode ospf sync request: %w", err)
		}
		advertisement, err := advertisementFromSyncRequest(request, fromPeerID)
		if err != nil {
			return nil, err
		}
		if _, err := flooder.Receive(ctx, advertisement, fromPeerID); err != nil {
			return nil, err
		}
		response := &peerrpc.SyncRouteInfoResponse{
			IsInitiator: false,
			SessionId:   flooder.SessionID(),
		}
		return proto.Marshal(response)
	})
	return service
}

// MeshBroadcast returns a BroadcastFunc that syncs one LSA to every direct
// neighbor (except exceptOrigin) through the peer-RPC mesh under the
// reference OspfRouteRpc identity, mirroring the reference LSA flooding over
// peer RPC. neighbors reports the current direct peer IDs; domain scopes the
// RPC service (typically the network name); sessionID is the local sync
// session identifier.
func MeshBroadcast(mgr *rpc.PeerRpcManager, domain string, neighbors func() []uint32, sessionID uint64) BroadcastFunc {
	return func(ctx context.Context, advertisement Advertisement, exceptOrigin uint32) error {
		if mgr == nil {
			return fmt.Errorf("ospf mesh broadcast requires a peer rpc manager")
		}
		request, err := syncRequestFromAdvertisement(advertisement, sessionID)
		if err != nil {
			return err
		}
		wire, err := proto.Marshal(request)
		if err != nil {
			return fmt.Errorf("encode ospf sync request: %w", err)
		}
		descriptor := &rpc.RpcDescriptor{
			DomainName:  domain,
			ProtoName:   OSPFRouteProtoName,
			ServiceName: rpc.ServiceNameOSPFRoute,
			MethodIndex: MethodOSPFRouteSync,
		}
		var firstErr error
		for _, neighbor := range neighbors() {
			if neighbor == 0 || neighbor == exceptOrigin {
				continue
			}
			callCtx, cancel := context.WithTimeout(ctx, ospfAnnounceTimeout)
			_, err := mgr.CallDescriptor(callCtx, neighbor, descriptor, wire)
			cancel()
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
}

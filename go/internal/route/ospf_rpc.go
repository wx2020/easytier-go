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

// OSPFServiceConfig carries the optional policy the SyncRouteInfo handler
// enforces on top of flooding.
type OSPFServiceConfig struct {
	// NetworkSecret verifies inbound credential proofs; empty disables
	// verification (a credential node itself holds no secret).
	NetworkSecret string
	// IsCredentialPeer classifies a sender as an unprivileged credential
	// peer. Nil means the local identity model does not classify peers yet
	// and credential enforcement is inert.
	IsCredentialPeer func(peerID uint32) bool
}

// NewOSPFService exposes the flooder over peer-RPC under the reference
// service identity: remote neighbors call SyncRouteInfo with a
// SyncRouteInfoRequest protobuf, which is converted to an LSA and installed
// via Flooder.Receive (deduped, then relayed).
//
// The handler implements the reference session semantics: it tracks each
// peer's sync-session identifier, verifies admin-signed credential proofs,
// detects duplicate peer ids through the flooded route identities, and
// rejects duplicated or unprivileged senders with
// SyncRouteInfoError_DuplicatePeerId.
func NewOSPFService(flooder *Flooder, cfg *OSPFServiceConfig) *rpc.FuncService {
	tracker := NewSessionTracker()
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
		// Reference update_dst_session_id: a changed session id means the
		// peer restarted its route service. The flooder keeps no per-dst
		// sync state, so only the observation is recorded.
		tracker.Observe(fromPeerID, request.GetMySessionId())

		lsas, err := advertisementsFromSyncRequest(request, fromPeerID)
		if err != nil {
			return nil, err
		}
		secret := ""
		var credentialPeer bool
		if cfg != nil {
			secret = cfg.NetworkSecret
			credentialPeer = cfg.IsCredentialPeer != nil && cfg.IsCredentialPeer(fromPeerID)
		}
		// Reference check_duplicate_peer_id: conflicting route identities
		// with version regressions flag duplicated peer ids.
		if duplicate := checkDuplicatePeerID(flooder, request, fromPeerID); duplicate {
			return syncRouteInfoErrorResponse(flooder)
		}

		for i := range lsas {
			// Only proofs that authenticate under our network secret are
			// trustworthy; anything else is dropped before use.
			lsas[i].TrustedCredentials = VerifiedTrustedCredentials(lsas[i].TrustedCredentials, secret)
			// Credential peers may only propagate their own route info, and
			// their connection info requires a verified relay permission.
			if credentialPeer && lsas[i].Origin == fromPeerID &&
				!VerifiedCredentialAllowsRelay(lsas[i].TrustedCredentials, secret) {
				lsas[i].Peers = nil
			}
			if _, err := flooder.Receive(ctx, lsas[i], fromPeerID); err != nil {
				return nil, err
			}
		}
		response := &peerrpc.SyncRouteInfoResponse{
			IsInitiator: false,
			SessionId:   flooder.SessionID(),
		}
		return proto.Marshal(response)
	})
	return service
}

// checkDuplicatePeerID mirrors the reference duplicate detection: a remote
// carrying our identity under a different route id with a higher version, or
// a sender whose own entry regressed under a different route id, exposes a
// duplicated peer id in the network. Entries without a route id (0) carry no
// identity claim and are exempt.
func checkDuplicatePeerID(flooder *Flooder, request *peerrpc.SyncRouteInfoRequest, fromPeerID uint32) bool {
	myPeerID := flooder.LocalPeerID()
	myRouteID := flooder.SessionID()
	for _, item := range request.GetPeerInfos().GetItems() {
		if item.GetPeerRouteId() == 0 {
			continue
		}
		switch item.GetPeerId() {
		case myPeerID:
			// The sender floods an entry about us: a different route id
			// with a higher version means our own peer id is duplicated.
			if item.GetPeerRouteId() != myRouteID && uint64(item.GetVersion()) > flooder.OriginVersion() {
				return true
			}
		case fromPeerID:
			// The sender floods its own entry: a different route id with a
			// lower version than the stored one means the sender's peer id
			// is duplicated between two live nodes.
			if stored := flooder.PeerRouteID(fromPeerID); stored != 0 &&
				item.GetPeerRouteId() != stored && uint64(item.GetVersion()) < flooder.SeenVersion(fromPeerID) {
				return true
			}
		}
	}
	return false
}

// syncRouteInfoErrorResponse builds the reference duplicate-peer rejection.
func syncRouteInfoErrorResponse(flooder *Flooder) ([]byte, error) {
	duplicate := peerrpc.SyncRouteInfoError_DuplicatePeerId
	response := &peerrpc.SyncRouteInfoResponse{
		IsInitiator: false,
		SessionId:   flooder.SessionID(),
		Error:       &duplicate,
	}
	return proto.Marshal(response)
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
			responseBody, err := mgr.CallDescriptor(callCtx, neighbor, descriptor, wire)
			cancel()
			if err == nil {
				if err = syncResponseError(responseBody); err != nil {
					err = fmt.Errorf("ospf sync to peer %d rejected: %w", neighbor, err)
				}
			}
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
}

// syncResponseError decodes the reference rejection carried in a sync
// response.
func syncResponseError(responseBody []byte) error {
	response := &peerrpc.SyncRouteInfoResponse{}
	if err := proto.Unmarshal(responseBody, response); err != nil {
		return nil
	}
	// The error field is optional and DuplicatePeerId is the ZERO enum
	// value: an absent error on a successful response must not be read as
	// a rejection, so test the pointer, not the getter.
	if response.Error != nil && *response.Error == peerrpc.SyncRouteInfoError_DuplicatePeerId {
		return fmt.Errorf("duplicate peer id detected by the remote peer")
	}
	return nil
}

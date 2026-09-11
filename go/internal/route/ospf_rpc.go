// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"context"
	"fmt"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/rpc"
)

// OSPF RPC method indexes served by OSPFService.
const (
	// MethodOSPFAnnounce carries one marshaled Advertisement.
	MethodOSPFAnnounce uint32 = 0
)

// ospfAnnounceTimeout bounds one per-neighbor announce RPC.
const ospfAnnounceTimeout = 3 * time.Second

// NewOSPFService exposes flooder over peer-RPC: remote neighbors announce
// their LSAs by calling MethodOSPFAnnounce with a marshaled Advertisement,
// which is installed via Flooder.Receive (deduped, then relayed).
func NewOSPFService(flooder *Flooder) *rpc.FuncService {
	service := rpc.NewFuncService(rpc.ServiceNameOSPFRoute)
	service.OnMethod(MethodOSPFAnnounce, func(ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
		if flooder == nil {
			return nil, fmt.Errorf("ospf flooder is not configured")
		}
		advertisement, err := ParseAdvertisement(requestBody)
		if err != nil {
			return nil, err
		}
		if _, err := flooder.Receive(ctx, advertisement, fromPeerID); err != nil {
			return nil, err
		}
		return []byte{}, nil
	})
	return service
}

// MeshBroadcast returns a BroadcastFunc that announces one advertisement to
// every direct neighbor (except exceptOrigin) through the peer-RPC mesh,
// mirroring Rust peer_ospf_route's LSA flooding over peer RPC. neighbors
// reports the current direct peer IDs; domain scopes the RPC service
// (typically the network name).
func MeshBroadcast(mgr *rpc.PeerRpcManager, domain string, neighbors func() []uint32) BroadcastFunc {
	return func(ctx context.Context, advertisement Advertisement, exceptOrigin uint32) error {
		if mgr == nil {
			return fmt.Errorf("ospf mesh broadcast requires a peer rpc manager")
		}
		wire, err := advertisement.Marshal()
		if err != nil {
			return err
		}
		var firstErr error
		for _, neighbor := range neighbors() {
			if neighbor == 0 || neighbor == exceptOrigin {
				continue
			}
			callCtx, cancel := context.WithTimeout(ctx, ospfAnnounceTimeout)
			_, err := mgr.Call(callCtx, neighbor, domain, rpc.ServiceNameOSPFRoute, MethodOSPFAnnounce, wire)
			cancel()
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
}

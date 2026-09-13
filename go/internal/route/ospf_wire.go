// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	peerrpc "github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
)

// OSPFRouteProtoName is the fully-qualified reference service name carried in
// the RPC descriptor; the reference registry keys services by
// (domain, service_name, proto_name) and the OSPF route service lives in the
// peer_rpc proto package.
const OSPFRouteProtoName = "peer_rpc.OspfRouteRpc"

// MaxSyncRouteInfoRequestSize bounds one encoded SyncRouteInfoRequest.
const MaxSyncRouteInfoRequestSize = 1 << 20

// NewSessionID draws a random reference session identifier for one OSPF
// sync-session manager.
func NewSessionID() uint64 {
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint64(id[:])
}

// syncRequestFromAdvertisement encodes one LSA into the reference
// SyncRouteInfoRequest protobuf. The origin's own entry carries its version,
// last-update timestamp and proxy CIDRs; every direct link contributes a
// peer-info entry (so the link cost survives the reference schema) and one
// conn-peer-list row.
func syncRequestFromAdvertisement(adv Advertisement, sessionID uint64) (*peerrpc.SyncRouteInfoRequest, error) {
	peers, cidrs, err := validatedAdvertisement(adv)
	if err != nil {
		return nil, err
	}
	version := uint32(adv.Version)
	lastUpdate := timestamppb.New(time.Unix(adv.Timestamp, 0))

	items := make([]*peerrpc.RoutePeerInfo, 0, len(peers)+1)
	items = append(items, &peerrpc.RoutePeerInfo{
		PeerId:                   adv.Origin,
		Cost:                     0,
		Version:                  version,
		LastUpdate:               lastUpdate,
		ProxyCidrs:               append([]string(nil), cidrs...),
		UdpNatType:               adv.UDPNatType,
		PeerRouteId:              adv.PeerRouteID,
		TrustedCredentialPubkeys: adv.TrustedCredentials,
	})
	connected := make([]uint32, 0, len(peers))
	for _, peer := range peers {
		items = append(items, &peerrpc.RoutePeerInfo{
			PeerId:     peer.Peer,
			Cost:       peer.Cost,
			Version:    version,
			LastUpdate: lastUpdate,
		})
		connected = append(connected, peer.Peer)
	}

	return &peerrpc.SyncRouteInfoRequest{
		MyPeerId:    adv.Origin,
		MySessionId: sessionID,
		IsInitiator: true,
		PeerInfos:   &peerrpc.RoutePeerInfos{Items: items},
		ConnInfo: &peerrpc.SyncRouteInfoRequest_ConnPeerList{
			ConnPeerList: &peerrpc.RouteConnPeerList{
				PeerConnInfos: []*peerrpc.RouteConnPeerList_PeerConnInfo{{
					PeerId:           &peerrpc.PeerIdVersion{PeerId: adv.Origin},
					ConnectedPeerIds: connected,
				}},
			},
		},
	}, nil
}

// advertisementFromSyncRequest decodes one reference SyncRouteInfoRequest
// back into the flooder's LSA form: the origin's links come from its own
// conn-info rows and the per-peer entries carry the link costs. Unknown or
// zero costs fall back to 1, mirroring the reference's unweighted graph.
func advertisementFromSyncRequest(req *peerrpc.SyncRouteInfoRequest, fromPeerID uint32) (Advertisement, error) {
	if req == nil {
		return Advertisement{}, fmt.Errorf("ospf sync request is nil")
	}
	if req.GetPeerInfos() != nil && len(req.GetPeerInfos().GetItems()) > MaxAdvertisementPeers+1 {
		return Advertisement{}, fmt.Errorf("ospf sync request has %d peers, limit is %d", len(req.GetPeerInfos().GetItems()), MaxAdvertisementPeers+1)
	}
	origin := req.GetMyPeerId()
	if origin == 0 {
		origin = fromPeerID
	}
	if origin == 0 {
		return Advertisement{}, fmt.Errorf("ospf sync request origin is zero")
	}

	costs := make(map[uint32]uint32)
	adv := Advertisement{Origin: origin}
	for _, item := range req.GetPeerInfos().GetItems() {
		if item.GetPeerId() == 0 {
			return Advertisement{}, fmt.Errorf("ospf sync request has a zero peer id")
		}
		costs[item.GetPeerId()] = item.GetCost()
		if item.GetPeerId() == origin {
			adv.Version = uint64(item.GetVersion())
			adv.PeerRouteID = item.GetPeerRouteId()
			adv.ProxyCIDRs = append([]string(nil), item.GetProxyCidrs()...)
			adv.UDPNatType = item.GetUdpNatType()
			adv.TrustedCredentials = item.GetTrustedCredentialPubkeys()
			if item.GetLastUpdate() != nil {
				adv.Timestamp = item.GetLastUpdate().GetSeconds()
			}
		}
	}

	edges := make(map[uint32]uint32)
	addEdge := func(peer uint32) error {
		if peer == 0 || peer == origin {
			return nil
		}
		if _, exists := edges[peer]; exists {
			return nil
		}
		cost := costs[peer]
		if cost == 0 {
			cost = 1
		}
		edges[peer] = cost
		return nil
	}
	switch conn := req.GetConnInfo().(type) {
	case *peerrpc.SyncRouteInfoRequest_ConnPeerList:
		for _, row := range conn.ConnPeerList.GetPeerConnInfos() {
			if row.GetPeerId().GetPeerId() != origin {
				continue
			}
			for _, peer := range row.GetConnectedPeerIds() {
				if err := addEdge(peer); err != nil {
					return Advertisement{}, err
				}
			}
		}
	case *peerrpc.SyncRouteInfoRequest_ConnBitmap:
		for _, peer := range connectedPeersFromBitmap(conn.ConnBitmap, origin) {
			if err := addEdge(peer); err != nil {
				return Advertisement{}, err
			}
		}
	case nil:
		// Node-info-only announcement: keep the LSA edges empty.
	default:
		return Advertisement{}, fmt.Errorf("ospf sync request carries an unknown conn info type")
	}

	for peer, cost := range edges {
		adv.Peers = append(adv.Peers, PeerCost{Peer: peer, Cost: cost})
	}
	sort.Slice(adv.Peers, func(i, j int) bool { return adv.Peers[i].Peer < adv.Peers[j].Peer })
	if _, _, err := validatedAdvertisement(adv); err != nil {
		return Advertisement{}, err
	}
	return adv, nil
}

// connectedPeersFromBitmap decodes the reference connection bitmap: bit
// (i*len+j) set means peer_ids[i] is directly connected to peer_ids[j]; only
// the origin's row contributes edges.
func connectedPeersFromBitmap(bitmap *peerrpc.RouteConnBitmap, origin uint32) []uint32 {
	if bitmap == nil {
		return nil
	}
	rows := bitmap.GetPeerIds()
	rowIndex := -1
	for i, row := range rows {
		if row.GetPeerId() == origin {
			rowIndex = i
			break
		}
	}
	if rowIndex < 0 {
		return nil
	}
	var connected []uint32
	for j, row := range rows {
		if j == rowIndex {
			continue
		}
		idx := rowIndex*len(rows) + j
		byteIdx := idx / 8
		if byteIdx >= len(bitmap.GetBitmap()) {
			continue
		}
		if bitmap.GetBitmap()[byteIdx]>>(idx%8)&1 == 1 {
			connected = append(connected, row.GetPeerId())
		}
	}
	return connected
}

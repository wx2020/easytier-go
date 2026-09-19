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
const OSPFRouteProtoName = "OspfRouteRpc"

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

	// Reference semantics: RoutePeerInfo items are PEER SELF-DESCRIPTIONS
	// (the origin's own, plus relayed ones), never fabricated entries for
	// other peers - the oracle's duplicate detection treats an entry with
	// its own peer_id under a foreign route id as identity theft. Link
	// connectivity travels in conn_info, not in peer_infos.
	connected := make([]uint32, 0, len(peers))
	for _, peer := range peers {
		connected = append(connected, peer.Peer)
	}

	return &peerrpc.SyncRouteInfoRequest{
		MyPeerId:    adv.Origin,
		MySessionId: sessionID,
		IsInitiator: true,
		PeerInfos: &peerrpc.RoutePeerInfos{Items: []*peerrpc.RoutePeerInfo{{
			PeerId:                   adv.Origin,
			Cost:                     0,
			Version:                  version,
			LastUpdate:               lastUpdate,
			ProxyCidrs:               append([]string(nil), cidrs...),
			UdpNatType:               adv.UDPNatType,
			PeerRouteId:              adv.PeerRouteID,
			TrustedCredentialPubkeys: adv.TrustedCredentials,
		}}},
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

// advertisementsFromSyncRequest decodes one reference SyncRouteInfoRequest
// into the flooder's LSA form. Reference semantics: every RoutePeerInfo item
// is a peer SELF-DESCRIPTION (the sender's own entry plus relayed ones), and
// the conn-info rows describe each REPORTING peer's direct connections. Each
// item yields one LSA: a self-description carries no edges unless the request
// also contains that peer's conn row (normally only the sender reports its
// own links, so relayed entries install as node-info-only LSAs and their
// edges arrive through their own syncs). Edges toward the receiver are the
// reporter-to-receiver direct link and must survive;
// route and self-edges never appear (a reporter never lists itself). Link
// costs do not travel: the reference conn graph is unweighted, so edges
// default to cost 1.
func advertisementsFromSyncRequest(req *peerrpc.SyncRouteInfoRequest, fromPeerID uint32) ([]Advertisement, error) {
	if req == nil {
		return nil, fmt.Errorf("ospf sync request is nil")
	}
	if req.GetPeerInfos() != nil && len(req.GetPeerInfos().GetItems()) > MaxAdvertisementPeers+1 {
		return nil, fmt.Errorf("ospf sync request has %d peers, limit is %d", len(req.GetPeerInfos().GetItems()), MaxAdvertisementPeers+1)
	}
	origin := req.GetMyPeerId()
	if origin == 0 {
		origin = fromPeerID
	}
	if origin == 0 {
		return nil, fmt.Errorf("ospf sync request origin is zero")
	}

	// Direct connections reported by each peer, keyed by reporter id.
	reportedEdges := make(map[uint32][]uint32)
	switch conn := req.GetConnInfo().(type) {
	case *peerrpc.SyncRouteInfoRequest_ConnPeerList:
		for _, row := range conn.ConnPeerList.GetPeerConnInfos() {
			reporter := row.GetPeerId().GetPeerId()
			for _, peer := range row.GetConnectedPeerIds() {
				if peer == 0 || peer == reporter {
					continue
				}
				reportedEdges[reporter] = append(reportedEdges[reporter], peer)
			}
		}
	case *peerrpc.SyncRouteInfoRequest_ConnBitmap:
		for _, link := range connectedPairsFromBitmap(conn.ConnBitmap) {
			reportedEdges[link.reporter] = append(reportedEdges[link.reporter], link.connected)
		}
	case nil:
		// Node-info-only announcement.
	default:
		return nil, fmt.Errorf("ospf sync request carries an unknown conn info type")
	}

	buildLSA := func(item *peerrpc.RoutePeerInfo) (Advertisement, error) {
		adv := Advertisement{
			Origin:             item.GetPeerId(),
			Version:            uint64(item.GetVersion()),
			PeerRouteID:        item.GetPeerRouteId(),
			ProxyCIDRs:         append([]string(nil), item.GetProxyCidrs()...),
			UDPNatType:         item.GetUdpNatType(),
			TrustedCredentials: item.GetTrustedCredentialPubkeys(),
		}
		if item.GetLastUpdate() != nil {
			adv.Timestamp = item.GetLastUpdate().GetSeconds()
		}
		for _, peer := range reportedEdges[item.GetPeerId()] {
			adv.Peers = append(adv.Peers, PeerCost{Peer: peer, Cost: 1})
		}
		sort.Slice(adv.Peers, func(i, j int) bool { return adv.Peers[i].Peer < adv.Peers[j].Peer })
		if _, _, err := validatedAdvertisement(adv); err != nil {
			return Advertisement{}, err
		}
		return adv, nil
	}

	var lsas []Advertisement
	items := req.GetPeerInfos().GetItems()
	for _, item := range items {
		if item.GetPeerId() == 0 {
			return nil, fmt.Errorf("ospf sync request has a zero peer id")
		}
		adv, err := buildLSA(item)
		if err != nil {
			return nil, err
		}
		lsas = append(lsas, adv)
	}
	if len(items) == 0 {
		// No self-descriptions at all: fall back to a sender-only LSA so
		// the receiver still records the reporter's existence.
		adv := Advertisement{Origin: origin}
		for _, peer := range reportedEdges[origin] {
			adv.Peers = append(adv.Peers, PeerCost{Peer: peer, Cost: 1})
		}
		sort.Slice(adv.Peers, func(i, j int) bool { return adv.Peers[i].Peer < adv.Peers[j].Peer })
		if _, _, err := validatedAdvertisement(adv); err != nil {
			return nil, err
		}
		lsas = append(lsas, adv)
	}
	return lsas, nil
}

// bitmapLink is one direct connection decoded from a conn bitmap: reporter is
// directly connected to connected.
type bitmapLink struct {
	reporter  uint32
	connected uint32
}

// connectedPairsFromBitmap decodes the reference connection bitmap: bit
// (i*len+j) set means peer_ids[i] is directly connected to peer_ids[j]; both
// directions of every set bit are reported.
func connectedPairsFromBitmap(bitmap *peerrpc.RouteConnBitmap) []bitmapLink {
	if bitmap == nil {
		return nil
	}
	rows := bitmap.GetPeerIds()
	var links []bitmapLink
	for i, row := range rows {
		for j, other := range rows {
			if i == j {
				continue
			}
			idx := i*len(rows) + j
			byteIdx := idx / 8
			if byteIdx >= len(bitmap.GetBitmap()) {
				continue
			}
			if bitmap.GetBitmap()[byteIdx]>>(idx%8)&1 == 1 {
				links = append(links, bitmapLink{reporter: row.GetPeerId(), connected: other.GetPeerId()})
			}
		}
	}
	return links
}

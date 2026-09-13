// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"unicode/utf8"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
)

const (
	advertisementMagic   uint32 = 0x52544531
	advertisementVersion uint16 = 1

	MaxAdvertisementSize       = 1 << 20
	MaxAdvertisementPeers      = 4096
	MaxAdvertisementProxyCIDRs = 4096
	MaxAdvertisementCIDRLength = 256
	advertisementHeaderSize    = 4 + 2 + 4 + 8 + 8 + 4 + 4
	peerCostSize               = 4 + 4
)

// PeerCost is the cost of a direct link from an advertisement's origin.
type PeerCost struct {
	Peer uint32
	Cost uint32
}

// Advertisement describes one origin's current peer links and proxied CIDRs.
type Advertisement struct {
	Origin     uint32
	Version    uint64
	Peers      []PeerCost
	ProxyCIDRs []string
	Timestamp  int64
	// UDPNatType is the origin's self-reported UDP NAT classification
	// (reference RoutePeerInfo.udp_nat_type); Unknown when not probed.
	UDPNatType common.NatType
}

// Marshal encodes an advertisement in a deterministic, bounded binary format.
func (a Advertisement) Marshal() ([]byte, error) {
	peers, cidrs, err := validatedAdvertisement(a)
	if err != nil {
		return nil, err
	}

	length := advertisementHeaderSize + len(peers)*peerCostSize
	for _, cidr := range cidrs {
		length += 4 + len(cidr)
	}
	if length > MaxAdvertisementSize {
		return nil, fmt.Errorf("advertisement size %d exceeds limit %d", length, MaxAdvertisementSize)
	}

	data := make([]byte, length)
	offset := 0
	binary.BigEndian.PutUint32(data[offset:], advertisementMagic)
	offset += 4
	binary.BigEndian.PutUint16(data[offset:], advertisementVersion)
	offset += 2
	binary.BigEndian.PutUint32(data[offset:], a.Origin)
	offset += 4
	binary.BigEndian.PutUint64(data[offset:], a.Version)
	offset += 8
	binary.BigEndian.PutUint64(data[offset:], uint64(a.Timestamp))
	offset += 8
	binary.BigEndian.PutUint32(data[offset:], uint32(len(peers)))
	offset += 4
	binary.BigEndian.PutUint32(data[offset:], uint32(len(cidrs)))
	offset += 4
	for _, peer := range peers {
		binary.BigEndian.PutUint32(data[offset:], peer.Peer)
		offset += 4
		binary.BigEndian.PutUint32(data[offset:], peer.Cost)
		offset += 4
	}
	for _, cidr := range cidrs {
		binary.BigEndian.PutUint32(data[offset:], uint32(len(cidr)))
		offset += 4
		copy(data[offset:], cidr)
		offset += len(cidr)
	}
	return data, nil
}

// ParseAdvertisement decodes and validates an advertisement.
func ParseAdvertisement(data []byte) (Advertisement, error) {
	if len(data) > MaxAdvertisementSize {
		return Advertisement{}, fmt.Errorf("advertisement size %d exceeds limit %d", len(data), MaxAdvertisementSize)
	}
	if len(data) < advertisementHeaderSize {
		return Advertisement{}, fmt.Errorf("advertisement is truncated")
	}

	offset := 0
	magic := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if magic != advertisementMagic {
		return Advertisement{}, fmt.Errorf("invalid advertisement magic %#x", magic)
	}
	formatVersion := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if formatVersion != advertisementVersion {
		return Advertisement{}, fmt.Errorf("unsupported advertisement format %d", formatVersion)
	}
	a := Advertisement{
		Origin:    binary.BigEndian.Uint32(data[offset:]),
		Version:   binary.BigEndian.Uint64(data[offset+4:]),
		Timestamp: int64(binary.BigEndian.Uint64(data[offset+12:])),
	}
	offset += 20
	peerCount := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	cidrCount := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if peerCount > MaxAdvertisementPeers {
		return Advertisement{}, fmt.Errorf("advertisement has %d peers, limit is %d", peerCount, MaxAdvertisementPeers)
	}
	if cidrCount > MaxAdvertisementProxyCIDRs {
		return Advertisement{}, fmt.Errorf("advertisement has %d proxy CIDRs, limit is %d", cidrCount, MaxAdvertisementProxyCIDRs)
	}
	if uint64(peerCount)*peerCostSize > uint64(len(data)-offset) {
		return Advertisement{}, fmt.Errorf("advertisement peer section exceeds payload")
	}

	a.Peers = make([]PeerCost, 0, peerCount)
	for i := uint32(0); i < peerCount; i++ {
		peer := PeerCost{
			Peer: binary.BigEndian.Uint32(data[offset:]),
			Cost: binary.BigEndian.Uint32(data[offset+4:]),
		}
		offset += peerCostSize
		a.Peers = append(a.Peers, peer)
	}
	a.ProxyCIDRs = make([]string, 0, cidrCount)
	for i := uint32(0); i < cidrCount; i++ {
		if len(data)-offset < 4 {
			return Advertisement{}, fmt.Errorf("advertisement proxy CIDR length is truncated")
		}
		length := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		if length > MaxAdvertisementCIDRLength || uint64(length) > uint64(len(data)-offset) {
			return Advertisement{}, fmt.Errorf("advertisement proxy CIDR length %d is invalid", length)
		}
		cidr := string(data[offset : offset+int(length)])
		offset += int(length)
		a.ProxyCIDRs = append(a.ProxyCIDRs, cidr)
	}
	if offset != len(data) {
		return Advertisement{}, fmt.Errorf("advertisement has %d trailing bytes", len(data)-offset)
	}
	if _, _, err := validatedAdvertisement(a); err != nil {
		return Advertisement{}, err
	}
	return a, nil
}

// EncodeAdvertisement is an explicit alias for Advertisement.Marshal.
func EncodeAdvertisement(a Advertisement) ([]byte, error) {
	return a.Marshal()
}

// DecodeAdvertisement is an explicit alias for ParseAdvertisement.
func DecodeAdvertisement(data []byte) (Advertisement, error) {
	return ParseAdvertisement(data)
}

func validatedAdvertisement(a Advertisement) ([]PeerCost, []string, error) {
	if a.Origin == 0 {
		return nil, nil, fmt.Errorf("advertisement origin is zero")
	}
	if len(a.Peers) > MaxAdvertisementPeers {
		return nil, nil, fmt.Errorf("advertisement has %d peers, limit is %d", len(a.Peers), MaxAdvertisementPeers)
	}
	if len(a.ProxyCIDRs) > MaxAdvertisementProxyCIDRs {
		return nil, nil, fmt.Errorf("advertisement has %d proxy CIDRs, limit is %d", len(a.ProxyCIDRs), MaxAdvertisementProxyCIDRs)
	}

	peers := append([]PeerCost(nil), a.Peers...)
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Peer != peers[j].Peer {
			return peers[i].Peer < peers[j].Peer
		}
		return peers[i].Cost < peers[j].Cost
	})
	for i, peer := range peers {
		if peer.Peer == 0 || peer.Peer == a.Origin {
			return nil, nil, fmt.Errorf("advertisement peer %d is invalid", peer.Peer)
		}
		if i > 0 && peers[i-1].Peer == peer.Peer {
			return nil, nil, fmt.Errorf("advertisement contains duplicate peer %d", peer.Peer)
		}
	}

	cidrs := append([]string(nil), a.ProxyCIDRs...)
	sort.Strings(cidrs)
	for i, cidr := range cidrs {
		if len(cidr) == 0 || len(cidr) > MaxAdvertisementCIDRLength || !utf8.ValidString(cidr) {
			return nil, nil, fmt.Errorf("advertisement proxy CIDR has invalid length")
		}
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return nil, nil, fmt.Errorf("advertisement proxy CIDR %q is invalid: %w", cidr, err)
		}
		if i > 0 && cidrs[i-1] == cidr {
			return nil, nil, fmt.Errorf("advertisement contains duplicate proxy CIDR %q", cidr)
		}
	}
	return peers, cidrs, nil
}

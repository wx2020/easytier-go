// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package nat

import (
	"github.com/EasyTier/EasyTier/go/internal/proto/common"
)

// UdpNatType classifies a UDP NAT enumeration into the punch-relevant
// families: open, cone, easy symmetric (with increment direction), and hard
// symmetric. Unknown is its own family so callers can apply the reference
// "treat unknown as cone" fallback explicitly.
type UdpNatType struct {
	proto common.NatType
	kind  udpNatKind
	// incremental is only meaningful for easySymmetric.
	incremental bool
}

type udpNatKind int

const (
	udpNatUnknown udpNatKind = iota
	udpNatOpen
	udpNatCone
	udpNatEasySymmetric
	udpNatHardSymmetric
)

// NewUdpNatType maps a proto NatType enumeration onto the punch families.
func NewUdpNatType(protoType common.NatType) UdpNatType {
	switch protoType {
	case common.NatType_OpenInternet:
		return UdpNatType{proto: protoType, kind: udpNatOpen}
	case common.NatType_NoPAT, common.NatType_FullCone, common.NatType_Restricted, common.NatType_PortRestricted:
		return UdpNatType{proto: protoType, kind: udpNatCone}
	case common.NatType_Symmetric, common.NatType_SymUdpFirewall:
		return UdpNatType{proto: protoType, kind: udpNatHardSymmetric}
	case common.NatType_SymmetricEasyInc:
		return UdpNatType{proto: protoType, kind: udpNatEasySymmetric, incremental: true}
	case common.NatType_SymmetricEasyDec:
		return UdpNatType{proto: protoType, kind: udpNatEasySymmetric}
	default:
		return UdpNatType{proto: common.NatType_Unknown, kind: udpNatUnknown}
	}
}

// Proto returns the underlying NatType enumeration value.
func (t UdpNatType) Proto() common.NatType { return t.proto }

// IsOpen reports whether the NAT is open internet or no-PAT, where remote
// peers can always reach us and punching is unnecessary.
func (t UdpNatType) IsOpen() bool { return t.kind == udpNatOpen }

// IsUnknown reports whether the NAT type could not be classified.
func (t UdpNatType) IsUnknown() bool { return t.kind == udpNatUnknown }

// IsCone reports whether the NAT keeps one stable external mapping per socket.
func (t UdpNatType) IsCone() bool { return t.kind == udpNatCone }

// IsEasySym reports whether the NAT is symmetric with predictable port
// allocation (incrementing or decrementing).
func (t UdpNatType) IsEasySym() bool { return t.kind == udpNatEasySymmetric }

// IsHardSym reports whether the NAT is symmetric with unpredictable port
// allocation.
func (t UdpNatType) IsHardSym() bool { return t.kind == udpNatHardSymmetric }

// IsSym reports whether the NAT is symmetric at all.
func (t UdpNatType) IsSym() bool { return t.IsEasySym() || t.IsHardSym() }

// IsIncremental returns (increment direction, true) for easy symmetric NATs.
func (t UdpNatType) IsIncremental() (bool, bool) {
	if t.kind != udpNatEasySymmetric {
		return false, false
	}
	return t.incremental, true
}

// PunchClientMethod names the hole punch strategy selected for one peer pair.
type PunchClientMethod int

const (
	// PunchMethodNone means this pair cannot be punched as a client.
	PunchMethodNone PunchClientMethod = iota
	// PunchMethodConeToCone is the cone-to-cone single-listener strategy.
	PunchMethodConeToCone
	// PunchMethodSymToCone targets a cone peer from a symmetric client.
	PunchMethodSymToCone
	// PunchMethodEasySymToEasySym predicts ports on both easy symmetric sides.
	PunchMethodEasySymToEasySym
)

// SelectPunchMethod applies the reference strategy decision table. When
// disableSymPunching is set, symmetric NATs are demoted to cone behavior.
// Unknown NAT types follow the reference fallback: unknown pairs punch as
// cone unless the other side is a known symmetric.
func SelectPunchMethod(my, other UdpNatType, disableSymPunching bool) PunchClientMethod {
	if disableSymPunching && my.IsSym() {
		if other.IsSym() {
			return PunchMethodNone
		}
		return PunchMethodConeToCone
	}

	if other.IsUnknown() {
		if my.IsSym() {
			return PunchMethodSymToCone
		}
		return PunchMethodConeToCone
	}
	if my.IsUnknown() {
		if other.IsSym() {
			return PunchMethodNone
		}
		return PunchMethodConeToCone
	}

	if my.IsOpen() || other.IsOpen() {
		// Open sides do not need to punch.
		return PunchMethodNone
	}

	switch {
	case my.IsCone():
		if other.IsSym() {
			return PunchMethodNone
		}
		return PunchMethodConeToCone
	case my.IsEasySym():
		if other.IsHardSym() {
			return PunchMethodNone
		}
		if other.IsEasySym() {
			return PunchMethodEasySymToEasySym
		}
		return PunchMethodSymToCone
	case my.IsHardSym():
		if other.IsSym() {
			return PunchMethodNone
		}
		return PunchMethodSymToCone
	default:
		return PunchMethodNone
	}
}

// CanPunchAsClient reports whether my side should initiate punching toward
// other. Two easy symmetric peers only punch when the local peer has the
// smaller ID, so exactly one side drives the exchange.
func CanPunchAsClient(my, other UdpNatType, myPeerID, otherPeerID uint32, disableSymPunching bool) bool {
	switch SelectPunchMethod(my, other, disableSymPunching) {
	case PunchMethodNone:
		return false
	case PunchMethodEasySymToEasySym:
		return myPeerID < otherPeerID
	default:
		return true
	}
}

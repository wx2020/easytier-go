// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package nat

import (
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/proto/common"
)

func TestUdpNatTypeClassification(t *testing.T) {
	cases := []struct {
		name        string
		proto       common.NatType
		wantOpen    bool
		wantCone    bool
		wantEasySym bool
		wantHardSym bool
		wantInc     bool
	}{
		{name: "unknown", proto: common.NatType_Unknown},
		{name: "open internet", proto: common.NatType_OpenInternet, wantOpen: true},
		{name: "no pat", proto: common.NatType_NoPAT, wantCone: true},
		{name: "full cone", proto: common.NatType_FullCone, wantCone: true},
		{name: "restricted", proto: common.NatType_Restricted, wantCone: true},
		{name: "port restricted", proto: common.NatType_PortRestricted, wantCone: true},
		{name: "symmetric", proto: common.NatType_Symmetric, wantHardSym: true},
		{name: "sym udp firewall", proto: common.NatType_SymUdpFirewall, wantHardSym: true},
		{name: "easy inc", proto: common.NatType_SymmetricEasyInc, wantEasySym: true, wantInc: true},
		{name: "easy dec", proto: common.NatType_SymmetricEasyDec, wantEasySym: true},
	}
	for _, c := range cases {
		got := NewUdpNatType(c.proto)
		if got.IsOpen() != c.wantOpen || got.IsCone() != c.wantCone ||
			got.IsEasySym() != c.wantEasySym || got.IsHardSym() != c.wantHardSym {
			t.Errorf("%s classified wrong: open=%v cone=%v easySym=%v hardSym=%v",
				c.name, got.IsOpen(), got.IsCone(), got.IsEasySym(), got.IsHardSym())
		}
		if inc, ok := got.IsIncremental(); ok && inc != c.wantInc {
			t.Errorf("%s increment direction = %v, want %v", c.name, inc, c.wantInc)
		}
	}
}

func TestSelectPunchMethod(t *testing.T) {
	unknown := NewUdpNatType(common.NatType_Unknown)
	open := NewUdpNatType(common.NatType_OpenInternet)
	noPat := NewUdpNatType(common.NatType_NoPAT)
	fullCone := NewUdpNatType(common.NatType_FullCone)
	restricted := NewUdpNatType(common.NatType_Restricted)
	cone := NewUdpNatType(common.NatType_PortRestricted)
	hardSym := NewUdpNatType(common.NatType_Symmetric)
	firewall := NewUdpNatType(common.NatType_SymUdpFirewall)
	easyInc := NewUdpNatType(common.NatType_SymmetricEasyInc)
	easyDec := NewUdpNatType(common.NatType_SymmetricEasyDec)

	cases := []struct {
		name               string
		my, other          UdpNatType
		disableSymPunching bool
		want               PunchClientMethod
	}{
		{"cone to cone", cone, cone, false, PunchMethodConeToCone},
		{"cone to unknown", cone, unknown, false, PunchMethodConeToCone},
		{"unknown to cone", unknown, cone, false, PunchMethodConeToCone},
		{"unknown to unknown", unknown, unknown, false, PunchMethodConeToCone},
		{"unknown to sym", unknown, hardSym, false, PunchMethodNone},
		{"sym to unknown", hardSym, unknown, false, PunchMethodSymToCone},
		{"open never punches", open, cone, false, PunchMethodNone},
		{"cone to open", cone, open, false, PunchMethodNone},
		{"cone never punches sym", cone, hardSym, false, PunchMethodNone},
		{"cone never punches firewall", cone, firewall, false, PunchMethodNone},
		{"hard sym to cone", hardSym, cone, false, PunchMethodSymToCone},
		{"hard sym to easy sym", hardSym, easyInc, false, PunchMethodNone},
		{"hard sym to hard sym", hardSym, hardSym, false, PunchMethodNone},
		{"easy sym to cone", easyInc, fullCone, false, PunchMethodSymToCone},
		{"easy sym to restricted", easyDec, restricted, false, PunchMethodSymToCone},
		{"easy sym to easy sym", easyInc, easyDec, false, PunchMethodEasySymToEasySym},
		{"easy sym to hard sym", easyInc, hardSym, false, PunchMethodNone},
		{"easy sym to no pat", easyInc, noPat, false, PunchMethodSymToCone},
		{"disable sym demotes to cone", hardSym, cone, true, PunchMethodConeToCone},
		{"disable sym both sym", hardSym, hardSym, true, PunchMethodNone},
	}
	for _, c := range cases {
		if got := SelectPunchMethod(c.my, c.other, c.disableSymPunching); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCanPunchAsClient(t *testing.T) {
	easyInc := NewUdpNatType(common.NatType_SymmetricEasyInc)
	easyDec := NewUdpNatType(common.NatType_SymmetricEasyDec)
	cone := NewUdpNatType(common.NatType_PortRestricted)
	hardSym := NewUdpNatType(common.NatType_Symmetric)

	if !CanPunchAsClient(cone, cone, 200, 100, false) {
		t.Error("cone pair should always punch")
	}
	if CanPunchAsClient(easyInc, easyDec, 200, 100, false) {
		t.Error("larger peer id must not initiate easy sym to easy sym punch")
	}
	if !CanPunchAsClient(easyInc, easyDec, 100, 200, false) {
		t.Error("smaller peer id should initiate easy sym to easy sym punch")
	}
	if CanPunchAsClient(hardSym, hardSym, 1, 2, false) {
		t.Error("hard sym pair cannot punch")
	}
}

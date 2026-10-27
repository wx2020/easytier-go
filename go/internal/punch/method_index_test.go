// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package punch

import "testing"

// TestUdpHolePunchRpcMethodIndices pins the method numbering of
// UdpHolePunchRpc against the reference service definition:
//
//	service UdpHolePunchRpc {
//	  rpc SelectPunchListener(...) ...;        // index 1
//	  rpc SendPunchPacketCone(...) ...;         // index 2
//	  rpc SendPunchPacketHardSym(...) ...;      // index 3
//	  rpc SendPunchPacketEasySym(...) ...;      // index 4
//	  rpc SendPunchPacketBothEasySym(...) ...;  // index 5
//	}
//
// The reference generator numbers methods from one, so a 0-based table makes
// every call miss the service on a reference peer.
func TestUdpHolePunchRpcMethodIndices(t *testing.T) {
	if ServiceName != "UdpHolePunchRpc" {
		t.Fatalf("ServiceName = %q", ServiceName)
	}
	cases := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"SelectPunchListener", MethodSelectPunchListener, 1},
		{"SendPunchPacketCone", MethodSendPunchPacketCone, 2},
		{"SendPunchPacketHardSym", MethodSendPunchPacketHardSym, 3},
		{"SendPunchPacketEasySym", MethodSendPunchPacketEasySym, 4},
		{"SendPunchPacketBothEasySym", MethodSendPunchPacketBothEasySym, 5},
	}
	for _, testCase := range cases {
		if testCase.got != testCase.want {
			t.Errorf("%s = %d, want %d", testCase.name, testCase.got, testCase.want)
		}
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package tcphole

import "testing"

// TestTcpHolePunchRpcMethodIndex pins the method numbering of
// TcpHolePunchRpc against the reference service definition:
//
//	service TcpHolePunchRpc {
//	  rpc ExchangeMappedAddr(...) ...;  // index 1
//	}
//
// The reference generator numbers methods from one.
func TestTcpHolePunchRpcMethodIndex(t *testing.T) {
	if ServiceName != "TcpHolePunchRpc" {
		t.Fatalf("ServiceName = %q", ServiceName)
	}
	if MethodExchangeMappedAddr != 1 {
		t.Fatalf("MethodExchangeMappedAddr = %d, want 1", MethodExchangeMappedAddr)
	}
}

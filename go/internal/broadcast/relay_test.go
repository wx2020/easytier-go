// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package broadcast

import (
	"net"
	"testing"
)

func TestRelayEnabledAndPeers(t *testing.T) {
	r := New(true)
	if !r.Enabled() {
		t.Fatal("should be enabled")
	}
	r.AddPeer("a", &net.UDPAddr{IP: net.ParseIP("10.0.0.1")})
	if r.Peers() != 1 {
		t.Fatal("peers count")
	}
	r.RemovePeer("a")
	if r.Peers() != 0 {
		t.Fatal("peers after remove")
	}
	r2 := New(false)
	if r2.ShouldRelay(net.IPv4bcast) {
		t.Fatal("disabled should not relay")
	}
	if !r.ShouldRelay(net.IPv4bcast) {
		t.Fatal("enabled broadcast should relay")
	}
}

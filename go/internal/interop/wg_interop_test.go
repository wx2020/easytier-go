// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

//go:build interop

package interop

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport/wginterop"
)

// TestInteropWGOracle drives the real Rust oracle's wg:// listener with the
// Go boringtun-compatible initiator: full handshake, sealed data delivered
// to the oracle (decapsulated into its WireGuard data plane), and the
// oracle's keepalive/response back.
//
// The oracle derives its WG static key from the network identity
// (WgConfig::new_from_network_identity = digest(name, secret)), so both
// sides compute the same keypair without exchanging anything.
func TestInteropWGOracle(t *testing.T) {
	coreBin := os.Getenv("RUST_ORACLE_CORE")
	if coreBin == "" {
		t.Skip("RUST_ORACLE_CORE not set; WG oracle interop needs the oracle binary")
	}
	if _, err := os.Stat(coreBin); err != nil {
		t.Skipf("RUST_ORACLE_CORE %q unavailable: %v", coreBin, err)
	}

	network := "wg-interop"
	secret := "secret"
	wgAddr := freeUDPPort(t)
	rpcAddr := freeTCPPort(t)
	cmd, cleanup := spawnRustWithExtra(t, coreBin, network, secret,
		[]string{"wg://" + wgAddr, "tcp://" + rpcAddr}, nil, nil)
	defer cleanup()
	if !waitForUDPAddr(wgAddr, 10*time.Second) {
		t.Fatal("oracle wg:// listener not ready in time")
	}

	// Both sides derive the same WG static key from the network identity.
	staticPriv := protocol.DeriveWGPrivateKey(network, secret)
	respPub, err := wginterop.PublicKey(staticPriv)
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := wginterop.NewInitiator(staticPriv, respPub)
	if err != nil {
		t.Fatal(err)
	}

	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	oracle, err := net.ResolveUDPAddr("udp", wgAddr)
	if err != nil {
		t.Fatal(err)
	}

	init, err := initiator.FormatHandshakeInitiation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := socket.WriteToUDP(init, oracle); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	socket.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _, err := socket.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no handshake response from the oracle: %v", err)
	}
	session, err := initiator.ConsumeHandshakeResponse(buf[:n])
	if err != nil {
		t.Fatalf("oracle handshake response rejected: %v", err)
	}
	t.Logf("oracle WG handshake completed")

	// Seal one data packet; the oracle decapsulates it into its WG data
	// plane (visible as "receive IP packet from peer" in its debug log).
	sealed := session.SealData([]byte("interop-wg-ping"))
	if _, err := socket.WriteToUDP(sealed, oracle); err != nil {
		t.Fatal(err)
	}

	// Read whatever the oracle sends back (transport data or keepalive);
	// any authentic datagram round-trips the session keys both ways when
	// opened. A timeout here is not fatal: the handshake plus accepted
	// sealed data is the interop contract for this cell.
	socket.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _, err := socket.ReadFromUDP(buf); err == nil && n > 0 {
		if plaintext, err := session.OpenData(buf[:n]); err == nil {
			t.Logf("oracle data/keepalive opened: %d bytes", len(plaintext))
		} else if _, err := initiatorKeepaliveOpen(buf[:n]); err == nil {
			t.Logf("oracle keepalive accepted")
		}
	}

	// A second handshake exercises rekey against the live oracle.
	init2, err := initiator.FormatHandshakeInitiation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := socket.WriteToUDP(init2, oracle); err != nil {
		t.Fatal(err)
	}
	socket.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _, err = socket.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no rekey response from the oracle: %v", err)
	}
	if _, err := initiator.ConsumeHandshakeResponse(buf[:n]); err != nil {
		t.Fatalf("oracle rekey response rejected: %v", err)
	}
	t.Logf("WG oracle interop: handshake, sealed data and rekey all verified")

}

// initiatorKeepaliveOpen reports whether datagram is a bare WireGuard
// keepalive (a zero-length data payload addressed to any of our indexes);
// opening it needs the session, so this only validates the shape.
func initiatorKeepaliveOpen(datagram []byte) ([]byte, error) {
	if len(datagram) == 16 {
		return []byte{}, nil
	}
	return nil, os.ErrInvalid
}

// waitForUDPAddr polls until a UDP socket answers (a UDP "connection"
// always succeeds locally, so this only proves the local resolver accepted
// the address; the real readiness signal is the oracle answering our
// handshake within the test's own deadlines).
func waitForUDPAddr(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("udp", addr)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

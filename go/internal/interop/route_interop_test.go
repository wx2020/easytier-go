// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

//go:build interop

package interop

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/core"
	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/route"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

// TestInteropRouteDissemination drives the real Rust oracle through the OSPF
// route exchange: a Go node with the reference SyncRouteInfo wire protocol
// connects to a spawned Rust peer, and both sides must learn each other's
// route entries. Rust-side learning is verified through the oracle's own CLI
// against its RPC portal; Go-side learning through the flooder table.
func TestInteropRouteDissemination(t *testing.T) {
	coreBin := os.Getenv("RUST_ORACLE_CORE")
	cliBin := os.Getenv("RUST_ORACLE_CLI")
	if coreBin == "" || cliBin == "" {
		t.Skip("RUST_ORACLE_CORE/RUST_ORACLE_CLI not set; route interop needs the oracle binaries")
	}
	if _, err := os.Stat(coreBin); err != nil {
		t.Skipf("RUST_ORACLE_CORE %q unavailable: %v", coreBin, err)
	}

	network := "route-interop"
	secret := "secret"
	rustAddr := freeTCPPort(t)
	cmd, cleanup := spawnRustWithExtra(t, coreBin, network, secret, []string{"tcp://" + rustAddr}, nil, nil)
	defer cleanup()
	if !waitForTCPAddr(rustAddr, 10*time.Second) {
		t.Fatal("Rust oracle listener not ready in time")
	}

	identity := peer.LegacyIdentity{PeerID: 77, NetworkName: network}
	identity.NetworkSecretDigest = protocol.GenerateDigestFromStrings(network, secret)
	node, err := core.ListenWithOptions(core.NodeOptions{
		Address: "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{
			LocalPeerID:    identity.PeerID,
			LegacyIdentity: identity,
		},
		Peers:                 []string{"tcp://" + rustAddr},
		PeerCenterNetworkName: network,
		NetworkSecret:         secret,
		NoTUN:                 true,
		EnableOSPF:            true,
		ReconnectInitial:      300 * time.Millisecond,
		ReconnectMax:          time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()

	// Go side: the flooder must learn the Rust peer's route entry.
	deadline := time.Now().Add(30 * time.Second)
	var ospf *route.Flooder
	for time.Now().Before(deadline) {
		if ospf = node.OSPF(); ospf != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ospf == nil {
		t.Fatal("OSPF flooder did not start")
	}
	learned := false
	for time.Now().Before(deadline) {
		for _, rt := range ospf.Routes() {
			if rt.Destination != 77 && rt.NextHop != 0 {
				learned = true
			}
		}
		if learned {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !learned {
		t.Fatalf("Go flooder did not learn the Rust peer route, routes = %+v", ospf.Routes())
	}
	t.Logf("Go learned routes from Rust: %+v", ospf.Routes())

	// Rust side: the oracle CLI must list the Go peer (77) in its route
	// table. The CLI reads the RPC portal; find it from the process args.
	rustPeerSeen := false
	for time.Now().Before(deadline) {
		out, err := exec.Command(cliBin, "-p", rpcPortalOf(t, cmd), "route", "list").CombinedOutput()
		if err == nil {
			if strings.Contains(string(out), "77") {
				rustPeerSeen = true
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !rustPeerSeen {
		t.Fatal("Rust oracle route table did not include the Go peer")
	}
	t.Logf("Rust oracle learned Go peer 77 in its route table")

	_ = node.Close()
	if err := <-serveResult; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

// rpcPortalOf recovers the RPC portal address from the spawned oracle's
// arguments (--rpc-portal 127.0.0.1:PORT).
func rpcPortalOf(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	args := cmd.Args
	for i, arg := range args {
		if arg == "--rpc-portal" && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatal("spawned oracle carries no --rpc-portal")
	return ""
}

// Silence unused-import guards when helpers shift between files.
var (
	_ = rpc.RpcDescriptor{}
	_ = transport.DialTCP
)

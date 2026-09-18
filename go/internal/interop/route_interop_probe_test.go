// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

//go:build interop

package interop

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/core"
	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/route"
)

// TestInteropRouteProxyDiagnosis inserts a counting TCP proxy between the Go
// node and the Rust oracle to decide whether Go's outbound RPC frames leave
// the node at all (proxy byte counters) versus the oracle failing to process
// them (RUST_LOG=debug output).
func TestInteropRouteProxyDiagnosis(t *testing.T) {
	coreBin := os.Getenv("RUST_ORACLE_CORE")
	cliBin := os.Getenv("RUST_ORACLE_CLI")
	if coreBin == "" || cliBin == "" {
		t.Skip("oracle binaries not set")
	}

	network := "route-interop"
	secret := "secret"
	rustAddr := freeTCPPort(t)
	cmd, cleanup := spawnRustWithExtra(t, coreBin, network, secret, []string{"tcp://" + rustAddr}, nil, nil)
	defer cleanup()
	if !waitForTCPAddr(rustAddr, 10*time.Second) {
		t.Fatal("oracle listener not ready")
	}

	// Counting proxy.
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	var toRust, fromRust atomic.Int64
	go func() {
		for {
			down, err := proxy.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", rustAddr)
			if err != nil {
				_ = down.Close()
				continue
			}
			go pumpCounting(down, up, &toRust)
			go pumpCounting(up, down, &fromRust)
		}
	}()

	identity := peer.LegacyIdentity{PeerID: 77, NetworkName: network}
	identity.NetworkSecretDigest = protocol.GenerateDigestFromStrings(network, secret)
	node, err := core.ListenWithOptions(core.NodeOptions{
		Address: "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{
			LocalPeerID:    identity.PeerID,
			LegacyIdentity: identity,
			PingerEnabled:  true,
		},
		Peers:                 []string{"tcp://" + proxy.Addr().String()},
		PeerCenterNetworkName: network,
		NetworkSecret:         secret,
		NoTUN:                 true,
		EnableOSPF:            true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- node.Serve(ctx) }()

	deadline := time.Now().Add(25 * time.Second)
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
	t.Logf("learned=%v toRust=%d fromRust=%d", learned, toRust.Load(), fromRust.Load())
	time.Sleep(5 * time.Second)
	t.Logf("final toRust=%d fromRust=%d", toRust.Load(), fromRust.Load())

	if _, err := ospf.Originate(context.Background()); err != nil {
		t.Logf("explicit originate error: %v", err)
	}
	time.Sleep(5 * time.Second)
	t.Logf("after originate toRust=%d fromRust=%d", toRust.Load(), fromRust.Load())

	out, _ := exec.Command(cliBin, "-p", rpcPortalOf(t, cmd), "route", "list").CombinedOutput()
	t.Logf("oracle route list: %s", strings.TrimSpace(string(out)))

	_ = node.Close()
	cancel()
	<-serveResult
	_ = route.OSPFRouteProtoName
}

func pumpCounting(dst, src net.Conn, counter *atomic.Int64) {
	defer dst.Close()
	buf := make([]byte, 16<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			counter.Add(int64(n))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
	}
}

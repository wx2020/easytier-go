// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

//go:build interop

package interop

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
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
	toRustFrames := &frameCounters{types: make(map[uint8]int)}
	fromRustFrames := &frameCounters{types: make(map[uint8]int)}
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
			go pumpFrames(down, up, toRustFrames)
			go pumpFrames(up, down, fromRustFrames)
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
	time.Sleep(5 * time.Second)

	if _, err := ospf.Originate(context.Background()); err != nil {
		t.Logf("explicit originate error: %v", err)
	}
	time.Sleep(5 * time.Second)

	out, _ := exec.Command(cliBin, "-p", rpcPortalOf(t, cmd), "route", "list").CombinedOutput()

	diagnosis := fmt.Sprintf("learned=%v goFrames=%s rustFrames=%s oracleRoutes=%s",
		learned, toRustFrames.snapshot(), fromRustFrames.snapshot(), strings.TrimSpace(string(out)))
	_ = node.Close()
	cancel()
	<-serveResult
	// Always fail with the diagnosis data: t.Logf is invisible without -v.
	t.Errorf("PROXY DIAGNOSIS %s", diagnosis)
	_ = route.OSPFRouteProtoName
}

// frameCounters tallies EasyTier peer packets by packet type in one proxy
// direction. The stream is [4-byte LE length][16-byte peer header][body].
type frameCounters struct {
	mu    sync.Mutex
	types map[uint8]int
	bytes int64
}

func (f *frameCounters) record(packetType uint8, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.types[packetType]++
	f.bytes += int64(n)
}

func (f *frameCounters) snapshot() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]int, 0, len(f.types))
	for k := range f.types {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("type%d=%d", k, f.types[uint8(k)]))
	}
	return fmt.Sprintf("bytes=%d [%s]", f.bytes, strings.Join(parts, " "))
}

// pumpFrames relays src to dst while counting packets by peer header type.
func pumpFrames(dst, src net.Conn, counters *frameCounters) {
	defer dst.Close()
	pending := make([]byte, 0, 4+protocol.PeerManagerHeaderSize)
	buf := make([]byte, 16<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			for {
				if len(pending) < 4 {
					break
				}
				frameLen := int(binary.LittleEndian.Uint32(pending[:4]))
				if frameLen < protocol.PeerManagerHeaderSize || frameLen > 1<<20 {
					counters.record(0, len(pending))
					pending = pending[:0]
					break
				}
				if len(pending) < 4+frameLen {
					break
				}
				counters.record(pending[4+8], 4+frameLen)
				pending = pending[4+frameLen:]
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

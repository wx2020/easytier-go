// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package vpnportal

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

// TestBoringtunProbeInterop runs a REAL boringtun initiator
// (tools/wg-probe, boringtun-easytier Tunn) against the Go portal:
// handshake, one data packet in, echo out. This is the stock-interop
// acceptance test (wg-interop-todo.md 3.2).
func TestBoringtunProbeInterop(t *testing.T) {
	probe := probeBinary(t)
	if probe == "" {
		t.Skip("wg-probe binary not built; run: cargo build --manifest-path tools/wg-probe/Cargo.toml")
	}

	portal, err := NewPortal(config.VPNPortalConfig{
		ClientCIDR:      "10.144.144.0/24",
		WireGuardListen: "127.0.0.1:0",
	}, config.NetworkIdentity{NetworkName: "interop-net", NetworkSecret: "interop-secret"})
	if err != nil {
		t.Fatal(err)
	}
	// Echo forwarder: swap src/dst and send back through the portal,
	// exercising the full bidirectional path.
	portal.SetMeshForwarder(func(ctx context.Context, ipPacket []byte) error {
		echo := swapIPv4Addrs(ipPacket)
		if echo == nil {
			return nil
		}
		handled, err := portal.DeliverToClient(ctx, echo)
		if err != nil {
			return err
		}
		if !handled {
			t.Errorf("echo was not deliverable")
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := portal.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer portal.Close()

	serverPub := hex.EncodeToString(portal.wgConfig.ServerPublic[:])
	clientPriv := hex.EncodeToString(portal.wgConfig.ClientPrivate[:])
	cmd := exec.Command(probe,
		portal.ListenAddr().String(),
		serverPub,
		clientPriv,
		"10.144.144.9",
		"10.144.144.1",
	)
	output, err := cmd.CombinedOutput()
	t.Logf("wg-probe output: %s", output)
	if err != nil {
		t.Fatalf("boringtun probe failed: %v", err)
	}
}

func swapIPv4Addrs(packet []byte) []byte {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil
	}
	out := append([]byte(nil), packet...)
	src := append([]byte(nil), out[12:16]...)
	copy(out[12:16], out[16:20])
	copy(out[16:20], src)
	return out
}

func probeBinary(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(file))))
	candidate := filepath.Join(root, "tools", "wg-probe", "target", "debug", "wg-probe")
	if info, err := os.Stat(candidate); err != nil || info.IsDir() {
		return ""
	}
	return candidate
}

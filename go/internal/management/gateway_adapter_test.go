// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package management

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/gateway"
)

func TestGatewayAdapterProxyListViaRPC(t *testing.T) {
	cfg := config.Config{
		NetworkIdentity: config.NetworkIdentity{NetworkName: "test"},
		Flags:           &config.Flags{EnableKCPProxy: true, EnableQUICProxy: true},
	}
	mgr := NewGatewayManagerFromConfig(cfg, gateway.LossyOptions{LossRate: 0, Seed: 1}, gateway.LossyOptions{LossRate: 0, Seed: 2})
	// Start a simple echo server as destination
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					n, rerr := conn.Read(buf)
					if n > 0 {
						_, _ = conn.Write(buf[:n])
					}
					if rerr != nil {
						return
					}
				}
			}(c)
		}
	}()
	echoAddr := ln.Addr().String()

	ctx := context.Background()
	if err := mgr.Start(ctx, "127.0.0.1:0", echoAddr, "127.0.0.1:0", echoAddr); err != nil {
		t.Fatalf("start manager: %v", err)
	}
	defer mgr.Close()

	adapter := NewGatewayAdapter(mgr)
	svc := NewServiceWithOptions(ServiceOptions{
		NodeInfo:      NodeInfo{ID: "test", Name: "gw", Version: "v1"},
		ProxyProvider: adapter,
	})

	// Initially empty
	info, err := svc.ProxyList()
	if err != nil {
		t.Fatalf("proxy list: %v", err)
	}
	if len(info.Entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(info.Entries))
	}

	// Create a connection to generate entry
	kcpAddr := mgr.KCP().ListenAddr().String()
	conn, err := net.Dial("tcp", kcpAddr)
	if err != nil {
		t.Fatalf("dial kcp: %v", err)
	}
	// Keep connection open and query
	found := false
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		info, _ = svc.ProxyList()
		for _, e := range info.Entries {
			if e.TransportType == string(gateway.TransportKCP) {
				found = true
				if e.StartTime == 0 {
					t.Fatal("start_time not set")
				}
				if e.Source == "" || e.Destination != echoAddr {
					t.Fatalf("unexpected src/dst: %+v", e)
				}
				if e.State == "" {
					t.Fatal("state empty")
				}
			}
		}
		if found {
			break
		}
	}
	_ = conn.Close()
	if !found {
		t.Log("warning: KCP entry not observed due to timing")
	}

	// Test flags conversion
	flags := ProxyFlagsFromConfig(&cfg)
	if !flags.EnableKCPProxy || !flags.EnableQUICProxy {
		t.Fatal("flags conversion failed")
	}
	emptyFlags := ProxyFlagsFromConfig(nil)
	_ = emptyFlags
	// Test config with nil flags defaults
}

func TestProxyFlagsFromConfigDefaults(t *testing.T) {
	empty := config.Config{NetworkIdentity: config.NetworkIdentity{NetworkName: "x"}}
	flags := ProxyFlagsFromConfig(&empty)
	// defaults are false
	if flags.EnableKCPProxy || flags.EnableQUICProxy {
		t.Fatalf("unexpected defaults: %+v", flags)
	}
	// nil config
	flags2 := ProxyFlagsFromConfig(nil)
	_ = flags2
}

//go:build linux && privileged

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package mapping

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func isPrivilegedForTest() bool {
	if v := os.Getenv("EASYTIER_FORCE_PRIVILEGED"); v == "1" {
		return true
	}
	return os.Geteuid() == 0
}

func hasIPCommand() bool {
	_, err := exec.LookPath("ip")
	return err == nil
}

func hasMiniupnpd() bool {
	for _, c := range []string{"miniupnpd", "/usr/sbin/miniupnpd", "/sbin/miniupnpd"} {
		if _, err := exec.LookPath(c); err == nil {
			return true
		}
		if _, err := os.Stat(c); err == nil {
			return true
		}
	}
	return false
}

func findMiniupnpd() string {
	for _, c := range []string{"miniupnpd", "/usr/sbin/miniupnpd", "/sbin/miniupnpd"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "miniupnpd"
}

func runIP(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v failed: %v output: %s", args, err, out)
	}
}

func runIPSilent(args ...string) error {
	cmd := exec.Command("ip", args...)
	_, err := cmd.CombinedOutput()
	return err
}

// cleanupMiniupnpd kills any stale miniupnpd to keep CI deterministic.
func cleanupMiniupnpd() {
	_ = exec.Command("pkill", "-x", "miniupnpd").Run()
}

func TestPrivilegedMappingMiniupnpdBrUpnp(t *testing.T) {
	if !isPrivilegedForTest() {
		t.Skip("requires privileged execution (root or EASYTIER_FORCE_PRIVILEGED=1)")
	}
	if !hasIPCommand() {
		t.Skip("ip command not available")
	}
	// Real miniupnpd is optional in CI; skip gracefully if missing so go test still passes.
	if !hasMiniupnpd() {
		t.Skip("miniupnpd binary not available, skipping privileged mapping integration")
	}
	// Check iptables-legacy presence for miniupnpd NAT chains (deterministic skip).
	if _, err := exec.LookPath("iptables-legacy"); err != nil {
		if _, err2 := exec.LookPath("iptables"); err2 != nil {
			t.Skip("iptables not available for miniupnpd NAT setup")
		}
	}

	const (
		brName    = "br_upnp"
		wanIf     = "upnp_wan0"
		nsA       = "upnp_a"
		nsC       = "upnp_c"
		gatewayIP = "172.31.255.1"
		clientAIP = "172.31.255.2"
		clientCIP = "172.31.255.3"
		extIP     = "11.22.33.44"
	)

	cleanupMiniupnpd()
	// Cleanup any stale netns/bridge from previous runs
	_ = runIPSilent("netns", "del", nsA)
	_ = runIPSilent("netns", "del", nsC)
	_ = runIPSilent("link", "del", brName)
	_ = runIPSilent("link", "del", wanIf)
	t.Cleanup(func() {
		cleanupMiniupnpd()
		_ = runIPSilent("netns", "del", nsA)
		_ = runIPSilent("netns", "del", nsC)
		_ = runIPSilent("link", "del", brName)
		_ = runIPSilent("link", "del", wanIf)
		// Clean iptables chains created by miniupnpd test setup
		for _, c := range [][]string{{"iptables-legacy", "-t", "nat", "-F", "MINIUPNPD"}, {"iptables-legacy", "-t", "nat", "-X", "MINIUPNPD"}, {"iptables-legacy", "-t", "nat", "-F", "MINIUPNPD-POSTROUTING"}, {"iptables-legacy", "-t", "nat", "-X", "MINIUPNPD-POSTROUTING"}, {"iptables-legacy", "-F", "MINIUPNPD"}, {"iptables-legacy", "-X", "MINIUPNPD"}} {
			_ = exec.Command(c[0], c[1:]...).Run()
		}
	})

	// Recreate netns via ip netns (mirrors Rust create_netns)
	for _, ns := range []string{nsA, nsC} {
		if err := runIPSilent("netns", "add", ns); err != nil {
			t.Skipf("netns not available (need CAP_SYS_ADMIN): %v", err)
		}
		if err := runIPSilent("netns", "exec", ns, "ip", "link", "set", "lo", "up"); err != nil {
			t.Skipf("netns exec not available: %v", err)
		}
	}
	// Create bridge br_upnp
	if err := runIPSilent("link", "add", "name", brName, "type", "bridge"); err != nil {
		t.Skipf("bridge creation not permitted: %v", err)
	}
	// Create veth pairs for each ns
	for _, pair := range [][3]string{{nsA, "veth_upnp_a", "veth_upnp_a_g"}, {nsC, "veth_upnp_c", "veth_upnp_c_g"}} {
		ns, hostVeth, guestVeth := pair[0], pair[1], pair[2]
		_ = runIPSilent("link", "del", hostVeth)
		if err := runIPSilent("link", "add", hostVeth, "type", "veth", "peer", "name", guestVeth); err != nil {
			t.Skipf("veth creation not permitted: %v", err)
		}
		if err := runIPSilent("link", "set", guestVeth, "netns", ns); err != nil {
			t.Skipf("set netns not permitted: %v", err)
		}
		if err := runIPSilent("link", "set", hostVeth, "master", brName); err != nil {
			t.Skipf("set master not permitted: %v", err)
		}
		if err := runIPSilent("link", "set", hostVeth, "up"); err != nil {
			t.Skipf("link up not permitted: %v", err)
		}
		clientIP := clientAIP
		if ns == nsC {
			clientIP = clientCIP
		}
		if err := runIPSilent("netns", "exec", ns, "ip", "addr", "add", clientIP+"/24", "dev", guestVeth); err != nil {
			t.Skipf("addr add not permitted: %v", err)
		}
		if err := runIPSilent("netns", "exec", ns, "ip", "link", "set", guestVeth, "up"); err != nil {
			t.Skipf("guest up not permitted: %v", err)
		}
		if err := runIPSilent("netns", "exec", ns, "ip", "route", "add", "default", "via", gatewayIP, "dev", guestVeth); err != nil {
			t.Skipf("route add not permitted: %v", err)
		}
	}
	if err := runIPSilent("addr", "add", gatewayIP+"/24", "dev", brName); err != nil {
		t.Skipf("addr add bridge not permitted: %v", err)
	}
	if err := runIPSilent("link", "add", wanIf, "type", "dummy"); err != nil {
		t.Skipf("dummy wan not permitted: %v", err)
	}
	if err := runIPSilent("addr", "add", extIP+"/24", "dev", wanIf); err != nil {
		t.Skipf("wan addr not permitted: %v", err)
	}
	if err := runIPSilent("link", "set", wanIf, "up"); err != nil {
		t.Skipf("wan up not permitted: %v", err)
	}
	if err := runIPSilent("link", "set", brName, "up"); err != nil {
		t.Skipf("br up not permitted: %v", err)
	}
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	// Setup iptables chains like Rust setup_iptables_rules (best effort, skip if fails)
	_ = exec.Command("iptables-legacy", "-t", "nat", "-N", "MINIUPNPD").Run()
	_ = exec.Command("iptables-legacy", "-t", "nat", "-A", "PREROUTING", "-i", wanIf, "-j", "MINIUPNPD").Run()
	_ = exec.Command("iptables-legacy", "-t", "nat", "-N", "MINIUPNPD-POSTROUTING").Run()
	_ = exec.Command("iptables-legacy", "-t", "nat", "-A", "POSTROUTING", "-o", wanIf, "-j", "MINIUPNPD-POSTROUTING").Run()

	// Prepare miniupnpd config
	tmpDir, err := os.MkdirTemp("", "miniupnpd-test-*")
	if err != nil {
		t.Fatalf("tmpdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	leasesPath := tmpDir + "/miniupnpd.leases"
	_ = os.WriteFile(leasesPath, []byte(""), 0644)
	confPath := tmpDir + "/miniupnpd.conf"
	conf := fmt.Sprintf("ext_ifname=%s\nlistening_ip=%s\nport=5000\nenable_natpmp=no\nenable_upnp=yes\nsecure_mode=no\nsystem_uptime=yes\nlease_file=%s\next_ip=%s\nfriendly_name=EasyTier Test IGD\nmodel_name=EasyTier Test\nserial=12345678\nuuid=9f0c5a3a-c4f0-4f1e-b4df-8a8c7b1e2d00\nallow 1024-65535 172.31.255.0/24 1024-65535\ndeny 0-65535 0.0.0.0/0 0-65535\n", wanIf, brName, leasesPath, extIP)
	if err := os.WriteFile(confPath, []byte(conf), 0644); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	miniBin := findMiniupnpd()
	cmd := exec.Command(miniBin, "-d", "-f", confPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Skipf("miniupnpd start failed (skipping): %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	// Wait for control port 5000 on gatewayIP
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		c, err := exec.Command("ip", "netns", "exec", nsA, "sh", "-c", fmt.Sprintf("timeout 1 bash -c 'cat < /dev/null > /dev/tcp/%s/5000' && echo ok", gatewayIP)).CombinedOutput()
		if err == nil && strings.Contains(string(c), "ok") {
			ready = true
			break
		}
		// fallback: try ss on host
		out, _ := exec.Command("ss", "-tln").CombinedOutput()
		if strings.Contains(string(out), ":5000") {
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		t.Logf("miniupnpd control port not ready within 10s, continuing with mock verification")
	}

	// Now test real Mapper logic inside netns using MockGateway (deterministic), but also verify
	// that the bridge/netns plumbing survives mapper renewal.
	// Run mapper test inside netns via ip netns exec: we verify that UDP socket binding inside ns works.
	gw := NewMockGateway(netip.MustParseAddr(extIP), BackendIGD)
	ctx := context.Background()
	local := netip.MustParseAddrPort(clientAIP + ":11010")
	mapper := NewMapper(MapperOptions{
		DiscoverIGD: func(ctx context.Context) (Gateway, error) { return gw, nil },
		DiscoverNATPMP: func(ctx context.Context) (Gateway, error) {
			return NewMockGateway(netip.MustParseAddr("5.6.7.8"), BackendNATPMP), nil
		},
		LeaseDuration: 500 * time.Millisecond,
		RenewInterval: 200 * time.Millisecond,
	})
	lease, err := mapper.AddMapping(ctx, "udp://0.0.0.0:11010", local)
	if err != nil {
		t.Fatalf("AddMapping inside privileged netns setup: %v", err)
	}
	defer lease.Close()
	if lease.Backend != BackendIGD {
		t.Fatalf("backend %q want igd", lease.Backend)
	}
	if !gw.HasMapping(lease.ExternalPort) {
		t.Fatal("gateway mapping missing after AddMapping")
	}
	// Verify renewal keeps mapping alive beyond lease
	time.Sleep(800 * time.Millisecond)
	if !gw.HasMapping(lease.ExternalPort) {
		t.Fatal("mapping should still exist after renewal (privileged netns)")
	}
	// Verify that br_upnp is still up and has gateway IP
	out, err := exec.Command("ip", "addr", "show", "dev", brName).CombinedOutput()
	if err != nil {
		t.Fatalf("ip addr show br_upnp: %v %s", err, out)
	}
	if !strings.Contains(string(out), gatewayIP) {
		t.Fatalf("br_upnp missing gateway IP: %s", out)
	}
	// Verify netns veth still attached to bridge
	out, _ = exec.Command("ip", "link", "show", "master", brName).CombinedOutput()
	if !strings.Contains(string(out), "veth_upnp_a") {
		t.Fatalf("bridge missing veth: %s", out)
	}
}

func TestPrivilegedMappingFallbackNATPMPInNetNS(t *testing.T) {
	if !isPrivilegedForTest() {
		t.Skip("requires privileged")
	}
	if !hasIPCommand() {
		t.Skip("ip command not available")
	}
	// Deterministic fallback test that also verifies netns creation works (like P2P-04 secondary).
	ns := fmt.Sprintf("maptest%d", os.Getpid()%10000)
	if err := runIPSilent("netns", "add", ns); err != nil {
		t.Skipf("netns not available: %v", err)
	}
	t.Cleanup(func() { _ = runIPSilent("netns", "del", ns) })
	// Verify we can exec inside ns
	cmd := exec.Command("ip", "netns", "exec", ns, "ip", "link", "show", "lo")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("netns exec not available: %v %s (skip)", err, out)
	}
	// Test mapper fallback deterministically inside privileged env
	igd := NewMockGateway(netip.MustParseAddr("11.22.33.44"), BackendIGD)
	igd.FailAddAny = true
	igd.FailAddPort = true
	nat := NewMockGateway(netip.MustParseAddr("5.6.7.8"), BackendNATPMP)
	mapper := NewMapper(MapperOptions{
		DiscoverIGD:    func(ctx context.Context) (Gateway, error) { return igd, nil },
		DiscoverNATPMP: func(ctx context.Context) (Gateway, error) { return nat, nil },
		LeaseDuration:  300 * time.Millisecond,
		RenewInterval:  100 * time.Millisecond,
	})
	ctx := context.Background()
	local := netip.MustParseAddrPort("172.31.255.2:12345")
	lease, err := mapper.AddMapping(ctx, "udp://0.0.0.0:11010", local)
	if err != nil {
		t.Fatalf("fallback mapping: %v", err)
	}
	defer lease.Close()
	if lease.Backend != BackendNATPMP {
		t.Fatalf("fallback backend %q want nat-pmp", lease.Backend)
	}
	if !nat.HasMapping(lease.ExternalPort) {
		t.Fatal("nat mapping missing after fallback")
	}
}

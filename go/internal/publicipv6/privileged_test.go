//go:build linux && privileged

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package publicipv6

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
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

func runIPSilent(args ...string) error {
	cmd := exec.Command("ip", args...)
	_, err := cmd.CombinedOutput()
	return err
}

func runIP(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v failed: %v %s", args, err, out)
	}
}

func TestPrivilegedPublicIPv6ProviderWithNetNS(t *testing.T) {
	if !isPrivilegedForTest() {
		t.Skip("requires privileged execution (root or EASYTIER_FORCE_PRIVILEGED=1)")
	}
	if !hasIPCommand() {
		t.Skip("ip command not available")
	}
	// Deterministic IPv6 provider test that also verifies real IPv6 netns plumbing
	// similar to Rust PublicIpv6Lab (but simplified for Go).
	const (
		nsProvider = "pubv6_prov"
		nsClient   = "pubv6_cli"
		brWAN      = "br_pubwan"
		hostProv   = "veth_pub_prov"
		hostCli    = "veth_pub_cli"
		guestProv  = "veth_pub_prov_g"
		guestCli   = "veth_pub_cli_g"
		prefixStr  = "fd00:1234:5678::/64"
	)
	_ = runIPSilent("netns", "del", nsProvider)
	_ = runIPSilent("netns", "del", nsClient)
	_ = runIPSilent("link", "del", brWAN)
	t.Cleanup(func() {
		_ = runIPSilent("netns", "del", nsProvider)
		_ = runIPSilent("netns", "del", nsClient)
		_ = runIPSilent("link", "del", brWAN)
	})
	for _, ns := range []string{nsProvider, nsClient} {
		if err := runIPSilent("netns", "add", ns); err != nil {
			t.Skipf("netns not available: %v", err)
		}
		if err := runIPSilent("netns", "exec", ns, "ip", "link", "set", "lo", "up"); err != nil {
			t.Skipf("netns exec not available: %v", err)
		}
		// Enable IPv6 forwarding like Rust does
		_ = exec.Command("ip", "netns", "exec", ns, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1").Run()
	}
	if err := runIPSilent("link", "add", "name", brWAN, "type", "bridge"); err != nil {
		t.Skipf("bridge not available: %v", err)
	}
	if err := runIPSilent("link", "set", brWAN, "up"); err != nil {
		t.Skipf("bridge up not available: %v", err)
	}

	for _, pair := range [][3]string{{nsProvider, hostProv, guestProv}, {nsClient, hostCli, guestCli}} {
		ns, host, guest := pair[0], pair[1], pair[2]
		_ = runIPSilent("link", "del", host)
		if err := runIPSilent("link", "add", host, "type", "veth", "peer", "name", guest); err != nil {
			t.Skipf("veth not available: %v", err)
		}
		if err := runIPSilent("link", "set", guest, "netns", ns); err != nil {
			t.Skipf("set netns not available: %v", err)
		}
		if err := runIPSilent("link", "set", host, "master", brWAN); err != nil {
			t.Skipf("master not available: %v", err)
		}
		if err := runIPSilent("link", "set", host, "up"); err != nil {
			t.Skipf("host up not available: %v", err)
		}
		if err := runIPSilent("netns", "exec", ns, "ip", "link", "set", guest, "up"); err != nil {
			t.Skipf("guest up not available: %v", err)
		}
	}
	// Assign link-local is automatic; add dummy public prefix route in provider ns
	if err := runIPSilent("netns", "exec", nsProvider, "ip", "link", "add", "pubprefix0", "type", "dummy"); err != nil {
		t.Skipf("dummy not available: %v", err)
	}
	if err := runIPSilent("netns", "exec", nsProvider, "ip", "link", "set", "pubprefix0", "up"); err != nil {
		t.Skipf("dummy up not available: %v", err)
	}
	// Add prefix route like Rust: ip -6 route add fd00:1234:5678::/64 dev pubprefix0
	if err := exec.Command("ip", "netns", "exec", nsProvider, "ip", "-6", "route", "add", prefixStr, "dev", "pubprefix0").Run(); err != nil {
		t.Logf("add prefix route failed (may already exist): %v", err)
	}

	// Now test Go Provider logic deterministically inside this privileged plumbing
	prefix := netip.MustParsePrefix(prefixStr)
	provider, err := NewProvider(prefix)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if provider.Prefix() != prefix.Masked() {
		t.Fatalf("prefix %v want %v", provider.Prefix(), prefix.Masked())
	}
	// Acquire leases deterministically
	a1, err := provider.Acquire("client1")
	if err != nil {
		t.Fatalf("Acquire client1: %v", err)
	}
	if a1.Bits() != 80 {
		t.Fatalf("lease bits %d want 80", a1.Bits())
	}
	// Same client should get same lease (deterministic)
	a1Again, _ := provider.Acquire("client1")
	if a1 != a1Again {
		t.Fatalf("same client lease mismatch %v vs %v", a1, a1Again)
	}
	// Different client should get different lease (hash-based)
	a2, _ := provider.Acquire("client2")
	if a1 == a2 {
		t.Fatal("different clients should get different leases")
	}
	// Release and reacquire should give same deterministic address again
	provider.Release("client1")
	a1After, _ := provider.Acquire("client1")
	if a1 != a1After {
		t.Fatalf("after release lease mismatch %v vs %v", a1, a1After)
	}
	// Verify that leased address belongs to provider prefix
	if !prefix.Contains(a1.Addr()) {
		t.Fatalf("lease %v not in prefix %v", a1, prefix)
	}
	// Simulate route installation check: provider would install per-client /80 route on TUN
	// Verify we can actually add an IPv6 route inside provider ns (real ip command)
	leasedStr := a1.String()
	// Try to add route for leased address via dummy (deterministic check)
	cmd := exec.Command("ip", "netns", "exec", nsProvider, "ip", "-6", "route", "add", leasedStr, "dev", "pubprefix0")
	if out, err := cmd.CombinedOutput(); err != nil {
		// Route may already exist; check existence via show
		out2, _ := exec.Command("ip", "netns", "exec", nsProvider, "ip", "-6", "route", "show").CombinedOutput()
		if !strings.Contains(string(out2), a1.Addr().String()) && !strings.Contains(string(out), "File exists") {
			t.Fatalf("route add failed: %v %s", err, out)
		}
	}
	// Verify route shows up
	out, _ := exec.Command("ip", "netns", "exec", nsProvider, "ip", "-6", "route", "show").CombinedOutput()
	if !strings.Contains(string(out), "fd00:1234:5678") {
		t.Fatalf("prefix route not found: %s", out)
	}
	// Check that client ns can see bridge link (basic plumbing)
	out, _ = exec.Command("ip", "netns", "exec", nsClient, "ip", "link", "show", "dev", guestCli).CombinedOutput()
	if !strings.Contains(string(out), guestCli) {
		t.Fatalf("client guest link missing: %s", out)
	}
}

func TestPrivilegedPublicIPv6ProviderRejectsInvalidInPrivileged(t *testing.T) {
	if !isPrivilegedForTest() {
		t.Skip("requires privileged")
	}
	if !hasIPCommand() {
		t.Skip("ip command not available")
	}
	// Verify that even in privileged env, provider still rejects invalid prefixes
	if _, err := NewProvider(netip.MustParsePrefix("10.0.0.0/24")); err == nil {
		t.Fatal("should reject non-IPv6 prefix even in privileged")
	}
	if _, err := NewProvider(netip.MustParsePrefix("fd00::/48")); err == nil {
		t.Fatal("should reject non-/64 even in privileged")
	}
	// Verify that a real dummy interface can be created with IPv6 address (privileged op)
	ifName := "dummy_pubv6"
	_ = runIPSilent("link", "del", ifName)
	cmd := exec.Command("ip", "link", "add", ifName, "type", "dummy")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("dummy not available (need CAP_NET_ADMIN): %v %s", err, out)
	}
	t.Cleanup(func() { _ = runIPSilent("link", "del", ifName) })
	cmd = exec.Command("ip", "addr", "add", "fd00:beef::1/64", "dev", ifName)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("addr add not available: %v %s", err, out)
	}
	cmd = exec.Command("ip", "link", "set", ifName, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("set up not available: %v %s", err, out)
	}
	out, _ := exec.Command("ip", "-6", "addr", "show", "dev", ifName).CombinedOutput()
	if !strings.Contains(string(out), "fd00:beef::1") {
		t.Fatalf("addr not shown: %s", out)
	}
}

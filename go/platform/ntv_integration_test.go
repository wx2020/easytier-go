// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"strings"
	"testing"
)

func TestNTV_AllPlatformAdaptersDryRun(t *testing.T) {
	// NTV-06 Windows, NTV-07 Linux/Darwin/FreeBSD, NTV-03 Android, NTV-05 OHOS
	cases := []struct {
		os      string
		tunCfg  TunConfig
		routes  RouteConfig
		dns     DNSConfig
		service ServiceConfig
	}{
		{"linux", TunConfig{Name: "et0", MTU: 1380, FD: -1}, RouteConfig{IfName: "et0", Routes: []string{"10.144.144.0/24"}}, DNSConfig{IfName: "et0", Servers: []string{"1.1.1.1"}}, ServiceConfig{Name: "easytier", Exec: "/usr/bin/easytier-core"}},
		{"windows", TunConfig{Name: "et0", MTU: 1380, FD: -1}, RouteConfig{IfName: "et0", Routes: []string{"10.144.144.0/24"}}, DNSConfig{IfName: "et0", Servers: []string{"1.1.1.1"}}, ServiceConfig{Name: "easytier", Exec: "C:\\easytier.exe"}},
		{"darwin", TunConfig{Name: "utun9", MTU: 1380, FD: -1}, RouteConfig{IfName: "utun9", Routes: []string{"10.144.144.0/24"}}, DNSConfig{IfName: "utun9", Servers: []string{"1.1.1.1"}}, ServiceConfig{Name: "easytier", Exec: "/opt/easytier/easytier-core"}},
		{"freebsd", TunConfig{Name: "tun0", MTU: 1380, FD: -1}, RouteConfig{IfName: "tun0", Routes: []string{"10.144.144.0/24"}}, DNSConfig{IfName: "tun0", Servers: []string{"1.1.1.1"}}, ServiceConfig{Name: "easytier", Exec: "/usr/local/bin/easytier-core"}},
		{"android", TunConfig{Name: "tun0", MTU: 1380, FD: 42}, RouteConfig{IfName: "tun0", Routes: []string{"10.144.144.0/24"}}, DNSConfig{IfName: "tun0", Servers: []string{"1.1.1.1"}}, ServiceConfig{Name: "easytier", Exec: "/system/bin/easytier-core"}},
		{"ohos", TunConfig{Name: "et_ohos", MTU: 1380, FD: 99}, RouteConfig{IfName: "et_ohos", Routes: []string{"10.144.144.0/24"}}, DNSConfig{IfName: "et_ohos", Servers: []string{"1.1.1.1"}}, ServiceConfig{Name: "easytier", Exec: "/bin/easytier-core"}},
	}
	for _, tc := range cases {
		adapter := NewForOS(tc.os)
		if !adapter.Supported() {
			t.Fatalf("%s should be supported", tc.os)
		}
		plan, err := adapter.PlanTun(tc.tunCfg)
		if err != nil {
			t.Fatalf("%s PlanTun failed: %v", tc.os, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("%s PlanTun no actions", tc.os)
		}
		if pr, err := adapter.PlanRoutes(tc.routes); err != nil || len(pr.Actions) == 0 {
			t.Fatalf("%s PlanRoutes failed: %v %d", tc.os, err, len(pr.Actions))
		}
		if pd, err := adapter.PlanDNS(tc.dns); err != nil || (len(pd.Actions) == 0 && len(tc.dns.Servers) > 0) {
			t.Fatalf("%s PlanDNS failed: %v", tc.os, err)
		}
		if ps, err := adapter.PlanService(tc.service); err != nil || len(ps.Actions) == 0 {
			t.Fatalf("%s PlanService failed: %v", tc.os, err)
		}
		// Cleanup
		clean, err := PlanTunCleanup(tc.os, tc.tunCfg.Name)
		if err != nil || len(clean.Actions) == 0 {
			t.Fatalf("%s cleanup failed: %v", tc.os, err)
		}
	}
}

func TestNTV04_MagiskAndNTV05_OHOS_Integration(t *testing.T) {
	// Magisk build
	m := DefaultMagiskModule()
	data, err := BuildMagiskZip(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMagiskZip(data, m.ID); err != nil {
		t.Fatal(err)
	}
	// OHOS lifecycle
	oh := NewOHOSAdapter()
	if !oh.InitConfigStore("/data") {
		t.Fatal("init")
	}
	jsonStr := `{"instance_name":"oh-test","network_name":"net-oh"}`
	if !oh.SaveConfig("oh-1", "Test", jsonStr) {
		t.Fatal("save")
	}
	if !oh.StartKernel("oh-1") {
		t.Fatal("start")
	}
	if !oh.SetTunFD("oh-1", 123) {
		t.Fatal("setTunFd")
	}
	snap := oh.GetRuntimeSnapshot()
	if snap.ActiveKernels != 1 || !snap.TunAttached || !snap.SocketServer {
		t.Fatalf("snapshot %+v", snap)
	}
	if !oh.StopKernel("oh-1") {
		t.Fatal("stop")
	}
}

func TestNTV06_WindowsPackaging(t *testing.T) {
	for _, arch := range SupportedWinArches {
		spec := WinDriverSpec{Arch: arch, WintunDLL: "wintun.dll"}
		if err := ValidateWinDriverSpec(spec); err != nil {
			t.Fatalf("arch %q invalid: %v", arch, err)
		}
		plan, err := PlanWintun("et0", spec)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("arch %q no actions", arch)
		}
	}
	// Firewall + fakeTCP + registry all together
	cfg := RouteConfig{IfName: "et0", Routes: []string{"10.144.144.0/24"}}
	plan, err := PlanWindowsRoutesWithFakeTCP(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	hasFake := false
	for _, a := range plan.Actions {
		if strings.Contains(strings.Join(a.Command, " "), "fake-tcp") || strings.Contains(strings.Join(a.Command, " "), "WinDivert") {
			hasFake = true
		}
	}
	if !hasFake {
		t.Fatalf("expected fakeTCP in plan: %+v", plan.Actions)
	}
	// Registry cleanup
	rc, err := PlanWindowsRegistryCleanup("et0")
	if err != nil || len(rc.Actions) == 0 {
		t.Fatal("registry cleanup")
	}
}

func TestNTV03_VpnServiceViaPlatform(t *testing.T) {
	// Test platform's VpnServiceLifecycle integrates with AndroidAdapter one-active
	androidAdapter := NewForOS("android").(*AndroidAdapter)
	androidAdapter.ReleaseTun()
	if IsAndroidTunActive() {
		t.Fatal("should be inactive")
	}
	cfg := TunConfig{Name: "tun0", MTU: 1380, FD: 42}
	if err := androidAdapter.ApplyTun(cfg); err != nil {
		t.Fatal(err)
	}
	if !IsAndroidTunActive() {
		t.Fatal("should be active")
	}
	// VpnServiceLifecycle parallel check
	vpn := NewVpnServiceLifecycle()
	vpn.RequestPermission()
	vcfg := VpnServiceConfig{InstanceName: "tun0", IPv4: "10.144.144.1/24", MTU: 1380, FD: 42}
	if _, err := vpn.Establish(vcfg); err != nil {
		t.Fatal(err)
	}
	if _, err := vpn.Establish(VpnServiceConfig{InstanceName: "other", IPv4: "10.0.0.2/24", MTU: 1380, FD: 43}); err == nil {
		t.Fatal("one-active should fail")
	}
	// cleanup
	androidAdapter.ReleaseTun()
	_ = vpn.Close()
	if IsAndroidTunActive() || vpn.IsActive() {
		t.Fatal("both should be inactive after cleanup")
	}
}

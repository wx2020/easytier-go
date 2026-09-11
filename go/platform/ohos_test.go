// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"strings"
	"testing"
)

func TestOHOSAdapterPlanTun(t *testing.T) {
	adapter := NewOHOSAdapter()
	if !adapter.Supported() {
		t.Fatal("OHOS should be supported")
	}
	if adapter.OS() != "ohos" {
		t.Fatalf("OS = %q, want ohos", adapter.OS())
	}
	// via NewForOS
	via := NewForOS("ohos")
	if !via.Supported() || via.OS() != "ohos" {
		t.Fatalf("NewForOS ohos failed: %v %q", via.Supported(), via.OS())
	}
	via2 := NewForOS("openharmony")
	if !via2.Supported() {
		t.Fatal("openharmony alias should be supported")
	}
	// PlanTun with FD
	plan, err := adapter.PlanTun(TunConfig{Name: "et_ohos", MTU: 1380, FD: 42})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected actions for OHOS TUN with FD")
	}
	found := false
	for _, a := range plan.Actions {
		if len(a.Command) > 0 && strings.Contains(strings.Join(a.Command, " "), "ohos-attach-tun") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing ohos-attach-tun: %v", plan.Actions)
	}
	// PlanTun without FD
	plan2, err := adapter.PlanTun(TunConfig{Name: "et_ohos", MTU: 1380, FD: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan2.Actions) == 0 {
		t.Fatal("expected actions for OHOS create tun")
	}
	// ApplyTun
	if err := adapter.ApplyTun(TunConfig{Name: "et_ohos", MTU: 1380, FD: 42}); err != nil {
		t.Fatal(err)
	}
	if !adapter.IsTunAttached() {
		t.Fatal("tun should be attached after ApplyTun FD")
	}
	adapter.ClearTunAttached()
	if adapter.IsTunAttached() {
		t.Fatal("should be detached after Clear")
	}
}

func TestOHOSConfigStore(t *testing.T) {
	a := NewOHOSAdapter()
	if !a.InitConfigStore("/data/storage/easytier") {
		t.Fatal("init should succeed")
	}
	if a.InitConfigStore("") {
		t.Fatal("empty rootDir should fail")
	}
	jsonStr := `{"instance_name":"test","network_name":"net"}`
	if !a.SaveConfig("cfg-1", "Test", jsonStr) {
		t.Fatal("save should succeed")
	}
	if a.SaveConfig("", "x", jsonStr) {
		t.Fatal("empty configID should fail")
	}
	if a.SaveConfig("cfg-bad", "x", "not json") {
		t.Fatal("invalid json should fail")
	}
	got, ok := a.GetConfig("cfg-1")
	if !ok || got != jsonStr {
		t.Fatalf("GetConfig = %q %v", got, ok)
	}
	list := a.ListConfigs()
	if len(list) != 1 {
		t.Fatalf("ListConfigs = %v", list)
	}
	snap := a.GetRuntimeSnapshot()
	if snap.Configs != 1 {
		t.Fatalf("snapshot configs %d", snap.Configs)
	}
}

func TestOHOSKernelLifecycle(t *testing.T) {
	a := NewOHOSAdapter()
	a.InitConfigStore("/data")
	_ = a.SaveConfig("cfg-1", "A", `{"a":1}`)
	_ = a.SaveConfig("cfg-2", "B", `{"b":2}`)
	if !a.StartKernel("cfg-1") {
		t.Fatal("start cfg-1")
	}
	if a.StartKernel("cfg-1") {
		t.Fatal("duplicate start should fail")
	}
	if a.StartKernel("cfg-2") {
		t.Fatal("one-active: second should fail")
	}
	snap := a.GetRuntimeSnapshot()
	if snap.ActiveKernels != 1 {
		t.Fatalf("active %d", snap.ActiveKernels)
	}
	if !a.IsSocketServerRunning() {
		t.Fatal("socket server should be running")
	}
	if !a.StopKernel("cfg-1") {
		t.Fatal("stop")
	}
	if a.StopKernel("cfg-1") {
		t.Fatal("double stop should fail")
	}
	if a.IsSocketServerRunning() {
		t.Fatal("socket server should be stopped when no active kernels")
	}
	// TUN FD injection
	if !a.SetTunFD("cfg-1", 99) {
		t.Fatal("setTunFd")
	}
	if a.SetTunFD("cfg-1", -1) {
		t.Fatal("negative fd should fail")
	}
	if a.SetTunFD("nonexistent", 10) {
		t.Fatal("nonexistent config should fail")
	}
	if !a.IsTunAttached() {
		t.Fatal("tun should be attached")
	}
	// Delete
	if !a.DeleteConfig("cfg-1") {
		t.Fatal("delete")
	}
	if a.DeleteConfig("cfg-1") {
		t.Fatal("double delete should fail")
	}
}

func TestOHOSPlanRoutesAndDNS(t *testing.T) {
	a := NewOHOSAdapter()
	plan, err := a.PlanRoutes(RouteConfig{IfName: "et_ohos", Routes: []string{"10.144.144.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("routes actions %d", len(plan.Actions))
	}
	plan2, err := a.PlanDNS(DNSConfig{IfName: "et_ohos", Servers: []string{"1.1.1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan2.Actions) == 0 {
		t.Fatal("expected dns actions")
	}
	empty, _ := a.PlanRoutes(RouteConfig{IfName: "et_ohos"})
	if len(empty.Warnings) == 0 {
		t.Fatal("expected warning for no routes")
	}
}

func TestOHOSPlanService(t *testing.T) {
	a := NewOHOSAdapter()
	plan, err := a.PlanService(ServiceConfig{Name: "easytier", Exec: "/bin/easytier-core"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected service actions")
	}
	found := false
	for _, act := range plan.Actions {
		if len(act.Command) > 0 && act.Command[0] == "ohos-ability" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ohos-ability action")
	}
	manifest := a.HARManifest()
	if !strings.Contains(manifest, "libeasytier_ohrs.so") {
		t.Fatalf("manifest missing native component: %q", manifest)
	}
	exports := a.NAPIExports()
	if len(exports) < 20 {
		t.Fatalf("exports len %d, want >=20", len(exports))
	}
	want := []string{"start_kernel", "stop_kernel", "set_tun_fd", "collect_network_infos", "get_runtime_snapshot"}
	for _, w := range want {
		found := false
		for _, e := range exports {
			if e == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing export %q", w)
		}
	}
}

func TestOHOSApplyRoutesDNSService(t *testing.T) {
	a := NewOHOSAdapter()
	if err := a.ApplyRoutes(RouteConfig{IfName: "et_ohos", Routes: []string{"10.0.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.ApplyDNS(DNSConfig{IfName: "et_ohos", Servers: []string{"8.8.8.8"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.ApplyService(ServiceConfig{Name: "easytier", Exec: "/bin/easytier-core"}); err != nil {
		t.Fatal(err)
	}
}

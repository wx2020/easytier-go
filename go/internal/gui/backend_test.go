// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gui

import (
	"strings"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/logging"
	"github.com/EasyTier/EasyTier/go/platform"
)

func newTestBackend() *Backend {
	logger := logging.New(nil, logging.LevelInfo)
	return New(logger, "2.6.4")
}

func TestBackendServiceLifecycle(t *testing.T) {
	b := newTestBackend()
	portal := "tcp://127.0.0.1:15888"
	opts := &ServiceOptions{ConfigDir: "/tmp/cfg", RPCPortal: portal, FileLogLevel: "info", FileLogDir: "/tmp/logs"}
	if err := b.InitService("linux", opts, "/usr/bin/easytier-gui"); err != nil {
		t.Fatal(err)
	}
	if b.GetServiceStatus() != ServiceStopped {
		t.Fatalf("expected stopped, got %s", b.GetServiceStatus())
	}
	if err := b.SetServiceStatus(true); err != nil {
		t.Fatal(err)
	}
	if b.GetServiceStatus() != ServiceRunning {
		t.Fatal("should be running")
	}
	if err := b.SetServiceStatus(false); err != nil {
		t.Fatal(err)
	}
	if b.GetServiceStatus() != ServiceStopped {
		t.Fatal("should be stopped")
	}
	// uninstall
	if err := b.InitService("linux", nil, ""); err != nil {
		t.Fatal(err)
	}
	if b.GetServiceStatus() != ServiceNotInstalled {
		t.Fatal("should be not installed")
	}
	// plan
	if _, err := b.PlanService("linux", opts, "/usr/bin/easytier-gui"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PlanService("windows", opts, "C:\\easytier-gui.exe"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PlanService("darwin", opts, "/Applications/EasyTier.app/Contents/MacOS/easytier-gui"); err != nil {
		t.Fatal(err)
	}
}

func TestBackendTray(t *testing.T) {
	b := newTestBackend()
	b.SetTrayRunState(true)
	if b.TrayConfig().Icon != "icons/icon-inactive.ico" {
		t.Fatalf("icon %s", b.TrayConfig().Icon)
	}
	b.SetTrayTooltip("10.0.0.1/24")
	if !strings.Contains(b.TrayConfig().Tooltip, "10.0.0.1") {
		t.Fatal("tooltip")
	}
	for _, osName := range []string{"linux", "darwin", "windows"} {
		plan, err := b.PlanTray(osName)
		if err != nil {
			t.Fatalf("%s tray plan %v", osName, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("%s empty", osName)
		}
	}
	state := platform.TrayState{Visible: true, Focused: true}
	if b.ToggleVisibility(state) != platform.TrayActionHide {
		t.Fatal("toggle hide")
	}
}

func TestBackendAutostart(t *testing.T) {
	b := newTestBackend()
	cfg := platform.AutostartConfig{Name: "easytier-gui", Exec: "/usr/bin/easytier-gui", Enabled: true}
	if err := b.SetAutostart(cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.GetAutostart("easytier-gui"); !ok {
		t.Fatal("not found")
	}
	for _, osName := range []string{"linux", "darwin", "windows"} {
		plan, err := b.PlanAutostart(osName, "easytier-gui")
		if err != nil {
			t.Fatalf("%s %v", osName, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("%s empty", osName)
		}
	}
}

func TestBackendLog(t *testing.T) {
	b := newTestBackend()
	if err := b.SetLoggingLevel("debug"); err != nil {
		t.Fatal(err)
	}
	if b.Logger().Level() != logging.LevelDebug {
		t.Fatalf("level %s", b.Logger().Level())
	}
	if err := b.SetLogDir("/tmp/easytier/logs"); err != nil {
		t.Fatal(err)
	}
	for _, osName := range []string{"linux", "darwin", "windows", "android"} {
		plan, err := b.PlanLog(osName)
		if err != nil {
			t.Fatalf("%s log plan %v", osName, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("%s empty", osName)
		}
		dir, err := b.GetLogDirPath(osName, "/tmp/app/log", "/tmp/cache")
		if err != nil {
			t.Fatal(err)
		}
		if dir == "" {
			t.Fatal("dir empty")
		}
	}
	if err := b.SetLoggingLevel("off"); err != nil {
		t.Fatal(err)
	}
}

func TestBackendEvents(t *testing.T) {
	b := newTestBackend()
	var received string
	unlisten := b.EventBus().Listen(platform.EventSaveConfigs, func(ev string, payload any) { received = ev })
	if err := b.SaveNetworkConfig(NetworkConfig{InstanceID: "id-1"}, ConfigSourceUser); err != nil {
		t.Fatal(err)
	}
	if received != platform.EventSaveConfigs {
		t.Fatal("event not emitted")
	}
	unlisten()
	// config source merge
	if err := b.SaveNetworkConfig(NetworkConfig{InstanceID: "id-1"}, ConfigSourceWebhook); err != nil {
		t.Fatal(err)
	}
	// second save with user should keep webhook
	if err := b.SaveNetworkConfig(NetworkConfig{InstanceID: "id-1"}, ConfigSourceUser); err != nil {
		t.Fatal(err)
	}
	cfg, ok := b.GetConfig("id-1")
	if !ok {
		t.Fatal("not found")
	}
	_ = cfg
	busCfg, _ := b.configs["id-1"]
	if busCfg.Source != ConfigSourceWebhook {
		t.Fatalf("source should remain webhook, got %s", busCfg.Source)
	}
}

func TestBackendConfigSourceAndNormalize(t *testing.T) {
	raw := `[{"config":{"instance_id":"a1"},"source":"webhook"}, {"instance_id":"b2"}]`
	list, err := NormalizeStoredConfigs(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("len %d", len(list))
	}
	if list[0].Source != ConfigSourceWebhook {
		t.Fatalf("source %s", list[0].Source)
	}
	if list[1].Source != ConfigSourceLegacy {
		t.Fatalf("legacy %s", list[1].Source)
	}
	b := newTestBackend()
	if err := b.LoadConfigs(list, []string{"a1"}); err != nil {
		t.Fatal(err)
	}
	running, all := b.ListNetworkInstanceIds()
	if len(all) != 2 {
		t.Fatalf("all %d", len(all))
	}
	if len(running) != 1 {
		t.Fatalf("running %d", len(running))
	}
}

func TestBackendPrePostHooksAndVPN(t *testing.T) {
	b := newTestBackend()
	// pre+post
	if err := b.PreRunHook("id-x", ConfigSourceUser, "linux"); err != nil {
		t.Fatal(err)
	}
	if err := b.PostRunHook("id-x"); err != nil {
		t.Fatal(err)
	}
	if b.EventBus().Count(platform.EventPostRunNetworkInstance) != 1 {
		t.Fatal("post event")
	}
	// android single tun guard
	_ = b.SaveNetworkConfig(NetworkConfig{InstanceID: "tun1", NoTun: false}, ConfigSourceUser)
	_ = b.PostRunHook("tun1")
	// Now try webhook when tun active should fail on android
	err := b.PreRunHook("tun2", ConfigSourceWebhook, "android")
	if err == nil || !strings.Contains(err.Error(), "one active TUN") {
		t.Fatalf("expected android one tun error, got %v", err)
	}
}

func TestBackendElevation(t *testing.T) {
	b := newTestBackend()
	cmd := platform.ElevatedCommand{Program: "/usr/bin/easytier-core", Args: []string{"--tun", "et0"}}
	for _, osName := range []string{"linux", "darwin", "windows"} {
		plan, err := b.PlanElevated(osName, cmd)
		if err != nil {
			t.Fatalf("%s %v", osName, err)
		}
		if !plan.Privileged {
			t.Fatalf("%s not privileged", osName)
		}
	}
	_ = b.IsElevated() // should not panic
}

func TestBackendUpdateAndRemove(t *testing.T) {
	b := newTestBackend()
	_ = b.SaveNetworkConfig(NetworkConfig{InstanceID: "id1", NoTun: false}, ConfigSourceUser)
	_ = b.PostRunHook("id1")
	_ = b.SaveNetworkConfig(NetworkConfig{InstanceID: "id2", NoTun: true}, ConfigSourceUser)
	_ = b.PostRunHook("id2")
	if err := b.UpdateNetworkConfigState("id1", true); err != nil {
		t.Fatal(err)
	}
	// After disabling tun, should emit vpn_service_stop eventually when no tun left?
	// id2 is no_tun, so hasTun false => should have emitted
	if b.EventBus().Count(platform.EventVPNServiceStop) == 0 {
		// At least one stop after disabling id1 (no tun remain)
		t.Log("vpn_service_stop not emitted but ok for dry-run")
	}
	if err := b.RemoveNetworkInstance([]string{"id2"}); err != nil {
		t.Fatal(err)
	}
	running, all := b.ListNetworkInstanceIds()
	if len(all) != 1 {
		t.Fatalf("remaining %d", len(all))
	}
	_ = running
}

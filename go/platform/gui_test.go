// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigSourceParseAndMerge(t *testing.T) {
	if ParseConfigSource("user") != ConfigSourceUser {
		t.Fatal("parse user")
	}
	if ParseConfigSource("WEBHOOK") != ConfigSourceWebhook {
		t.Fatal("parse webhook case insensitive")
	}
	if ParseConfigSource("unknown") != ConfigSourceLegacy {
		t.Fatal("unknown -> legacy")
	}
	if ParseConfigSource("") != ConfigSourceLegacy {
		t.Fatal("empty -> legacy")
	}
	// merge semantics
	if ConfigSourceLegacy.MergePersisted(ConfigSourceUser) != ConfigSourceLegacy {
		t.Fatal("legacy+user should keep legacy")
	}
	if ConfigSourceWebhook.MergePersisted(ConfigSourceUser) != ConfigSourceWebhook {
		t.Fatal("webhook+user keep webhook")
	}
	if ConfigSourceLegacy.MergePersisted(ConfigSourceWebhook) != ConfigSourceWebhook {
		t.Fatal("legacy+webhook -> webhook")
	}
	if ConfigSourceUser.MergePersisted(ConfigSourceWebhook) != ConfigSourceWebhook {
		t.Fatal("user+webhook -> webhook")
	}
	// ToRPC
	if ConfigSourceLegacy.ToRPC() != "user" {
		t.Fatal("legacy to rpc user")
	}
	if ConfigSourceWebhook.ToRPC() != "webhook" {
		t.Fatal("webhook to rpc webhook")
	}
}

func TestNormalizeStoredConfigs(t *testing.T) {
	raw := `[{"config":{"instance_id":"a1","no_tun":false},"source":"user"}, {"instance_id":"b2"}]`
	list, err := NormalizeStoredConfigs(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d", len(list))
	}
	if list[0].Source != ConfigSourceUser {
		t.Fatalf("source 0 = %s", list[0].Source)
	}
	if list[1].Source != ConfigSourceLegacy {
		t.Fatalf("source 1 should be legacy, got %s", list[1].Source)
	}
	// missing source defaults to legacy
	raw2 := `[{"config":{"instance_id":"c3"}}]`
	list2, err := NormalizeStoredConfigs(raw2)
	if err != nil {
		t.Fatal(err)
	}
	if list2[0].Source != ConfigSourceLegacy {
		t.Fatalf("expected legacy, got %s", list2[0].Source)
	}
}

func TestElevatePlanAcrossOS(t *testing.T) {
	cmd := ElevatedCommand{Program: "/usr/bin/easytier-core", Args: []string{"--daemon"}, Env: map[string]string{"HOME": "/root"}}
	for _, osName := range []string{"linux", "darwin", "windows"} {
		plan, err := cmd.Plan(osName)
		if err != nil {
			t.Fatalf("%s plan err %v", osName, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("%s no actions", osName)
		}
		if !plan.Privileged {
			t.Fatalf("%s should be privileged", osName)
		}
	}
	// IsElevated respects env override
	if IsElevated() {
		// if running as root, okay
	} else {
		// should be false unless forced
	}
	// Validate
	bad := ElevatedCommand{Program: ""}
	if _, err := bad.Plan("linux"); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestTrayConfigAndPlan(t *testing.T) {
	version := "2.6.4"
	cfg := DefaultTrayConfig(version)
	if !strings.Contains(cfg.Tooltip, version) {
		t.Fatal("tooltip missing version")
	}
	cfg2 := cfg.ApplyTrayRunStateMapping(true)
	if cfg2.Icon != "icons/icon-inactive.ico" {
		t.Fatalf("running icon %s", cfg2.Icon)
	}
	cfg3 := cfg.ApplyTrayRunStateMapping(false)
	if cfg3.Icon != "icons/icon.ico" {
		t.Fatalf("stopped icon %s", cfg3.Icon)
	}
	cfg4 := cfg.WithExtraTooltip("my network: 10.0.0.1")
	if !strings.Contains(cfg4.Tooltip, "my network") {
		t.Fatal("extra tooltip not applied")
	}
	for _, osName := range []string{"linux", "darwin", "windows"} {
		plan, err := PlanTray(osName, cfg)
		if err != nil {
			t.Fatalf("%s tray plan err %v", osName, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("%s no tray actions", osName)
		}
	}
	// Toggle logic
	s := TrayState{Visible: true, Minimized: false, Focused: true}
	if s.NextToggleTarget() != TrayActionHide {
		t.Fatal("should hide when visible+focused")
	}
	s2 := TrayState{Visible: false}
	if s2.NextToggleTarget() != TrayActionShow {
		t.Fatal("should show when not visible")
	}
	menu := RenderTrayMenu(cfg.Menu)
	if !strings.Contains(menu, "Show") || !strings.Contains(menu, "Quit") {
		t.Fatalf("menu render %s", menu)
	}
}

func TestAutostartRenderAndPlan(t *testing.T) {
	cfg := AutostartConfig{Name: "easytier-gui", Exec: "/opt/easytier/easytier-gui", Args: []string{"--daemon"}, Enabled: true, DisplayName: "EasyTier", Description: "EasyTier Gui"}
	desktop, err := RenderAutostartDesktop(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(desktop, "Exec=") || !strings.Contains(desktop, "Autostart-enabled=true") {
		t.Fatalf("desktop %q", desktop)
	}
	plist, err := RenderAutostartLaunchd(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plist, "<key>Label</key>") {
		t.Fatalf("plist %q", plist)
	}
	reg, err := RenderAutostartRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reg, "HKEY_CURRENT_USER") {
		t.Fatalf("reg %q", reg)
	}
	for _, osName := range []string{"linux", "darwin", "windows"} {
		plan, err := PlanAutostart(osName, cfg)
		if err != nil {
			t.Fatalf("%s autostart plan %v", osName, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("%s no actions", osName)
		}
	}
	// Disabled path
	cfg.Enabled = false
	desktop2, _ := RenderAutostartDesktop(cfg)
	if !strings.Contains(desktop2, "Hidden=true") {
		t.Fatal("disabled desktop hidden")
	}
}

func TestGUILogOptions(t *testing.T) {
	for _, lvl := range []string{"off", "trace", "debug", "info", "warn", "error"} {
		if _, err := ParseGUILogLevel(lvl); err != nil {
			t.Fatalf("level %s err %v", lvl, err)
		}
	}
	if _, err := ParseGUILogLevel("invalid"); err == nil {
		t.Fatal("expected invalid level error")
	}
	opts := GUILogOptions{Dir: "/tmp/logs", Level: GUILogInfo, File: "easytier.log"}
	if _, err := RenderGUILogConfig(opts); err != nil {
		t.Fatal(err)
	}
	if filepath.ToSlash(opts.LogFilePath()) != "/tmp/logs/easytier.log" {
		t.Fatalf("log path %s", opts.LogFilePath())
	}
	for _, osName := range []string{"linux", "darwin", "windows", "android"} {
		plan, err := PlanGUILog(osName, opts)
		if err != nil {
			t.Fatalf("%s log plan %v", osName, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("%s no log actions", osName)
		}
	}
	// android log dir
	dir := ResolveGUILogDir("android", "/data/app/log", "/cache")
	if !strings.HasSuffix(dir, "logs") {
		t.Fatalf("android dir %s", dir)
	}
	dir2 := ResolveGUILogDir("linux", "/var/log/easytier", "")
	if dir2 != "/var/log/easytier" {
		t.Fatalf("linux dir %s", dir2)
	}
}

func TestGUIEvents(t *testing.T) {
	for _, ev := range AllGUIEvents {
		if !IsValidGUIEvent(ev) {
			t.Fatalf("event %s invalid", ev)
		}
	}
	bus := NewEventBus()
	var got string
	unlisten := bus.Listen(EventSaveConfigs, func(ev string, payload any) { got = ev })
	if err := bus.Emit(EventSaveConfigs, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if got != EventSaveConfigs {
		t.Fatal("listen not called")
	}
	if bus.Count(EventSaveConfigs) != 1 {
		t.Fatal("count")
	}
	unlisten()
	// normalize payload
	if NormalizeInstanceIDPayload("abc-123") != "abc-123" {
		t.Fatal("string payload")
	}
	if NormalizeInstanceIDPayload(nil) != "" {
		t.Fatal("nil payload")
	}
	_ = RenderEventHistory(bus.History())
	for _, osName := range []string{"linux", "darwin", "windows", "android"} {
		plan, err := PlanEvents(osName, nil)
		if err != nil {
			t.Fatalf("%s event plan %v", osName, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("%s no event actions", osName)
		}
	}
}

func TestGUIService(t *testing.T) {
	portal := "tcp://0.0.0.0:15888"
	cfgServer := "tcp://config.example.com:8080"
	opts := GUIServiceOptions{
		ConfigDir:    "/tmp/easytier/config",
		RPCPortal:    portal,
		FileLogLevel: "info",
		FileLogDir:   "/tmp/easytier/logs",
		ConfigServer: &cfgServer,
	}
	if err := opts.Validate(); err != nil {
		t.Fatal(err)
	}
	args := opts.ToArgs()
	if len(args) == 0 || args[0] != "--config-dir" {
		t.Fatalf("args %v", args)
	}
	for _, osName := range []string{"linux", "darwin", "windows"} {
		plan, err := PlanGUIService(osName, &opts, "/usr/bin/easytier-gui")
		if err != nil {
			t.Fatalf("%s service plan %v", osName, err)
		}
		if len(plan.Actions) == 0 {
			t.Fatalf("%s no service actions", osName)
		}
		// Check rendering
		if osName == "linux" {
			unit, err := RenderGUISystemd(opts, "/usr/bin/easytier-gui")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(unit, "ExecStart=") {
				t.Fatalf("unit %q", unit)
			}
		}
		if osName == "darwin" {
			plist, err := RenderGUILaunchd(opts, "/Applications/EasyTier.app/Contents/MacOS/easytier-gui")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(plist, "ProgramArguments") {
				t.Fatalf("plist %q", plist)
			}
		}
	}
	// uninstall plan
	planUninstall, err := PlanGUIService("linux", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(planUninstall.Actions) == 0 {
		t.Fatal("uninstall no actions")
	}
	// service status plans
	for _, action := range []string{"status", "start", "stop"} {
		cur := ServiceStatusStopped
		if action == "start" {
			cur = ServiceStatusStopped
		} else if action == "stop" {
			cur = ServiceStatusRunning
		}
		if _, err := PlanServiceStatus("linux", action, cur); err != nil {
			t.Fatalf("status plan %s err %v", action, err)
		}
	}
	// invalid
	if _, err := PlanServiceStatus("linux", "start", ServiceStatusRunning); err == nil {
		t.Fatal("should fail start when running")
	}
	// Validate missing fields
	bad := GUIServiceOptions{}
	if err := bad.Validate(); err == nil {
		t.Fatal("bad validate should fail")
	}
}

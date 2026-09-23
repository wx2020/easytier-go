// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"runtime"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/gui"
)

func TestAppLifecycle(t *testing.T) {
	app := NewApp("2.6.4")
	if app.EasytierVersion() != "2.6.4" {
		t.Fatalf("expected version 2.6.4, got %s", app.EasytierVersion())
	}

	if app.GetOSType() != runtime.GOOS {
		t.Fatalf("expected os %s, got %s", runtime.GOOS, app.GetOSType())
	}

	dirs := app.GetDefaultDirs()
	if dirs["config_dir"] == "" || dirs["log_dir"] == "" {
		t.Fatalf("expected non-empty dirs, got %+v", dirs)
	}

	if app.GetServiceStatus() != "NotInstalled" {
		t.Fatalf("expected NotInstalled, got %s", app.GetServiceStatus())
	}

	// Test config lifecycle
	cfg := gui.NetworkConfig{
		InstanceID: "test-node-1",
		RawTOML:    `instance_name = "test-node-1"`,
	}

	if err := app.ValidateConfig(cfg); err != nil {
		t.Fatalf("validate config failed: %v", err)
	}

	if err := app.SaveNetworkConfig(cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}

	got, err := app.GetConfig("test-node-1")
	if err != nil {
		t.Fatalf("get config failed: %v", err)
	}
	if got.InstanceID != "test-node-1" {
		t.Fatalf("expected instance id test-node-1, got %s", got.InstanceID)
	}

	ids := app.ListNetworkInstanceIds()
	if len(ids["all"]) != 1 || ids["all"][0] != "test-node-1" {
		t.Fatalf("expected 1 instance in all, got %+v", ids)
	}

	if err := app.RunNetworkInstance(cfg, false); err != nil {
		t.Fatalf("run network instance failed: %v", err)
	}

	if err := app.UpdateNetworkConfigState("test-node-1", true); err != nil {
		t.Fatalf("update state disabled failed: %v", err)
	}

	if err := app.RemoveNetworkInstance("test-node-1"); err != nil {
		t.Fatalf("remove instance failed: %v", err)
	}
}


// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"strings"
	"testing"
)

// TestDesktopPackagingValidatesFeaturesOnAllTargets mirrors the GUI-02 acceptance:
// Desktop packaging tests validate service, elevation, tray, autostart, log,
// event, and config-source on Windows, macOS, and Linux.
func TestDesktopPackagingValidatesFeaturesOnAllTargets(t *testing.T) {
	for _, osName := range []string{"windows", "darwin", "linux"} {
		t.Run(osName, func(t *testing.T) {
			// Service
			portal := "tcp://127.0.0.1:15888"
			opts := GUIServiceOptions{
				ConfigDir:    "/tmp/easytier/config",
				RPCPortal:    portal,
				FileLogLevel: "info",
				FileLogDir:   "/tmp/easytier/logs",
			}
			svcPlan, err := PlanGUIService(osName, &opts, "/usr/bin/easytier-gui")
			if err != nil {
				t.Fatalf("service plan: %v", err)
			}
			if len(svcPlan.Actions) == 0 {
				t.Fatal("service plan empty")
			}
			// Elevation
			cmd := ElevatedCommand{Program: "/usr/bin/easytier-gui", Args: []string{"--create-tun", "et0"}}
			elevPlan, err := cmd.Plan(osName)
			if err != nil {
				t.Fatalf("elevate plan: %v", err)
			}
			if !elevPlan.Privileged {
				t.Fatal("elevate should be privileged")
			}
			// Tray
			trayCfg := DefaultTrayConfig("2.6.4")
			trayPlan, err := PlanTray(osName, trayCfg)
			if err != nil {
				t.Fatalf("tray plan: %v", err)
			}
			if len(trayPlan.Actions) == 0 {
				t.Fatal("tray plan empty")
			}
			// Autostart
			autoCfg := AutostartConfig{Name: "easytier-gui", Exec: "/usr/bin/easytier-gui", Enabled: true}
			autoPlan, err := PlanAutostart(osName, autoCfg)
			if err != nil {
				t.Fatalf("autostart plan: %v", err)
			}
			if len(autoPlan.Actions) == 0 {
				t.Fatal("autostart plan empty")
			}
			// Log
			logOpts := GUILogOptions{Dir: "/tmp/easytier/logs", Level: GUILogInfo, File: "easytier.log"}
			logPlan, err := PlanGUILog(osName, logOpts)
			if err != nil {
				t.Fatalf("log plan: %v", err)
			}
			if len(logPlan.Actions) == 0 {
				t.Fatal("log plan empty")
			}
			// Events
			evPlan, err := PlanEvents(osName, nil)
			if err != nil {
				t.Fatalf("event plan: %v", err)
			}
			if len(evPlan.Actions) == 0 {
				t.Fatal("event plan empty")
			}
			// Config source
			cs := ParseConfigSource("webhook")
			if cs != ConfigSourceWebhook {
				t.Fatalf("config source parse webhook got %s", cs)
			}
			merged := ConfigSourceWebhook.MergePersisted(ConfigSourceUser)
			if merged != ConfigSourceWebhook {
				t.Fatalf("config source merge expected webhook got %s", merged)
			}
			// Ensure renderers produce expected OS-specific markers
			if osName == "linux" {
				if !containsAny(svcPlan.Warnings, "systemd") && svcPlan.Actions[0].Command[0] != "mkdir" {
					// svcPlan should contain systemd
					found := false
					for _, a := range svcPlan.Actions {
						if len(a.Command) > 0 && (a.Command[0] == "systemctl" || a.Command[0] == "systemd-unit") {
							found = true
						}
					}
					if !found {
						t.Fatal("linux service plan missing systemctl")
					}
				}
			}
			if osName == "darwin" {
				found := false
				for _, a := range svcPlan.Actions {
					if len(a.Command) > 0 && a.Command[0] == "launchctl" {
						found = true
					}
				}
				if !found {
					t.Fatal("darwin service plan missing launchctl")
				}
			}
			if osName == "windows" {
				found := false
				for _, a := range svcPlan.Actions {
					if len(a.Command) > 0 && a.Command[0] == "sc" {
						found = true
					}
				}
				if !found {
					t.Fatal("windows service plan missing sc")
				}
			}
		})
	}
}

func containsAny(list []string, substr string) bool {
	for _, s := range list {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

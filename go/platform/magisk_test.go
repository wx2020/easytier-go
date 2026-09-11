// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"strings"
	"testing"
)

func TestMagiskModuleProp(t *testing.T) {
	m := DefaultMagiskModule()
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	prop, err := m.RenderModuleProp()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"id=easytier_magisk", "name=EasyTier", "version=v2.6.4", "updateJson"} {
		if !strings.Contains(prop, want) {
			t.Fatalf("module.prop missing %q: %q", want, prop)
		}
	}
	bad := DefaultMagiskModule()
	bad.ID = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("expected error for empty ID")
	}
	bad2 := DefaultMagiskModule()
	bad2.Version = ""
	if err := bad2.Validate(); err == nil {
		t.Fatal("expected error for empty version")
	}
}

func TestMagiskBuildAndValidateZip(t *testing.T) {
	m := DefaultMagiskModule()
	data, err := BuildMagiskZip(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty zip")
	}
	if err := ValidateMagiskZip(data, m.ID); err != nil {
		t.Fatal(err)
	}
	// missing file case: validate with wrong ID should fail
	if err := ValidateMagiskZip(data, "nonexistent"); err == nil {
		t.Fatal("expected error for wrong ID")
	}
	if err := ValidateMagiskZip([]byte{}, m.ID); err == nil {
		t.Fatal("expected error for empty zip")
	}
	if err := ValidateMagiskZip([]byte("not a zip"), m.ID); err == nil {
		t.Fatal("expected error for invalid zip")
	}
}

func TestMagiskPlanInstall(t *testing.T) {
	m := DefaultMagiskModule()
	plan, err := PlanMagiskInstall(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected actions")
	}
	foundInstall := false
	foundTUN := false
	for _, a := range plan.Actions {
		if len(a.Command) > 0 && a.Command[0] == "magisk" {
			foundInstall = true
		}
		if len(a.Command) > 0 && a.Command[0] == "sh" {
			joined := strings.Join(a.Command, " ")
			if strings.Contains(joined, "tun") {
				foundTUN = true
			}
		}
	}
	if !foundInstall {
		t.Fatal("expected magisk install action")
	}
	if !foundTUN {
		t.Fatal("expected TUN ensure action")
	}
	bad := DefaultMagiskModule()
	bad.ID = ""
	if _, err := PlanMagiskInstall(bad); err == nil {
		t.Fatal("expected error for invalid module")
	}
}

func TestMagiskUninstallPlan(t *testing.T) {
	plan := PlanMagiskUninstall("easytier_magisk")
	if len(plan.Actions) == 0 {
		t.Fatal("expected actions")
	}
	hasRemove := false
	for _, a := range plan.Actions {
		if len(a.Command) >= 2 && a.Command[0] == "rm" {
			hasRemove = true
		}
	}
	if !hasRemove {
		t.Fatal("expected rm action in uninstall")
	}
}

func TestMagiskScripts(t *testing.T) {
	scripts := MagiskScripts("easytier_magisk")
	for _, need := range []string{"module.prop", "service.sh", "customize.sh", "easytier_core.sh", "hotspot_iprule.sh"} {
		if _, ok := scripts[need]; !ok {
			t.Fatalf("missing script %q", need)
		}
	}
	if !strings.Contains(scripts["service.sh"], "sys.boot_completed") {
		t.Fatalf("service.sh missing boot check")
	}
	if !strings.Contains(scripts["hotspot_iprule.sh"], "ET_NAT") {
		t.Fatalf("hotspot_iprule.sh missing ET_NAT")
	}
}

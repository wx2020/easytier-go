// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package jni

import (
	"strings"
	"testing"
)

func TestABIsContainAllFour(t *testing.T) {
	if len(ABIs) != 4 {
		t.Fatalf("ABIs len = %d, want 4", len(ABIs))
	}
	if len(AllABIs) != 4 {
		t.Fatalf("AllABIs len = %d, want 4", len(AllABIs))
	}
	want := map[string]bool{"arm64-v8a": true, "armeabi-v7a": true, "x86": true, "x86_64": true}
	for _, abi := range ABIs {
		if !want[abi] {
			t.Fatalf("unexpected ABI %q", abi)
		}
		delete(want, abi)
	}
	if len(want) != 0 {
		t.Fatalf("missing ABIs: %v", want)
	}
	for _, def := range AllABIs {
		if !wantContains(ABIs, def.AndroidABI) {
			t.Fatalf("AllABIs %q not in ABIs", def.AndroidABI)
		}
		if err := ValidateABIs([]string{def.AndroidABI}); err != nil {
			t.Fatalf("ValidateABIs(%q) failed: %v", def.AndroidABI, err)
		}
		if def.GoOS != "android" {
			t.Fatalf("GoOS for %q = %q, want android", def.AndroidABI, def.GoOS)
		}
	}
}

func wantContains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func TestABIByName(t *testing.T) {
	def, err := ABIByName("arm64-v8a")
	if err != nil {
		t.Fatal(err)
	}
	if def.RustTarget != "aarch64-linux-android" {
		t.Fatalf("RustTarget = %q, want aarch64-linux-android", def.RustTarget)
	}
	if def.GoArch != "arm64" {
		t.Fatalf("GoArch = %q, want arm64", def.GoArch)
	}
	if _, err := ABIByName("invalid"); err == nil {
		t.Fatal("expected error for invalid ABI")
	}
}

func TestValidateABIsDuplicate(t *testing.T) {
	if err := ValidateABIs([]string{"arm64-v8a", "arm64-v8a"}); err == nil {
		t.Fatal("expected duplicate error")
	}
	if err := ValidateABIs([]string{"x86", "invalid-abi"}); err == nil {
		t.Fatal("expected unknown ABI error")
	}
}

func TestBuildEnv(t *testing.T) {
	def, _ := ABIByName("arm64-v8a")
	env := BuildEnv(def, "/opt/android-ndk")
	if env["GOOS"] != "android" || env["GOARCH"] != "arm64" {
		t.Fatalf("env GOOS/GOARCH = %q/%q", env["GOOS"], env["GOARCH"])
	}
	if !strings.Contains(env["CC"], "aarch64") {
		t.Fatalf("CC missing aarch64: %q", env["CC"])
	}
	def2, _ := ABIByName("armeabi-v7a")
	env2 := BuildEnv(def2, "/opt/ndk")
	if !strings.Contains(env2["CC"], "armv7a") {
		t.Fatalf("CC for armeabi-v7a should contain armv7a: %q", env2["CC"])
	}
}

func TestPlanBuildAllABIs(t *testing.T) {
	plan, err := PlanBuildAllABIs("/opt/ndk")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 4 {
		t.Fatalf("actions = %d, want 4", len(plan.Actions))
	}
	for _, a := range plan.Actions {
		if !IsSupportedABI(a.ABI) {
			t.Fatalf("unsupported ABI in plan: %q", a.ABI)
		}
		if len(a.Commands) == 0 || a.Commands[0][0] != "go" {
			t.Fatalf("unexpected command for %q: %v", a.ABI, a.Commands)
		}
	}
	plan2, err := PlanBuildAllABIs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan2.Warnings) == 0 {
		t.Fatal("expected warning when NDK root empty")
	}
}

func TestLibraryNameAndOutputDir(t *testing.T) {
	if LibraryName("arm64-v8a") != "libeasytier_jni.so" {
		t.Fatalf("LibraryName wrong")
	}
	if OutputDir("x86") != "src/main/jniLibs/x86" {
		t.Fatalf("OutputDir wrong: %q", OutputDir("x86"))
	}
}

func TestCGOEnabledFlag(t *testing.T) {
	_ = CGOEnabled() // just ensure it compiles on both cgo and non-cgo
}

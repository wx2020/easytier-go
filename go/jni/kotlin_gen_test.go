// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package jni

import (
	"strings"
	"testing"
)

func TestKotlinAPIComplete(t *testing.T) {
	if err := ValidateKotlinAPI(); err != nil {
		t.Fatal(err)
	}
	files := GeneratedKotlinAPI()
	if len(files) != 3 {
		t.Fatalf("files = %d, want 3", len(files))
	}
	wantPaths := map[string]bool{
		"com/easytier/jni/EasyTierJNI.kt":        true,
		"com/easytier/jni/EasyTierManager.kt":    true,
		"com/easytier/jni/EasyTierVpnService.kt": true,
	}
	for _, f := range files {
		if !wantPaths[f.Path] {
			t.Fatalf("unexpected path %q", f.Path)
		}
		if f.Package != "com.easytier.jni" {
			t.Fatalf("package %q, want com.easytier.jni", f.Package)
		}
		if f.Content == "" {
			t.Fatalf("empty content for %q", f.Path)
		}
	}
	jniContent := KotlinEasyTierJNI()
	for _, sym := range []string{"setTunFd", "parseConfig", "runNetworkInstance", "retainNetworkInstance", "collectNetworkInfos", "getLastError", "stopAllInstances", "retainSingleInstance"} {
		if !strings.Contains(jniContent, sym) {
			t.Fatalf("EasyTierJNI.kt missing %q", sym)
		}
	}
	mgr := KotlinEasyTierManager()
	if !strings.Contains(mgr, "EasyTierManager") || !strings.Contains(mgr, "VpnService") {
		t.Fatalf("Manager missing VpnService logic")
	}
	vpn := KotlinEasyTierVpnService()
	if !strings.Contains(vpn, "VpnService") || !strings.Contains(vpn, "setTunFd") || !strings.Contains(vpn, "Builder") {
		t.Fatalf("VpnService missing required calls")
	}
}

func TestKotlinAPIOriginalStub(t *testing.T) {
	api := KotlinAPI()
	if !strings.Contains(api, "EasyTierJNI") {
		t.Fatalf("KotlinAPI() missing EasyTierJNI")
	}
	if !strings.Contains(api, "setTunFd") {
		t.Fatalf("KotlinAPI() missing setTunFd")
	}
}

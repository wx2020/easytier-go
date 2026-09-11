// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package jni

import (
	"encoding/json"
	"testing"
)

// TestNTV02_NTV03_Integration verifies JNI + VpnService one-active lifecycle together (NTV-02 + NTV-03).
func TestNTV02_NTV03_Integration(t *testing.T) {
	mgr := NewManager()
	vpn := NewVpnServiceManager()
	vpn.Reset()

	good := "instance_name = \"int-test\"\n[network_identity]\nnetwork_name = \"net-int\"\n"
	if err := mgr.ParseConfig(good); err != nil {
		t.Fatal(err)
	}
	if err := mgr.RunNetworkInstance(good); err != nil {
		t.Fatal(err)
	}
	// VpnService permission + establish
	if !vpn.Prepare() {
		t.Fatal("prepare")
	}
	cfg := VpnServiceConfig{
		InstanceName: "int-test",
		IPv4:         "10.144.144.5/24",
		ProxyCIDRs:   []string{"10.10.0.0/16"},
		MTU:          1380,
	}
	fd, err := vpn.Establish(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Inject FD via JNI
	if err := mgr.SetTunFd("int-test", fd); err != nil {
		t.Fatal(err)
	}
	// Collect should show tun_fd
	jsonStr, err := mgr.CollectNetworkInfos()
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &out); err != nil {
		t.Fatal(err)
	}
	info, ok := out["int-test"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing int-test in %s", jsonStr)
	}
	if int(info["tun_fd"].(float64)) != fd {
		t.Fatalf("tun_fd %v, want %d", info["tun_fd"], fd)
	}
	// Second instance should be blocked at both layers
	good2 := "instance_name = \"int-test2\"\n[network_identity]\nnetwork_name = \"net-int2\"\n"
	if err := mgr.RunNetworkInstance(good2); err != nil {
		t.Fatal(err)
	}
	cfg2 := VpnServiceConfig{InstanceName: "int-test2", IPv4: "10.144.144.6/24", MTU: 1380}
	if _, err := vpn.Establish(cfg2); err == nil {
		t.Fatal("expected VpnService one-active error")
	}
	if err := mgr.SetTunFd("int-test2", 99); err == nil {
		t.Fatal("expected JNI one-active error")
	}
	// Cleanup
	_ = vpn.Close()
	if err := mgr.RetainNetworkInstance(nil); err != nil {
		t.Fatal(err)
	}
	jsonStr, _ = mgr.CollectNetworkInfos()
	var out2 map[string]interface{}
	_ = json.Unmarshal([]byte(jsonStr), &out2)
	if len(out2) != 0 {
		t.Fatalf("expected empty after retain nil, got %v", out2)
	}
	vpn.Reset()
}

func TestNTV02_ABIBuildMatrix(t *testing.T) {
	plan, err := PlanBuildAllABIs("/opt/ndk")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 4 {
		t.Fatalf("want  4, got %d", len(plan.Actions))
	}
	for _, abi := range ABIs {
		if !IsSupportedABI(abi) {
			t.Fatalf("ABI %q not supported", abi)
		}
	}
	if err := ValidateKotlinAPI(); err != nil {
		t.Fatal(err)
	}
	files := GeneratedKotlinAPI()
	if len(files) != 3 {
		t.Fatalf("kotlin files %d", len(files))
	}
}

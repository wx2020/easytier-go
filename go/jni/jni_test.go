// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package jni

import (
	"encoding/json"
	"testing"
)

func TestJNIParseAndRun(t *testing.T) {
	m := NewManager()
	good := "instance_name = \"jni-test\"\n[network_identity]\nnetwork_name = \"net-jni\"\n"
	if err := m.ParseConfig(good); err != nil {
		t.Fatal(err)
	}
	if err := m.RunNetworkInstance(good); err != nil {
		t.Fatal(err)
	}
	// duplicate
	if err := m.RunNetworkInstance(good); err == nil {
		t.Fatal("expected duplicate error")
	}
	// parse bad
	bad := "ipv4 = \"bad\"\n"
	if err := m.ParseConfig(bad); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestJNICollectAndTunFD(t *testing.T) {
	m := NewManager()
	cfg := "instance_name = \"tun-jni\"\n[network_identity]\nnetwork_name = \"net-tun\"\n"
	if err := m.RunNetworkInstance(cfg); err != nil {
		t.Fatal(err)
	}
	if err := m.SetTunFd("tun-jni", 42); err != nil {
		t.Fatal(err)
	}
	// second instance
	cfg2 := "instance_name = \"tun-jni2\"\n[network_identity]\nnetwork_name = \"net-tun2\"\n"
	if err := m.RunNetworkInstance(cfg2); err != nil {
		t.Fatal(err)
	}
	// one-active should fail
	if err := m.SetTunFd("tun-jni2", 43); err == nil {
		t.Fatal("expected one-active error")
	}
	jsonStr, err := m.CollectNetworkInfos()
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["tun-jni"]; !ok {
		t.Fatalf("missing tun-jni in %s", jsonStr)
	}
	// retain
	if err := m.RetainNetworkInstance([]string{"tun-jni"}); err != nil {
		t.Fatal(err)
	}
	jsonStr, _ = m.CollectNetworkInfos()
	var out2 map[string]interface{}
	_ = json.Unmarshal([]byte(jsonStr), &out2)
	if len(out2) != 1 {
		t.Fatalf("retain left %d", len(out2))
	}
	m.RetainNetworkInstance(nil)
	jsonStr, _ = m.CollectNetworkInfos()
	var out3 map[string]interface{}
	_ = json.Unmarshal([]byte(jsonStr), &out3)
	if len(out3) != 0 {
		t.Fatalf("expected empty after clear, got %v", out3)
	}
}

func TestKotlinAPI(t *testing.T) {
	api := KotlinAPI()
	if api == "" {
		t.Fatal("kotlin api empty")
	}
}

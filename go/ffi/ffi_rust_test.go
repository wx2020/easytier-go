//go:build cgo

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRustParseConfigLogic(t *testing.T) {
	good := `listeners = ["127.0.0.1:0"]
instance_name = "rust-parse-good"
[network_identity]
network_name = "net-good"
`
	if _, err := parseConfig(good); err != nil {
		t.Fatalf("parse good failed: %v", err)
	}
	bad := `ipv4 = "not-an-ip"`
	if _, err := parseConfig(bad); err == nil {
		t.Fatal("parse bad should fail")
	}
	// Test global error via rust wrapper helpers
	clearGlobalError()
	setGlobalError("test error")
	if got := getGlobalError(); got != "test error" {
		t.Fatalf("global error = %q", got)
	}
	clearGlobalError()
	if got := getGlobalError(); got != "" {
		t.Fatalf("clear failed, got %q", got)
	}
}

func TestRustRunCollectRetainLogic(t *testing.T) {
	// Clean slate
	clearGlobalError()
	// Clear registry
	globalRegistry.Lock()
	for k := range globalRegistry.byName {
		delete(globalRegistry.byName, k)
	}
	for k := range globalRegistry.byID {
		delete(globalRegistry.byID, k)
	}
	globalRegistry.Unlock()
	instances.Lock()
	for k := range instances.items {
		delete(instances.items, k)
	}
	instances.Unlock()
	defer func() {
		globalRegistry.Lock()
		for k := range globalRegistry.byName {
			delete(globalRegistry.byName, k)
		}
		for k := range globalRegistry.byID {
			delete(globalRegistry.byID, k)
		}
		globalRegistry.Unlock()
	}()

	cfg1 := `listeners = ["127.0.0.1:0"]
instance_name = "rust-test-1"
[network_identity]
network_name = "net1"
`
	cfg2 := `listeners = ["127.0.0.1:0"]
instance_name = "rust-test-2"
[network_identity]
network_name = "net2"
`
	// Simulate run_network_instance
	run := func(toml string) error {
		cfg, err := parseConfig(toml)
		if err != nil {
			return err
		}
		name := cfg.InstanceName
		if name == "" {
			name = cfg.NetworkIdentity.NetworkName
		}
		globalRegistry.Lock()
		if _, exists := globalRegistry.byName[name]; exists {
			globalRegistry.Unlock()
			return errAlreadyExists
		}
		inst := &ffiInstance{cfg: cfg, state: "created", tunFD: -1}
		globalRegistry.byName[name] = inst
		globalRegistry.Unlock()
		instances.Lock()
		h := instances.next
		instances.next++
		instances.items[h] = inst
		instances.Unlock()
		globalRegistry.Lock()
		globalRegistry.byID[name] = h
		globalRegistry.Unlock()
		if code := startInstance(inst); code != statusOK {
			globalRegistry.Lock()
			delete(globalRegistry.byName, name)
			delete(globalRegistry.byID, name)
			globalRegistry.Unlock()
			instances.Lock()
			delete(instances.items, h)
			instances.Unlock()
			return errStartFailed
		}
		return nil
	}

	if err := run(cfg1); err != nil {
		t.Fatalf("run 1 failed: %v", err)
	}
	if err := run(cfg2); err != nil {
		t.Fatalf("run 2 failed: %v", err)
	}
	if err := run(cfg1); err == nil {
		t.Fatal("duplicate should fail")
	}
	// collect via helper
	collect := func(max int) ([]struct{ Key, Value string }, int) {
		globalRegistry.RLock()
		names := make([]string, 0, len(globalRegistry.byName))
		for n := range globalRegistry.byName {
			names = append(names, n)
		}
		globalRegistry.RUnlock()
		count := 0
		var pairs []struct{ Key, Value string }
		for _, n := range names {
			if count >= max {
				break
			}
			globalRegistry.RLock()
			inst := globalRegistry.byName[n]
			globalRegistry.RUnlock()
			inst.mu.Lock()
			info := map[string]interface{}{
				"instance_name": n,
				"state":         inst.state,
				"running":       inst.state == "running",
				"address":       inst.address,
				"tun_fd":        inst.tunFD,
			}
			inst.mu.Unlock()
			data, _ := json.Marshal(info)
			pairs = append(pairs, struct{ Key, Value string }{Key: n, Value: string(data)})
			count++
		}
		return pairs, count
	}
	pairs, n := collect(10)
	if n != 2 {
		t.Fatalf("collect n=%d want 2", n)
	}
	found := map[string]bool{}
	for _, p := range pairs {
		found[p.Key] = true
		if !strings.Contains(p.Value, "\"state\"") {
			t.Fatalf("missing state in %q", p.Value)
		}
	}
	if !found["rust-test-1"] || !found["rust-test-2"] {
		t.Fatalf("found=%v", found)
	}
	// retain only one (simulate retain)
	retain := func(keep []string) {
		keepSet := map[string]bool{}
		for _, k := range keep {
			keepSet[k] = true
		}
		var toRemove []string
		globalRegistry.RLock()
		for name := range globalRegistry.byName {
			if len(keep) == 0 || !keepSet[name] {
				toRemove = append(toRemove, name)
			} else if len(keep) > 0 && !keepSet[name] {
				toRemove = append(toRemove, name)
			}
		}
		globalRegistry.RUnlock()
		for _, name := range toRemove {
			globalRegistry.RLock()
			inst := globalRegistry.byName[name]
			h := globalRegistry.byID[name]
			globalRegistry.RUnlock()
			_ = stopInstance(inst)
			inst.mu.Lock()
			inst.released = true
			inst.mu.Unlock()
			globalRegistry.Lock()
			delete(globalRegistry.byName, name)
			delete(globalRegistry.byID, name)
			globalRegistry.Unlock()
			instances.Lock()
			delete(instances.items, h)
			instances.Unlock()
		}
	}
	retain([]string{"rust-test-1"})
	_, n = collect(10)
	if n != 1 {
		t.Fatalf("after retain n=%d want 1", n)
	}
	retain([]string{})
	_, n = collect(10)
	if n != 0 {
		t.Fatalf("after clear n=%d want 0", n)
	}
}

func TestRustSetTunFDLogic(t *testing.T) {
	// Clean
	globalRegistry.Lock()
	for k := range globalRegistry.byName {
		delete(globalRegistry.byName, k)
	}
	for k := range globalRegistry.byID {
		delete(globalRegistry.byID, k)
	}
	globalRegistry.Unlock()
	defer func() {
		globalRegistry.Lock()
		for k := range globalRegistry.byName {
			delete(globalRegistry.byName, k)
		}
		for k := range globalRegistry.byID {
			delete(globalRegistry.byID, k)
		}
		globalRegistry.Unlock()
	}()
	cfg := `listeners = ["127.0.0.1:0"]
instance_name = "rust-tun-test"
[network_identity]
network_name = "net-tun"
`
	c, err := parseConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	inst := &ffiInstance{cfg: c, state: "created", tunFD: -1}
	globalRegistry.Lock()
	globalRegistry.byName["rust-tun-test"] = inst
	globalRegistry.Unlock()
	// invalid fd simulation
	setTun := func(name string, fd int) error {
		globalRegistry.RLock()
		inst, ok := globalRegistry.byName[name]
		globalRegistry.RUnlock()
		if !ok {
			return errNotFound
		}
		if fd < 0 {
			return errInvalidFD
		}
		inst.mu.Lock()
		inst.tunFD = fd
		inst.mu.Unlock()
		return nil
	}
	if err := setTun("rust-tun-test", -1); err == nil {
		t.Fatal("should fail for -1")
	}
	if err := setTun("unknown", 42); err == nil {
		t.Fatal("should fail for unknown")
	}
	if err := setTun("rust-tun-test", 42); err != nil {
		t.Fatal(err)
	}
	inst.mu.Lock()
	if inst.tunFD != 42 {
		t.Fatalf("tunFD=%d want 42", inst.tunFD)
	}
	inst.mu.Unlock()
}

var (
	errAlreadyExists = errString("already exists")
	errStartFailed   = errString("start failed")
	errNotFound      = errString("not found")
	errInvalidFD     = errString("invalid fd")
)

type errString string

func (e errString) Error() string { return string(e) }

//go:build cgo

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const testTOML = `listeners = ["127.0.0.1:0"]

[network_identity]
network_name = "ffi-test"
network_secret = "secret"
`

func TestLifecycleAndPerHandleState(t *testing.T) {
	firstConfig := strings.Replace(testTOML, "ffi-test", "first", 1)
	secondConfig := strings.Replace(testTOML, "ffi-test", "second", 1)
	first, err := createForTest(firstConfig)
	if err != nil {
		t.Fatal(err)
	}
	second, err := createForTest(secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseForTest(t, first)
	defer releaseForTest(t, second)

	if got := startInstance(first); got != statusOK {
		t.Fatalf("first start status = %d", got)
	}
	if got := startInstance(second); got != statusOK {
		t.Fatalf("second start status = %d", got)
	}

	first.mu.Lock()
	firstAddress := first.address
	first.mu.Unlock()
	second.mu.Lock()
	secondAddress := second.address
	second.mu.Unlock()
	if firstAddress == "" || secondAddress == "" {
		t.Fatalf("listener addresses = %q, %q", firstAddress, secondAddress)
	}
	if got := stopInstance(first); got != statusOK {
		t.Fatalf("first stop status = %d", got)
	}
	second.mu.Lock()
	secondState := second.state
	second.mu.Unlock()
	if secondState != "running" {
		t.Fatalf("second state = %q, want running", secondState)
	}
}

func TestInvalidConfigurationAndLastError(t *testing.T) {
	if _, err := createForTest("ipv4 = \"not-an-ip\"\n"); err == nil {
		t.Fatal("invalid configuration was accepted")
	}

	instance, err := createForTest(strings.Replace(testTOML, "listeners = [\"127.0.0.1:0\"]", "listeners = []", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer releaseForTest(t, instance)
	if got := startInstance(instance); got != statusConfig {
		t.Fatalf("start status = %d, want config error", got)
	}
	instance.mu.Lock()
	lastError := instance.lastError
	instance.mu.Unlock()
	if !strings.Contains(lastError, "listener") {
		t.Fatalf("last error = %q", lastError)
	}
}

func TestStatusJSON(t *testing.T) {
	instance, err := createForTest(testTOML)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseForTest(t, instance)
	instance.mu.Lock()
	status := struct {
		State   string `json:"state"`
		Running bool   `json:"running"`
	}{}
	statusData, marshalErr := json.Marshal(struct {
		State   string `json:"state"`
		Running bool   `json:"running"`
	}{instance.state, instance.state == "running"})
	instance.mu.Unlock()
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if err := json.Unmarshal(statusData, &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "created" || status.Running {
		t.Fatalf("status = %#v", status)
	}
}

func createForTest(text string) (*ffiInstance, error) {
	cfg, err := parseConfig(text)
	if err != nil {
		return nil, err
	}
	return &ffiInstance{cfg: cfg, state: "created"}, nil
}

func releaseForTest(t *testing.T, instance *ffiInstance) {
	t.Helper()
	if got := stopInstance(instance); got != statusOK {
		t.Errorf("release stop status = %d", got)
	}
}

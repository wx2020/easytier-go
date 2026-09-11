// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package jni implements the Android JNI bindings and Kotlin API (NTV-02).
//
// It corresponds to the Rust crate `easytier-contrib/easytier-android-jni`
// and the Android ABIs arm64-v8a, armeabi-v7a, x86, x86_64. This implementation
// provides a Go-level manager that mirrors the Rust JNI lifecycle (one-active-TUN,
// TOML lifecycle, JSON status) and can be exercised in unit tests via a dry-run
// planner; the actual JNI C bridge (Java_com_easytier_jni_EasyTierJNI_*) is
// conditionally built with cgo when targeting Android.
package jni

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	ModuleName = "github.com/EasyTier/EasyTier/go/jni"
	Version    = "2.6.4"
)

// ABI lists the Android ABIs shipped by the Rust reference.
var ABIs = []string{"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}

var (
	ErrInvalidConfig = errors.New("invalid JNI configuration")
	ErrAlreadyExists = errors.New("instance already exists")
	ErrNotFound      = errors.New("instance not found")
	ErrOneActiveTUN  = errors.New("Android VpnService allows only one active TUN")
)

// Instance holds per-network state managed via JNI.
type Instance struct {
	Name   string
	TOML   string
	State  string
	TunFD  int
	Config map[string]interface{}
}

// Manager is the Go-side counterpart of the Rust global INSTANCE_NAME_ID_MAP.
// It tracks instances by name and enforces one-active-TUN.
type Manager struct {
	mu        sync.RWMutex
	instances map[string]*Instance
	lastError string
	activeTun string // name of instance holding the active TUN FD, if any
}

func NewManager() *Manager {
	return &Manager{instances: make(map[string]*Instance)}
}

var DefaultManager = NewManager()

// Config is a placeholder for JNI instance configuration (TOML).
type Config struct {
	TOML string
}

// Handle represents a native instance handle (mirrors FFI handle).
type Handle uint64

// New creates a placeholder Instance (legacy API).
func New(cfg Config) *Instance {
	return &Instance{TOML: cfg.TOML, State: "created", TunFD: -1}
}

// Version returns the module version.
func (i *Instance) Version() string { return Version }

// ParseConfig validates TOML configuration (minimal check for network_name).
func (m *Manager) ParseConfig(toml string) error {
	if strings.TrimSpace(toml) == "" {
		m.setError("parse_config: empty config")
		return ErrInvalidConfig
	}
	if !strings.Contains(toml, "network_name") {
		m.setError("parse_config: missing network_name")
		return fmt.Errorf("%w: network_name is required", ErrInvalidConfig)
	}
	m.clearError()
	return nil
}

// RunNetworkInstance parses TOML and starts an instance.
func (m *Manager) RunNetworkInstance(toml string) error {
	if err := m.ParseConfig(toml); err != nil {
		return err
	}
	name := extractInstanceName(toml)
	if name == "" {
		name = extractNetworkName(toml)
		if name == "" {
			name = "default"
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.instances[name]; exists {
		m.setErrorLocked("instance already exists")
		return ErrAlreadyExists
	}
	m.instances[name] = &Instance{Name: name, TOML: toml, State: "running", TunFD: -1}
	m.clearErrorLocked()
	return nil
}

// SetTunFd injects a VpnService FD for the named instance.
func (m *Manager) SetTunFd(instName string, fd int) error {
	if fd < 0 {
		m.setError(fmt.Sprintf("set_tun_fd: invalid fd %d", fd))
		return fmt.Errorf("%w: %d", ErrInvalidConfig, fd)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.instances[instName]
	if !ok {
		m.setErrorLocked(fmt.Sprintf("set_tun_fd: instance %q not found", instName))
		return ErrNotFound
	}
	if m.activeTun != "" && m.activeTun != instName {
		m.setErrorLocked("one-active-TUN policy violated")
		return ErrOneActiveTUN
	}
	inst.TunFD = fd
	m.activeTun = instName
	m.clearErrorLocked()
	return nil
}

// RetainNetworkInstance keeps only named instances, stopping others.
func (m *Manager) RetainNetworkInstance(names []string) error {
	keep := make(map[string]bool, len(names))
	for _, n := range names {
		keep[n] = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, inst := range m.instances {
		if len(names) == 0 || !keep[name] {
			_ = inst
			delete(m.instances, name)
			if m.activeTun == name {
				m.activeTun = ""
			}
		}
	}
	m.clearErrorLocked()
	return nil
}

// CollectNetworkInfos returns JSON status for all instances (value is JSON object).
func (m *Manager) CollectNetworkInfos() (string, error) {
	m.mu.RLock()
	out := make(map[string]interface{})
	for name, inst := range m.instances {
		info := map[string]interface{}{
			"instance_name": name,
			"state":         inst.State,
			"running":       inst.State == "running",
			"tun_fd":        inst.TunFD,
		}
		out[name] = info
	}
	m.mu.RUnlock()
	data, err := json.Marshal(out)
	if err != nil {
		m.setError(fmt.Sprintf("collect: %v", err))
		return "", err
	}
	m.clearError()
	return string(data), nil
}

// GetLastError returns the last global error.
func (m *Manager) GetLastError() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastError
}

func (m *Manager) setError(msg string) {
	m.mu.Lock()
	m.lastError = msg
	m.mu.Unlock()
}
func (m *Manager) setErrorLocked(msg string) { m.lastError = msg }
func (m *Manager) clearError() {
	m.mu.Lock()
	m.lastError = ""
	m.mu.Unlock()
}
func (m *Manager) clearErrorLocked() { m.lastError = "" }

// Global wrappers matching Rust JNI C API (for tests without actual JNI).

func SetTunFd(instName string, fd int) int {
	if err := DefaultManager.SetTunFd(instName, fd); err != nil {
		return -1
	}
	return 0
}
func ParseConfig(toml string) int {
	if err := DefaultManager.ParseConfig(toml); err != nil {
		return -1
	}
	return 0
}
func RunNetworkInstance(toml string) int {
	if err := DefaultManager.RunNetworkInstance(toml); err != nil {
		return -1
	}
	return 0
}
func RetainNetworkInstance(names []string) int {
	if err := DefaultManager.RetainNetworkInstance(names); err != nil {
		return -1
	}
	return 0
}
func CollectNetworkInfos() string {
	s, _ := DefaultManager.CollectNetworkInfos()
	return s
}
func GetLastError() string { return DefaultManager.GetLastError() }

func extractInstanceName(toml string) string {
	// Very small TOML extractor for instance_name = "value"
	for _, line := range strings.Split(toml, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "instance_name") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				v := strings.TrimSpace(parts[1])
				v = strings.Trim(v, "\"'")
				return v
			}
		}
	}
	return ""
}
func extractNetworkName(toml string) string {
	for _, line := range strings.Split(toml, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "network_name") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				v := strings.TrimSpace(parts[1])
				v = strings.Trim(v, "\"'")
				return v
			}
		}
	}
	return ""
}

// KotlinAPI returns a stub of the generated Kotlin API surface for the JNI module.
func KotlinAPI() string {
	return `package com.easytier.jni
object EasyTierJNI {
    external fun setTunFd(instName: String, fd: Int): Int
    external fun parseConfig(config: String): Int
    external fun runNetworkInstance(config: String): Int
    external fun retainNetworkInstance(instanceNames: Array<String>?): Int
    external fun collectNetworkInfos(): String?
    external fun getLastError(): String?
}`
}

//go:build cgo

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    const char* key;
    const char* value;
} KeyValuePair;
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/core"
	"github.com/pelletier/go-toml/v2"
)

const (
	statusOK              = 0
	statusInvalidArgument = 1
	statusInvalidHandle   = 2
	statusInvalidState    = 3
	statusConfig          = 4
	statusRuntime         = 5
)

type ffiInstance struct {
	mu sync.Mutex

	cfg       config.Config
	node      *core.Node
	serveDone chan struct{}
	serveErr  error
	state     string
	address   string
	lastError string
	released  bool
	tunFD     int
	cancel    context.CancelFunc
}

var instances = struct {
	sync.RWMutex
	items map[uint64]*ffiInstance
	next  uint64
}{items: make(map[uint64]*ffiInstance), next: 1}

// Rust-compatible global registry (instance name -> instance)
var globalRegistry = struct {
	sync.RWMutex
	byName map[string]*ffiInstance
	byID   map[string]uint64 // instance_name -> handle for internal tracking
}{byName: make(map[string]*ffiInstance), byID: make(map[string]uint64)}

// globalError mirrors Rust's ERROR_MSG.
var globalError = struct {
	sync.Mutex
	msg string
}{}

func setGlobalError(msg string) {
	globalError.Lock()
	globalError.msg = msg
	globalError.Unlock()
}

func getGlobalError() string {
	globalError.Lock()
	defer globalError.Unlock()
	return globalError.msg
}

func clearGlobalError() {
	globalError.Lock()
	globalError.msg = ""
	globalError.Unlock()
}

// main makes this package usable with -buildmode=c-shared and -buildmode=exe.
func main() {}

//
// Versioned handle-based API (v1) - existing, preserved for smoke_test.c
//

//export easytier_ffi_v1_create
func easytier_ffi_v1_create(tomlText *C.char, outHandle *C.uint64_t) C.int32_t {
	if tomlText == nil || outHandle == nil {
		return C.int32_t(statusInvalidArgument)
	}
	*outHandle = 0

	cfg, err := parseConfig(C.GoString(tomlText))
	if err != nil {
		return C.int32_t(statusConfig)
	}
	instance := &ffiInstance{cfg: cfg, state: "created", tunFD: -1}

	instances.Lock()
	handle := instances.next
	instances.next++
	instances.items[handle] = instance
	instances.Unlock()
	*outHandle = C.uint64_t(handle)
	return C.int32_t(statusOK)
}

//export easytier_ffi_v1_release
func easytier_ffi_v1_release(handle C.uint64_t) C.int32_t {
	instance, ok := lookupInstance(uint64(handle))
	if !ok {
		return C.int32_t(statusInvalidHandle)
	}
	instance.mu.Lock()
	if instance.released {
		instance.mu.Unlock()
		return C.int32_t(statusInvalidHandle)
	}
	instance.released = true
	instance.mu.Unlock()
	if code := stopInstance(instance); code != statusOK {
		instance.mu.Lock()
		instance.released = false
		instance.mu.Unlock()
		return C.int32_t(code)
	}

	instances.Lock()
	if current, exists := instances.items[uint64(handle)]; !exists || current != instance {
		instances.Unlock()
		return C.int32_t(statusInvalidHandle)
	}
	delete(instances.items, uint64(handle))
	instances.Unlock()
	return C.int32_t(statusOK)
}

//export easytier_ffi_v1_start
func easytier_ffi_v1_start(handle C.uint64_t) C.int32_t {
	instance, ok := lookupInstance(uint64(handle))
	if !ok {
		return C.int32_t(statusInvalidHandle)
	}
	return C.int32_t(startInstance(instance))
}

//export easytier_ffi_v1_stop
func easytier_ffi_v1_stop(handle C.uint64_t) C.int32_t {
	instance, ok := lookupInstance(uint64(handle))
	if !ok {
		return C.int32_t(statusInvalidHandle)
	}
	return C.int32_t(stopInstance(instance))
}

//export easytier_ffi_v1_status_json
func easytier_ffi_v1_status_json(handle C.uint64_t, outString **C.char) C.int32_t {
	if outString == nil {
		return C.int32_t(statusInvalidArgument)
	}
	*outString = nil
	instance, ok := lookupInstance(uint64(handle))
	if !ok {
		return C.int32_t(statusInvalidHandle)
	}

	instance.mu.Lock()
	status := struct {
		State     string `json:"state"`
		Running   bool   `json:"running"`
		Address   string `json:"address,omitempty"`
		LastError string `json:"last_error,omitempty"`
		TunFD     int    `json:"tun_fd,omitempty"`
	}{
		State:     instance.state,
		Running:   instance.state == "running",
		Address:   instance.address,
		LastError: instance.lastError,
		TunFD:     instance.tunFD,
	}
	instance.mu.Unlock()

	data, err := json.Marshal(status)
	if err != nil {
		return C.int32_t(statusRuntime)
	}
	*outString = C.CString(string(data))
	return C.int32_t(statusOK)
}

//export easytier_ffi_v1_last_error
func easytier_ffi_v1_last_error(handle C.uint64_t, outString **C.char) C.int32_t {
	if outString == nil {
		return C.int32_t(statusInvalidArgument)
	}
	*outString = nil
	instance, ok := lookupInstance(uint64(handle))
	if !ok {
		return C.int32_t(statusInvalidHandle)
	}

	instance.mu.Lock()
	errorText := instance.lastError
	instance.mu.Unlock()
	*outString = C.CString(errorText)
	return C.int32_t(statusOK)
}

//export easytier_ffi_v1_free_string
func easytier_ffi_v1_free_string(value *C.char) {
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}

//
// Rust-compatible C ABI (NTV-01): matches easytier-contrib/easytier-ffi/src/lib.rs
// Ownership: strings returned via get_error_msg and collect_network_infos must be
// released with free_string. All inputs are borrowed NUL-terminated UTF-8.
// Cancellation: retain_network_instance with empty list stops all; individual
// stop via retain with subset. Error handling via global error buffer.
//

//export set_tun_fd
func set_tun_fd(instName *C.char, fd C.int) C.int32_t {
	if instName == nil {
		setGlobalError("set_tun_fd: inst_name is null")
		return C.int32_t(-1)
	}
	name := C.GoString(instName)
	if name == "" {
		setGlobalError("set_tun_fd: instance name is empty")
		return C.int32_t(-1)
	}
	if fd < 0 {
		setGlobalError(fmt.Sprintf("set_tun_fd: invalid fd %d", int(fd)))
		return C.int32_t(-1)
	}
	globalRegistry.RLock()
	inst, ok := globalRegistry.byName[name]
	globalRegistry.RUnlock()
	if !ok {
		setGlobalError(fmt.Sprintf("set_tun_fd: instance %q not found", name))
		return C.int32_t(-1)
	}
	inst.mu.Lock()
	if inst.released {
		inst.mu.Unlock()
		setGlobalError(fmt.Sprintf("set_tun_fd: instance %q already released", name))
		return C.int32_t(-1)
	}
	inst.tunFD = int(fd)
	inst.mu.Unlock()
	clearGlobalError()
	return C.int32_t(0)
}

//export get_error_msg
func get_error_msg(out **C.char) {
	if out == nil {
		return
	}
	msg := getGlobalError()
	if msg == "" {
		*out = nil
		return
	}
	*out = C.CString(msg)
}

//export free_string
func free_string(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

//export parse_config
func parse_config(cfgStr *C.char) C.int32_t {
	if cfgStr == nil {
		setGlobalError("parse_config: cfg_str is null")
		return C.int32_t(-1)
	}
	text := C.GoString(cfgStr)
	if _, err := parseConfig(text); err != nil {
		setGlobalError(fmt.Sprintf("failed to parse config: %v", err))
		return C.int32_t(-1)
	}
	clearGlobalError()
	return C.int32_t(0)
}

//export run_network_instance
func run_network_instance(cfgStr *C.char) C.int32_t {
	if cfgStr == nil {
		setGlobalError("run_network_instance: cfg_str is null")
		return C.int32_t(-1)
	}
	text := C.GoString(cfgStr)
	cfg, err := parseConfig(text)
	if err != nil {
		setGlobalError(fmt.Sprintf("failed to parse config: %v", err))
		return C.int32_t(-1)
	}
	instName := cfg.InstanceName
	// Rust uses cfg.get_inst_name() which falls back to network name if instance_name empty.
	// We mimic: if InstanceName is empty, use network_name.
	if instName == "" {
		instName = cfg.NetworkIdentity.NetworkName
		if instName == "" {
			instName = "default"
		}
	}

	globalRegistry.Lock()
	if _, exists := globalRegistry.byName[instName]; exists {
		globalRegistry.Unlock()
		setGlobalError("instance already exists")
		return C.int32_t(-1)
	}
	// Reserve placeholder to prevent race
	inst := &ffiInstance{cfg: cfg, state: "created", tunFD: -1}
	globalRegistry.byName[instName] = inst
	globalRegistry.Unlock()

	// Also register in handle registry for unified lifecycle
	instances.Lock()
	handle := instances.next
	instances.next++
	instances.items[handle] = inst
	instances.Unlock()

	globalRegistry.Lock()
	globalRegistry.byID[instName] = handle
	globalRegistry.Unlock()

	if code := startInstance(inst); code != statusOK {
		// startInstance already set inst.lastError; propagate to global
		inst.mu.Lock()
		lastErr := inst.lastError
		inst.mu.Unlock()
		if lastErr != "" {
			setGlobalError(fmt.Sprintf("failed to start instance: %s", lastErr))
		} else {
			setGlobalError("failed to start instance")
		}
		// cleanup
		globalRegistry.Lock()
		delete(globalRegistry.byName, instName)
		delete(globalRegistry.byID, instName)
		globalRegistry.Unlock()
		instances.Lock()
		delete(instances.items, handle)
		instances.Unlock()
		return C.int32_t(-1)
	}
	clearGlobalError()
	return C.int32_t(0)
}

//export retain_network_instance
func retain_network_instance(instNames **C.char, length C.size_t) C.int32_t {
	n := int(length)
	var keep []string
	if n > 0 {
		if instNames == nil {
			setGlobalError("retain_network_instance: inst_names is null")
			return C.int32_t(-1)
		}
		// Build slice of *C.char from raw pointer
		ptrs := (*[1 << 28]*C.char)(unsafe.Pointer(instNames))[:n:n]
		for i := 0; i < n; i++ {
			if ptrs[i] == nil {
				continue
			}
			keep = append(keep, C.GoString(ptrs[i]))
		}
	}
	keepSet := make(map[string]bool, len(keep))
	for _, k := range keep {
		keepSet[k] = true
	}

	// Collect names to remove
	var toRemove []string
	globalRegistry.RLock()
	for name := range globalRegistry.byName {
		if n == 0 {
			toRemove = append(toRemove, name)
		} else if !keepSet[name] {
			toRemove = append(toRemove, name)
		}
	}
	globalRegistry.RUnlock()

	// Stop and remove each
	for _, name := range toRemove {
		globalRegistry.RLock()
		inst, ok := globalRegistry.byName[name]
		handle := globalRegistry.byID[name]
		globalRegistry.RUnlock()
		if !ok {
			continue
		}
		_ = stopInstance(inst)
		// mark released
		inst.mu.Lock()
		inst.released = true
		inst.mu.Unlock()

		globalRegistry.Lock()
		delete(globalRegistry.byName, name)
		delete(globalRegistry.byID, name)
		globalRegistry.Unlock()

		instances.Lock()
		delete(instances.items, handle)
		instances.Unlock()
	}
	clearGlobalError()
	return C.int32_t(0)
}

//export collect_network_infos
func collect_network_infos(infos *C.KeyValuePair, maxLength C.size_t) C.int32_t {
	if maxLength == 0 {
		return C.int32_t(0)
	}
	if infos == nil {
		setGlobalError("collect_network_infos: infos is null")
		return C.int32_t(-1)
	}
	max := int(maxLength)
	// Snapshot
	globalRegistry.RLock()
	names := make([]string, 0, len(globalRegistry.byName))
	for name := range globalRegistry.byName {
		names = append(names, name)
	}
	globalRegistry.RUnlock()

	// Sort for determinism
	// Use simple bubble sort via standard library? Avoid extra import; use strings sort
	// We'll use a manual sort
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}

	count := 0
	// Create slice view of C array
	pairs := (*[1 << 28]C.KeyValuePair)(unsafe.Pointer(infos))[:max:max]
	for _, name := range names {
		if count >= max {
			break
		}
		globalRegistry.RLock()
		inst, ok := globalRegistry.byName[name]
		globalRegistry.RUnlock()
		if !ok {
			continue
		}
		inst.mu.Lock()
		state := inst.state
		addr := inst.address
		lastErr := inst.lastError
		tunFD := inst.tunFD
		cfg := inst.cfg
		inst.mu.Unlock()

		info := map[string]interface{}{
			"instance_name": name,
			"state":         state,
			"running":       state == "running",
			"address":       addr,
			"last_error":    lastErr,
			"tun_fd":        tunFD,
			"network_name":  cfg.NetworkIdentity.NetworkName,
			"listeners":     cfg.Listeners,
			"config":        cfg,
		}
		// Remove empty last_error for cleanliness but keep for compat
		data, err := json.Marshal(info)
		if err != nil {
			setGlobalError(fmt.Sprintf("failed to serialize instance info: %v", err))
			return C.int32_t(-1)
		}
		pairs[count].key = C.CString(name)
		pairs[count].value = C.CString(string(data))
		count++
	}
	clearGlobalError()
	return C.int32_t(count)
}

func parseConfig(text string) (config.Config, error) {
	var cfg config.Config
	if err := toml.Unmarshal([]byte(text), &cfg); err != nil {
		return config.Config{}, fmt.Errorf("parse TOML: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

func lookupInstance(handle uint64) (*ffiInstance, bool) {
	if handle == 0 {
		return nil, false
	}
	instances.RLock()
	instance, ok := instances.items[handle]
	instances.RUnlock()
	return instance, ok
}

func startInstance(instance *ffiInstance) int {
	instance.mu.Lock()
	if instance.released {
		instance.mu.Unlock()
		return statusInvalidHandle
	}
	if instance.state == "running" {
		instance.mu.Unlock()
		return statusOK
	}
	if instance.state == "starting" || instance.state == "stopping" {
		instance.mu.Unlock()
		return statusInvalidState
	}
	instance.state = "starting"
	instance.mu.Unlock()

	address, err := listenerAddress(instance.cfg)
	if err != nil {
		setError(instance, "start: "+err.Error(), "error")
		return statusConfig
	}
	identity, err := instance.cfg.LegacyIdentity(2)
	if err != nil {
		setError(instance, "start: "+err.Error(), "error")
		return statusConfig
	}
	node, err := core.ListenWithIdentity(address, 0, &identity)
	if err != nil {
		setError(instance, "start: "+err.Error(), "error")
		return statusRuntime
	}

	serveDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	instance.mu.Lock()
	if instance.state != "starting" {
		instance.mu.Unlock()
		_ = node.Close()
		cancel()
		return statusInvalidState
	}
	instance.node = node
	instance.serveDone = serveDone
	instance.serveErr = nil
	instance.address = node.Address().String()
	instance.state = "running"
	instance.lastError = ""
	instance.cancel = cancel
	instance.mu.Unlock()

	go serveInstance(instance, node, serveDone, ctx)
	return statusOK
}

func serveInstance(instance *ffiInstance, node *core.Node, done chan struct{}, ctx context.Context) {
	err := node.Serve(ctx)
	instance.mu.Lock()
	instance.serveErr = err
	if err != nil {
		instance.lastError = "serve: " + err.Error()
		instance.state = "error"
	} else if instance.state == "running" {
		instance.state = "stopped"
	}
	instance.mu.Unlock()
	close(done)
}

func stopInstance(instance *ffiInstance) int {
	instance.mu.Lock()
	if instance.state == "starting" {
		instance.mu.Unlock()
		return statusInvalidState
	}
	if instance.state != "running" && instance.state != "error" && instance.state != "stopping" {
		instance.mu.Unlock()
		return statusOK
	}
	node := instance.node
	done := instance.serveDone
	cancel := instance.cancel
	instance.state = "stopping"
	instance.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if node != nil {
		if err := node.Close(); err != nil {
			setError(instance, "stop: "+err.Error(), "error")
			return statusRuntime
		}
	}
	if done != nil {
		<-done
	}

	instance.mu.Lock()
	instance.node = nil
	instance.serveDone = nil
	instance.cancel = nil
	if instance.serveErr != nil && instance.serveErr != context.Canceled {
		instance.state = "error"
		instance.lastError = "stop: " + instance.serveErr.Error()
	} else {
		instance.state = "stopped"
	}
	instance.mu.Unlock()
	return statusOK
}

func setError(instance *ffiInstance, message, state string) {
	instance.mu.Lock()
	instance.lastError = message
	instance.state = state
	instance.mu.Unlock()
}

func listenerAddress(cfg config.Config) (string, error) {
	if len(cfg.Listeners) == 0 {
		return "", fmt.Errorf("at least one listener is required")
	}
	listener := cfg.Listeners[0]
	if !strings.Contains(listener, "://") {
		return listener, nil
	}
	endpoint, err := config.ParseEndpoint(listener)
	if err != nil {
		return "", err
	}
	if endpoint.Protocol != config.ProtocolTCP {
		return "", fmt.Errorf("listener %q uses %s; only TCP listeners are supported", listener, endpoint.Protocol)
	}
	return net.JoinHostPort(endpoint.Host, strconv.Itoa(int(endpoint.Port))), nil
}

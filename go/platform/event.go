// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// GUIEvent names mirror the frontend event.ts EVENTS object.
const (
	EventSaveConfigs            = "save_configs"
	EventSaveEnabledNetworks    = "save_enabled_networks"
	EventPreRunNetworkInstance  = "pre_run_network_instance"
	EventPostRunNetworkInstance = "post_run_network_instance"
	EventVPNServiceStop         = "vpn_service_stop"
	EventDHCPIPChanged          = "dhcp_ip_changed"
	EventProxyCidrsUpdated      = "proxy_cidrs_updated"
	EventEventLagged            = "event_lagged"
)

// AllGUIEvents lists every known GUI event.
var AllGUIEvents = []string{
	EventSaveConfigs,
	EventSaveEnabledNetworks,
	EventPreRunNetworkInstance,
	EventPostRunNetworkInstance,
	EventVPNServiceStop,
	EventDHCPIPChanged,
	EventProxyCidrsUpdated,
	EventEventLagged,
}

// IsValidGUIEvent reports whether name is a known GUI event.
func IsValidGUIEvent(name string) bool {
	for _, e := range AllGUIEvents {
		if e == name {
			return true
		}
	}
	return false
}

// GUIEventPayload normalizes instance-id payloads like the frontend's normalizeInstanceIdPayload.
// Payload may be a string or an object {part1,part2,part3,part4} (UUID parts).
func NormalizeInstanceIDPayload(payload any) string {
	if payload == nil {
		return ""
	}
	switch v := payload.(type) {
	case string:
		return v
	case map[string]any:
		if isUUIDParts(v) {
			// Reconstruct as hex string for determinism, similar to Utils.UuidToStr
			// Use JSON marshaling of map's values for stability.
			b, _ := json.Marshal(v)
			return string(b)
		}
		if s, ok := v["id"].(string); ok {
			return s
		}
		b, _ := json.Marshal(v)
		s := string(b)
		if s == "{}" || s == "null" {
			return ""
		}
		if s == "[object Object]" {
			return ""
		}
		return s
	default:
		s := fmt.Sprint(v)
		if s == "[object Object]" {
			return ""
		}
		return s
	}
}

func isUUIDParts(m map[string]any) bool {
	for _, k := range []string{"part1", "part2", "part3", "part4"} {
		v, ok := m[k]
		if !ok {
			return false
		}
		switch v.(type) {
		case float64, int, int32, int64:
		default:
			return false
		}
	}
	return true
}

// EventHandler is a function receiving event name and payload.
type EventHandler func(event string, payload any)

// EventBus provides a simple in-process pub/sub for GUI events.
// It mirrors Tauri's emit/listen model in-process for tests and the Go backend.
type EventBus struct {
	mu        sync.RWMutex
	listeners map[string][]EventHandler
	history   []EmittedEvent
}

// EmittedEvent records an emitted event for assertions.
type EmittedEvent struct {
	Event   string
	Payload any
}

// NewEventBus creates a bus.
func NewEventBus() *EventBus {
	return &EventBus{listeners: make(map[string][]EventHandler)}
}

// Listen registers a handler for an event, returning an unlisten function.
func (b *EventBus) Listen(event string, handler EventHandler) func() {
	if b == nil {
		return func() {}
	}
	if !IsValidGUIEvent(event) {
		// Allow custom events but warn via history
	}
	b.mu.Lock()
	b.listeners[event] = append(b.listeners[event], handler)
	idx := len(b.listeners[event]) - 1
	b.mu.Unlock()
	return func() {
		if b == nil {
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		hs := b.listeners[event]
		if idx >= len(hs) {
			return
		}
		// Remove by index without preserving order
		hs[idx] = hs[len(hs)-1]
		b.listeners[event] = hs[:len(hs)-1]
	}
}

// Emit broadcasts payload to listeners and records history.
func (b *EventBus) Emit(event string, payload any) error {
	if b == nil {
		return fmt.Errorf("event bus is nil")
	}
	b.mu.Lock()
	b.history = append(b.history, EmittedEvent{Event: event, Payload: payload})
	handlers := append([]EventHandler(nil), b.listeners[event]...)
	b.mu.Unlock()
	for _, h := range handlers {
		h(event, payload)
	}
	return nil
}

// History returns a copy of emitted events.
func (b *EventBus) History() []EmittedEvent {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]EmittedEvent, len(b.history))
	copy(out, b.history)
	return out
}

// ClearHistory clears recorded history.
func (b *EventBus) ClearHistory() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.history = nil
	b.mu.Unlock()
}

// Count returns number of emitted events with given name.
func (b *EventBus) Count(event string) int {
	if b == nil {
		return 0
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := 0
	for _, e := range b.history {
		if e.Event == event {
			n++
		}
	}
	return n
}

// PlanEvents returns a dry-run Plan describing event wiring for the OS.
func PlanEvents(osName string, events []string) (Plan, error) {
	if strings.TrimSpace(osName) == "" {
		osName = "linux"
	}
	plan := newPlan(osName)
	if len(events) == 0 {
		events = AllGUIEvents
	}
	for _, ev := range events {
		if !IsValidGUIEvent(ev) {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("unknown event %q", ev))
		}
		plan.Add(fmt.Sprintf("listen %s", ev), []string{"event", "listen", ev}, false, []string{"event", "unlisten", ev})
	}
	// Android-specific extra handling for VPN events
	if osName == "android" {
		plan.Add("register vpnservice listener", []string{"vpnservice", "listen", "vpn_service_start"}, true, nil)
		plan.Add("handle dhcp/proxy lag", []string{"broadcast", "subscribe", "GlobalCtxEvent"}, true, nil)
	}
	return plan, nil
}

// RenderEventHistory returns a human-readable snapshot of history for tests.
func RenderEventHistory(history []EmittedEvent) string {
	var b strings.Builder
	for i, e := range history {
		if i > 0 {
			b.WriteString("|")
		}
		payloadStr := ""
		if e.Payload != nil {
			if js, err := json.Marshal(e.Payload); err == nil {
				payloadStr = string(js)
			} else {
				payloadStr = fmt.Sprint(e.Payload)
			}
		}
		b.WriteString(e.Event + ":" + payloadStr)
	}
	return b.String()
}

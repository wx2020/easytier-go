// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ConfigSource distinguishes how a network configuration was obtained.
// Mirrors Rust PersistedConfigSource / ConfigSource.
type ConfigSource string

const (
	ConfigSourceUser    ConfigSource = "user"
	ConfigSourceWebhook ConfigSource = "webhook"
	ConfigSourceLegacy  ConfigSource = "legacy"
)

// ParseConfigSource normalizes a raw string to a known ConfigSource.
// Unknown values fall back to legacy, matching the frontend's parseStoredConfigs.
func ParseConfigSource(s string) ConfigSource {
	switch ConfigSource(strings.ToLower(strings.TrimSpace(s))) {
	case ConfigSourceUser:
		return ConfigSourceUser
	case ConfigSourceWebhook:
		return ConfigSourceWebhook
	default:
		return ConfigSourceLegacy
	}
}

// IsValid reports whether the source is a known user/webhook/legacy value.
func (s ConfigSource) IsValid() bool {
	switch s {
	case ConfigSourceUser, ConfigSourceWebhook, ConfigSourceLegacy:
		return true
	default:
		return false
	}
}

// IsWebhookLike reports webhook-like ownership (only webhook).
func (s ConfigSource) IsWebhookLike() bool { return s == ConfigSourceWebhook }

// ToRPC returns the wire value (user->user, webhook->webhook, legacy->user)
// matching Rust's to_runtime_source then to_rpc.
func (s ConfigSource) ToRPC() string {
	switch s {
	case ConfigSourceWebhook:
		return "webhook"
	default:
		return "user"
	}
}

// MergePersisted implements the Rust merge_persisted semantics:
//
//	(Legacy, User) and (Webhook, User) keep self, otherwise incoming wins.
func (s ConfigSource) MergePersisted(incoming ConfigSource) ConfigSource {
	if incoming == ConfigSourceUser && (s == ConfigSourceLegacy || s == ConfigSourceWebhook) {
		return s
	}
	return incoming
}

// FromRuntimeSource maps a runtime ConfigSource (user/webhook) to persisted.
// Mirrors PersistedConfigSource::from_runtime_source.
func FromRuntimeSource(runtime string) ConfigSource {
	switch strings.ToLower(runtime) {
	case "webhook":
		return ConfigSourceWebhook
	default:
		return ConfigSourceUser
	}
}

// StoredGuiConfig mirrors manager::StoredGuiConfig for persistence.
type StoredGuiConfig struct {
	Config json.RawMessage `json:"config"`
	Source ConfigSource    `json:"source"`
}

// UnmarshalJSON ensures missing source defaults to legacy.
func (s *StoredGuiConfig) UnmarshalJSON(data []byte) error {
	type alias StoredGuiConfig
	var tmp struct {
		Config json.RawMessage `json:"config"`
		Source *string         `json:"source"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	s.Config = tmp.Config
	if tmp.Source == nil || strings.TrimSpace(*tmp.Source) == "" {
		s.Source = ConfigSourceLegacy
		return nil
	}
	mapped := ParseConfigSource(*tmp.Source)
	// Only user/webhook are explicit; everything else becomes legacy.
	if mapped == ConfigSourceUser || mapped == ConfigSourceWebhook {
		s.Source = mapped
	} else {
		s.Source = ConfigSourceLegacy
	}
	return nil
}

// MarshalJSON preserves source as lower-case string.
func (s StoredGuiConfig) MarshalJSON() ([]byte, error) {
	type alias StoredGuiConfig
	return json.Marshal(struct {
		Config json.RawMessage `json:"config"`
		Source string          `json:"source"`
	}{Config: s.Config, Source: string(s.Source)})
}

// NormalizeStoredConfigs parses a JSON array that may contain either wrapped
// {config, source} entries or bare config objects (legacy). Mirrors the
// frontend parseStoredConfigs helper.
func NormalizeStoredConfigs(raw string) ([]StoredGuiConfig, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return []StoredGuiConfig{}, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
		return nil, fmt.Errorf("invalid stored configs: %w", err)
	}
	out := make([]StoredGuiConfig, 0, len(arr))
	for _, item := range arr {
		var wrapped map[string]json.RawMessage
		if err := json.Unmarshal(item, &wrapped); err != nil {
			continue
		}
		if cfg, ok := wrapped["config"]; ok {
			var src ConfigSource = ConfigSourceLegacy
			if rawSrc, ok2 := wrapped["source"]; ok2 {
				var s string
				if json.Unmarshal(rawSrc, &s) == nil {
					src = ParseConfigSource(s)
					if src != ConfigSourceUser && src != ConfigSourceWebhook {
						src = ConfigSourceLegacy
					}
				}
			}
			out = append(out, StoredGuiConfig{Config: cfg, Source: src})
			continue
		}
		// Bare config object -> legacy
		out = append(out, StoredGuiConfig{Config: item, Source: ConfigSourceLegacy})
	}
	return out, nil
}

// ConfigSourceForRPC validates source values used in RPC requests.
func ConfigSourceForRPC(s string) (ConfigSource, error) {
	p := ParseConfigSource(s)
	if p == ConfigSourceLegacy {
		return ConfigSourceUser, nil
	}
	return p, nil
}

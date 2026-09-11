// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package relay

import (
	"sync"
	"time"
)

// TrustedKeySource mirrors Rust's TrustedKeySource.
type TrustedKeySource int

const (
	TrustedSourceNode TrustedKeySource = iota
	TrustedSourceCredential
)

// TrustedKeyMetadata holds expiry info for a trusted pubkey.
type TrustedKeyMetadata struct {
	Source     TrustedKeySource
	ExpiryUnix *int64
}

// IsExpired reports whether the key has expired.
func (m TrustedKeyMetadata) IsExpired() bool {
	if m.ExpiryUnix == nil {
		return false
	}
	now := time.Now().Unix()
	return now >= *m.ExpiryUnix
}

// TrustedStore keeps per-network trusted X25519 pubkeys.
type TrustedStore struct {
	mu   sync.RWMutex
	keys map[string]map[string]TrustedKeyMetadata // network -> hex(pubkey) -> metadata
}

func NewTrustedStore() *TrustedStore {
	return &TrustedStore{keys: make(map[string]map[string]TrustedKeyMetadata)}
}

func pubkeyToString(pubkey []byte) string {
	// Use string directly; pubkey is 32 bytes binary.
	return string(pubkey)
}

// Update replaces the entire trusted set for network.
func (s *TrustedStore) Update(network string, trusted map[string]TrustedKeyMetadata) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(trusted) == 0 {
		delete(s.keys, network)
		return
	}
	cp := make(map[string]TrustedKeyMetadata, len(trusted))
	for k, v := range trusted {
		cp[k] = v
	}
	s.keys[network] = cp
}

// Add inserts one trusted key.
func (s *TrustedStore) Add(network string, pubkey []byte, meta TrustedKeyMetadata) {
	if len(pubkey) != 32 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys[network] == nil {
		s.keys[network] = make(map[string]TrustedKeyMetadata)
	}
	s.keys[network][pubkeyToString(pubkey)] = meta
}

// Remove deletes all keys for network.
func (s *TrustedStore) Remove(network string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, network)
}

// IsTrusted reports whether pubkey is trusted for network.
// If source is nil, any source matches.
func (s *TrustedStore) IsTrusted(pubkey []byte, network string, source *TrustedKeySource) bool {
	if len(pubkey) != 32 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.keys[network]
	if !ok {
		return false
	}
	meta, ok := m[pubkeyToString(pubkey)]
	if !ok {
		return false
	}
	if meta.IsExpired() {
		return false
	}
	if source != nil && meta.Source != *source {
		return false
	}
	return true
}

// IsTrustedAny reports if any key in network matches.
func (s *TrustedStore) IsTrustedAny(pubkey []byte, network string) bool {
	return s.IsTrusted(pubkey, network, nil)
}

// List returns non-expired keys for network sorted by pubkey.
func (s *TrustedStore) List(network string) map[string]TrustedKeyMetadata {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]TrustedKeyMetadata)
	for k, v := range s.keys[network] {
		if !v.IsExpired() {
			out[k] = v
		}
	}
	return out
}

// Count returns number of non-expired keys.
func (s *TrustedStore) Count(network string) int {
	return len(s.List(network))
}

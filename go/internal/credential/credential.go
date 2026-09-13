// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package credential manages locally issued, temporary access credentials.
package credential

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"
)

var (
	ErrNotFound          = errors.New("credential not found")
	ErrExpired           = errors.New("credential expired")
	ErrPublicKeyMismatch = errors.New("credential public key mismatch")
	ErrUsed              = errors.New("credential has already been used")
)

// Credential authorizes a peer until ExpiresAt. PublicKey is an X25519 public
// key. ProxyCIDRs describes the networks the credential may proxy.
type Credential struct {
	ID        string
	PublicKey [32]byte
	// PrivateKey is returned only by Generate and is never stored by Manager.
	// It is intentionally omitted from JSON and proof encoding.
	PrivateKey   []byte `json:"-"`
	Groups       []string
	RelayAllowed bool
	ProxyCIDRs   []netip.Prefix
	Reusable     bool
	ExpiresAt    time.Time
}

// GenerateOption changes the policy fields of a generated credential.
type GenerateOption func(*Credential)

// WithGroups sets the groups assigned to a generated credential.
func WithGroups(groups ...string) GenerateOption {
	return func(credential *Credential) {
		credential.Groups = append([]string(nil), groups...)
	}
}

// WithRelayPermission sets whether a generated credential may relay traffic.
func WithRelayPermission(allowed bool) GenerateOption {
	return func(credential *Credential) {
		credential.RelayAllowed = allowed
	}
}

// WithProxyCIDRs sets the CIDRs a generated credential may proxy.
func WithProxyCIDRs(prefixes ...netip.Prefix) GenerateOption {
	return func(credential *Credential) {
		credential.ProxyCIDRs = append([]netip.Prefix(nil), prefixes...)
	}
}

// WithReusable sets whether a credential can validate more than once.
func WithReusable(reusable bool) GenerateOption {
	return func(credential *Credential) {
		credential.Reusable = reusable
	}
}

// Manager stores credentials in memory. Its zero value is ready for use.
type Manager struct {
	mu          sync.Mutex
	credentials map[string]entry
}

type entry struct {
	credential Credential
	used       bool
}

// Generate creates and stores a credential. An empty id creates a random
// UUID-v4-style ID; non-empty IDs must use that same lowercase hexadecimal form.
func (m *Manager) Generate(ttl time.Duration, id string, options ...GenerateOption) (Credential, error) {
	if ttl <= 0 {
		return Credential{}, errors.New("credential TTL must be positive")
	}
	if id == "" {
		var err error
		id, err = randomID()
		if err != nil {
			return Credential{}, err
		}
	} else if !validID(id) {
		return Credential{}, fmt.Errorf("credential ID %q is invalid", id)
	}

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Credential{}, fmt.Errorf("generate X25519 key: %w", err)
	}
	var publicKey [32]byte
	copy(publicKey[:], privateKey.PublicKey().Bytes())

	credential := Credential{
		ID:         id,
		PublicKey:  publicKey,
		PrivateKey: append([]byte(nil), privateKey.Bytes()...),
		ExpiresAt:  time.Now().Add(ttl),
	}
	for _, option := range options {
		if option != nil {
			option(&credential)
		}
	}
	if err := credential.Validate(); err != nil {
		return Credential{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(time.Now())
	if m.credentials == nil {
		m.credentials = make(map[string]entry)
	}
	if _, exists := m.credentials[id]; exists {
		return Credential{}, fmt.Errorf("credential ID %q already exists", id)
	}
	stored := clone(credential)
	stored.PrivateKey = nil
	m.credentials[id] = entry{credential: stored}
	return credential, nil
}

// List returns all non-expired credentials and removes expired credentials.
func (m *Manager) List(now time.Time) []Credential {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	credentials := make([]Credential, 0, len(m.credentials))
	for _, stored := range m.credentials {
		credentials = append(credentials, clone(stored.credential))
	}
	sort.Slice(credentials, func(i, j int) bool {
		return credentials[i].ID < credentials[j].ID
	})
	return credentials
}

// Revoke removes an existing credential. It returns whether one was removed.
func (m *Manager) Revoke(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(time.Now())
	if _, exists := m.credentials[id]; !exists {
		return false
	}
	delete(m.credentials, id)
	return true
}

// Validate looks up an unexpired credential by ID and X25519 public key.
// A successful validation consumes a non-reusable credential atomically.
func (m *Manager) Validate(id string, publicKey [32]byte, now time.Time) (Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	stored, exists := m.credentials[id]
	if !exists {
		return Credential{}, ErrNotFound
	}
	if stored.credential.PublicKey != publicKey {
		return Credential{}, ErrPublicKeyMismatch
	}
	if !stored.credential.Reusable && stored.used {
		return Credential{}, ErrUsed
	}
	if !stored.credential.Reusable {
		stored.used = true
		m.credentials[id] = stored
	}
	return clone(stored.credential), nil
}

// Validate confirms the credential fields are safe and complete.
func (c Credential) Validate() error {
	if !validID(c.ID) {
		return fmt.Errorf("credential ID %q is invalid", c.ID)
	}
	if c.PublicKey == [32]byte{} {
		return errors.New("credential public key is zero")
	}
	if c.ExpiresAt.IsZero() {
		return errors.New("credential expiry is required")
	}
	seenGroups := make(map[string]struct{}, len(c.Groups))
	for i, group := range c.Groups {
		if group == "" {
			return fmt.Errorf("credential group %d is empty", i)
		}
		if _, exists := seenGroups[group]; exists {
			return fmt.Errorf("credential group %q is duplicated", group)
		}
		seenGroups[group] = struct{}{}
	}
	for i, prefix := range c.ProxyCIDRs {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return fmt.Errorf("credential proxy CIDR %d is invalid", i)
		}
	}
	return nil
}

// Proof computes an HMAC-SHA256 over the credential's canonical binary form.
func Proof(key []byte, credential Credential) ([sha256.Size]byte, error) {
	encoded, err := credential.MarshalBinary()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write(encoded)
	var proof [sha256.Size]byte
	copy(proof[:], hash.Sum(nil))
	return proof, nil
}

// VerifyProof reports whether proof authenticates credential with key.
func VerifyProof(key []byte, credential Credential, proof [sha256.Size]byte) bool {
	want, err := Proof(key, credential)
	return err == nil && hmac.Equal(want[:], proof[:])
}

// MarshalBinary returns a stable binary encoding suitable for proof generation.
func (c Credential) MarshalBinary() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	groups := append([]string(nil), c.Groups...)
	sort.Strings(groups)
	prefixes := append([]netip.Prefix(nil), c.ProxyCIDRs...)
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })

	var encoded bytes.Buffer
	encoded.WriteByte(1)
	writeString(&encoded, c.ID)
	encoded.Write(c.PublicKey[:])
	if c.RelayAllowed {
		encoded.WriteByte(1)
	} else {
		encoded.WriteByte(0)
	}
	if c.Reusable {
		encoded.WriteByte(1)
	} else {
		encoded.WriteByte(0)
	}
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], uint64(c.ExpiresAt.UTC().UnixNano()))
	encoded.Write(expiry[:])
	writeUint32(&encoded, uint32(len(groups)))
	for _, group := range groups {
		writeString(&encoded, group)
	}
	writeUint32(&encoded, uint32(len(prefixes)))
	for _, prefix := range prefixes {
		writeString(&encoded, prefix.String())
	}
	return encoded.Bytes(), nil
}

func (m *Manager) cleanupLocked(now time.Time) {
	for id, stored := range m.credentials {
		if !stored.credential.ExpiresAt.After(now) {
			delete(m.credentials, id)
		}
	}
}

func clone(credential Credential) Credential {
	credential.Groups = append([]string(nil), credential.Groups...)
	credential.ProxyCIDRs = append([]netip.Prefix(nil), credential.ProxyCIDRs...)
	credential.PrivateKey = append([]byte(nil), credential.PrivateKey...)
	return credential
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate credential ID: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return hex.EncodeToString(raw[:4]) + "-" + hex.EncodeToString(raw[4:6]) + "-" + hex.EncodeToString(raw[6:8]) + "-" + hex.EncodeToString(raw[8:10]) + "-" + hex.EncodeToString(raw[10:]), nil
}

func validID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	for i := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !(id[i] >= '0' && id[i] <= '9' || id[i] >= 'a' && id[i] <= 'f') {
			return false
		}
	}
	return true
}

func writeString(buffer *bytes.Buffer, value string) {
	writeUint32(buffer, uint32(len(value)))
	buffer.WriteString(value)
}

func writeUint32(buffer *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	buffer.Write(raw[:])
}

// LoadPublicCredentials reads a JSON file containing an array of credentials
// (the same encoding produced by encoding/json on []Credential). Entries that
// fail validation are skipped; the function errors only when the file cannot
// be read or parsed. It is the loading path for --credential-file on admin
// nodes that publish trusted credentials in their OSPF LSAs.
func LoadPublicCredentials(path string) ([]Credential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}
	var credentials []Credential
	if err := json.Unmarshal(data, &credentials); err != nil {
		return nil, fmt.Errorf("parse credential file: %w", err)
	}
	valid := make([]Credential, 0, len(credentials))
	for _, credential := range credentials {
		if err := credential.Validate(); err != nil {
			continue
		}
		valid = append(valid, credential)
	}
	return valid, nil
}

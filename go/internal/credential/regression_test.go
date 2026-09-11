// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package credential

import (
	"net/netip"
	"testing"
	"time"
)

// TestCredentialGroupsAndProxyCIDRs mirrors Rust credential relay/proxy handling
func TestCredentialGroupsAndProxyCIDRs(t *testing.T) {
	m := new(Manager)
	cred, err := m.Generate(time.Hour, "11111111-1111-4111-8111-111111111111", WithGroups("operators"), WithProxyCIDRs(netip.MustParsePrefix("10.0.0.0/8")), WithRelayPermission(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.Groups) != 1 || cred.Groups[0] != "operators" {
		t.Fatalf("groups = %v", cred.Groups)
	}
	if len(cred.ProxyCIDRs) != 1 || cred.ProxyCIDRs[0].String() != "10.0.0.0/8" {
		t.Fatalf("proxy CIDRs = %v", cred.ProxyCIDRs)
	}
	if !cred.RelayAllowed {
		t.Fatal("relay should be allowed")
	}
	// Deterministic proof: same credential must verify
	proof, err := Proof([]byte("key"), cred)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyProof([]byte("key"), cred, proof) {
		t.Fatal("proof verify failed")
	}
	// Reordered groups should still verify (canonical encoding)
	cred2, _ := m.Generate(time.Hour, "22222222-2222-4222-8222-222222222222", WithGroups("workers", "operators"))
	if len(cred2.Groups) != 2 {
		t.Fatalf("groups length")
	}
	// Validate sorting: proof should be deterministic regardless of input order
	credA := Credential{ID: "33333333-3333-4333-8333-333333333333", PublicKey: [32]byte{1}, Groups: []string{"b", "a"}, ProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16")}, ExpiresAt: time.Unix(1_700_000_000, 0).UTC()}
	proofA, _ := Proof([]byte("k"), credA)
	credB := Credential{ID: "33333333-3333-4333-8333-333333333333", PublicKey: [32]byte{1}, Groups: []string{"a", "b"}, ProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("10.0.0.0/8")}, ExpiresAt: credA.ExpiresAt}
	if !VerifyProof([]byte("k"), credB, proofA) {
		t.Fatal("canonical proof should verify for reordered")
	}
}

// TestNonReusableCredentialRace mirrors Rust credential_non_reusable_allows_only_one_peer
func TestNonReusableCredentialRace(t *testing.T) {
	m := new(Manager)
	cred, err := m.Generate(time.Hour, "44444444-4444-4444-8444-444444444444", WithReusable(false))
	if err != nil {
		t.Fatal(err)
	}
	// First validation succeeds
	if _, err := m.Validate(cred.ID, cred.PublicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Second validation should fail as used
	if _, err := m.Validate(cred.ID, cred.PublicKey, time.Now()); err == nil {
		t.Fatal("second use of non-reusable should fail")
	}
	// Reusable should allow second
	reusable, _ := m.Generate(time.Hour, "55555555-5555-4555-8555-555555555555", WithReusable(true))
	for i := 0; i < 3; i++ {
		if _, err := m.Validate(reusable.ID, reusable.PublicKey, time.Now()); err != nil {
			t.Fatalf("reusable validate %d: %v", i, err)
		}
	}
}

// TestCredentialRevocationPropagates mirrors Rust credential_revocation
func TestCredentialRevocationPropagates(t *testing.T) {
	m := new(Manager)
	cred, _ := m.Generate(time.Hour, "66666666-6666-4666-8666-666666666666")
	if !m.Revoke(cred.ID) {
		t.Fatal("revoke should succeed")
	}
	if _, err := m.Validate(cred.ID, cred.PublicKey, time.Now()); err == nil {
		t.Fatal("revoked credential should not validate")
	}
	if m.Revoke(cred.ID) {
		t.Fatal("second revoke should fail")
	}
	list := m.List(time.Now())
	for _, c := range list {
		if c.ID == cred.ID {
			t.Fatal("revoked credential should not be in list")
		}
	}
}

// TestCredentialValidationCoversRustCases mirrors Rust invalid credential cases
func TestCredentialValidationCoversRustCases(t *testing.T) {
	cases := []struct {
		name string
		cred Credential
		ok   bool
	}{
		{"valid", Credential{ID: "77777777-7777-4777-8777-777777777777", PublicKey: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour)}, true},
		{"empty ID", Credential{PublicKey: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour)}, false},
		{"zero key", Credential{ID: "77777777-7777-4777-8777-777777777777", ExpiresAt: time.Now().Add(time.Hour)}, false},
		{"duplicate group", Credential{ID: "77777777-7777-4777-8777-777777777777", PublicKey: [32]byte{1}, Groups: []string{"a", "a"}, ExpiresAt: time.Now().Add(time.Hour)}, false},
		{"empty group", Credential{ID: "77777777-7777-4777-8777-777777777777", PublicKey: [32]byte{1}, Groups: []string{""}, ExpiresAt: time.Now().Add(time.Hour)}, false},
		{"invalid CIDR", Credential{ID: "77777777-7777-4777-8777-777777777777", PublicKey: [32]byte{1}, ProxyCIDRs: []netip.Prefix{{}}, ExpiresAt: time.Now().Add(time.Hour)}, false},
	}
	for _, tc := range cases {
		err := tc.cred.Validate()
		if tc.ok && err != nil {
			t.Fatalf("%s should be valid: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s should be invalid", tc.name)
		}
	}
}

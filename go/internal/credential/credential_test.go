// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package credential

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestManagerExpiresCredentials(t *testing.T) {
	manager := new(Manager)
	credential, err := manager.Generate(time.Hour, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}

	expiredAt := credential.ExpiresAt
	if _, err := manager.Validate(credential.ID, credential.PublicKey, expiredAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Validate at expiry error = %v, want ErrNotFound", err)
	}
	if got := manager.List(expiredAt); len(got) != 0 {
		t.Fatalf("List at expiry = %#v, want no credentials", got)
	}
}

func TestManagerRevokesCredentials(t *testing.T) {
	manager := new(Manager)
	credential, err := manager.Generate(time.Hour, "22222222-2222-4222-8222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.Revoke(credential.ID) {
		t.Fatal("Revoke returned false, want true")
	}
	if manager.Revoke(credential.ID) {
		t.Fatal("second Revoke returned true, want false")
	}
	if _, err := manager.Validate(credential.ID, credential.PublicKey, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Validate after revoke error = %v, want ErrNotFound", err)
	}
}

func TestManagerConsumesNonReusableCredentials(t *testing.T) {
	manager := new(Manager)
	nonReusable, err := manager.Generate(time.Hour, "33333333-3333-4333-8333-333333333333")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Validate(nonReusable.ID, nonReusable.PublicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Validate(nonReusable.ID, nonReusable.PublicKey, time.Now()); !errors.Is(err, ErrUsed) {
		t.Fatalf("second Validate error = %v, want ErrUsed", err)
	}

	reusable, err := manager.Generate(time.Hour, "44444444-4444-4444-8444-444444444444", WithReusable(true))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := manager.Validate(reusable.ID, reusable.PublicKey, time.Now()); err != nil {
			t.Fatalf("Validate reusable credential: %v", err)
		}
	}
}

func TestProofUsesCanonicalCredentialEncoding(t *testing.T) {
	credential := Credential{
		ID:           "55555555-5555-4555-8555-555555555555",
		PublicKey:    [32]byte{1},
		Groups:       []string{"operators", "workers"},
		RelayAllowed: true,
		ProxyCIDRs: []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/32"),
			netip.MustParsePrefix("10.0.0.0/8"),
		},
		Reusable:  true,
		ExpiresAt: time.Unix(1_700_000_000, 123).UTC(),
	}
	proof, err := Proof([]byte("proof key"), credential)
	if err != nil {
		t.Fatal(err)
	}
	reordered := credential
	reordered.Groups = []string{"workers", "operators"}
	reordered.ProxyCIDRs = []netip.Prefix{credential.ProxyCIDRs[1], credential.ProxyCIDRs[0]}
	if !VerifyProof([]byte("proof key"), reordered, proof) {
		t.Fatal("proof did not verify for equivalent credential")
	}
	if VerifyProof([]byte("wrong key"), credential, proof) {
		t.Fatal("proof verified with wrong key")
	}
	credential.RelayAllowed = false
	if VerifyProof([]byte("proof key"), credential, proof) {
		t.Fatal("proof verified after credential mutation")
	}
}

func TestCredentialValidation(t *testing.T) {
	valid := Credential{
		ID:        "66666666-6666-4666-8666-666666666666",
		PublicKey: [32]byte{1},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	for _, test := range []struct {
		name       string
		credential Credential
	}{
		{name: "invalid ID", credential: Credential{PublicKey: [32]byte{1}, ExpiresAt: valid.ExpiresAt}},
		{name: "zero key", credential: Credential{ID: valid.ID, ExpiresAt: valid.ExpiresAt}},
		{name: "empty group", credential: Credential{ID: valid.ID, PublicKey: valid.PublicKey, Groups: []string{""}, ExpiresAt: valid.ExpiresAt}},
		{name: "duplicate group", credential: Credential{ID: valid.ID, PublicKey: valid.PublicKey, Groups: []string{"a", "a"}, ExpiresAt: valid.ExpiresAt}},
		{name: "invalid CIDR", credential: Credential{ID: valid.ID, PublicKey: valid.PublicKey, ProxyCIDRs: []netip.Prefix{{}}, ExpiresAt: valid.ExpiresAt}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.credential.Validate(); err == nil {
				t.Fatal("Validate error = nil, want error")
			}
		})
	}
	if _, err := new(Manager).Generate(0, ""); err == nil {
		t.Fatal("Generate with zero TTL error = nil, want error")
	}
}

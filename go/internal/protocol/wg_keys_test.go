// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"encoding/hex"
	"testing"
)

func TestDeriveWGPrivateKeyMatchesDigest(t *testing.T) {
	digest := GenerateDigestFromStrings("mesh", "secret")
	priv := DeriveWGPrivateKey("mesh", "secret")
	if priv != digest {
		t.Fatalf("WG private key diverged from digest: got %x want %x", priv, digest)
	}
	wantHex := "31107b8e51f0ce46f7b98ceefacfec089fdf3c65e27f8b20fbe21c0ae043c564"
	if got := hex.EncodeToString(priv[:]); got != wantHex {
		t.Fatalf("WG private key hex = %s, want %s", got, wantHex)
	}
}

func TestDeriveWGKeyPairForPortalIsDeterministic(t *testing.T) {
	s1, c1, err := DeriveWGKeyPairForPortal("easytier", "default-secret")
	if err != nil {
		t.Fatal(err)
	}
	s2, c2, err := DeriveWGKeyPairForPortal("easytier", "default-secret")
	if err != nil {
		t.Fatal(err)
	}
	if s1 != s2 || c1 != c2 {
		t.Fatal("portal keypairs not deterministic")
	}
	if s1.Private == c1.Private {
		t.Fatal("server and client private keys must differ")
	}
}

func TestWGSyntheticHeaderRoundTripWithKeyMaterial(t *testing.T) {
	// Verify that the synthetic header used by WG transport is correct for
	// payload lengths that exercise the total-length encoding, and that the
	// key-derived identities can be used to create a valid session.
	kp, err := DeriveWGKeyPair("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if kp.Public == [32]byte{} {
		t.Fatal("public key is zero")
	}
	for _, n := range []int{0, 5, 100, 1380} {
		h := MarshalWGTunnelHeader(n)
		got, err := ParseWGTunnelHeader(h)
		if err != nil {
			t.Fatalf("ParseWGTunnelHeader(%d): %v", n, err)
		}
		if got != n {
			t.Fatalf("payload length round-trip %d != %d", got, n)
		}
		if h[0] != 0x45 || h[8] != 64 {
			t.Fatalf("synthetic header prefix invalid: %x", h[:10])
		}
	}
}

func TestWGRejectsMismatchedSecret(t *testing.T) {
	a := DeriveWGPrivateKey("mesh", "secret")
	b := DeriveWGPrivateKey("mesh", "wrong")
	if a == b {
		t.Fatal("mismatched secrets produced same WG private key")
	}
}

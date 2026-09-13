// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"bytes"
	"testing"

	peerrpc "github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
)

// The reference proof is HMAC-SHA256 keyed with the network secret over
// "easytier credential proof" followed by the protobuf encoding of the
// credential; this vector was computed against that contract.
func TestSignTrustedCredentialProofGolden(t *testing.T) {
	// Hand-encoded TrustedCredentialPubkey: field 1 (pubkey, 32 bytes).
	var pubkey [32]byte
	for i := range pubkey {
		pubkey[i] = byte(i + 1)
	}
	wire := append([]byte{0x0a, 0x20}, pubkey[:]...)
	credential := &peerrpc.TrustedCredentialPubkey{Pubkey: pubkey[:]}

	// The golden vector only transfers if the protobuf encoding matches the
	// hand-written bytes.
	encoded, err := proto.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, wire) {
		t.Fatalf("credential encoding = %x, want %x", encoded, wire)
	}

	proof, err := SignTrustedCredentialProof(credential, "mesh-secret")
	if err != nil {
		t.Fatal(err)
	}
	expected := mustHex(t, "2859d5614894eb9d7d59c3c5c51563af4208b23673534113019836a28985a8fc")
	if !bytes.Equal(proof, expected) {
		t.Fatalf("proof = %x, want %x", proof, expected)
	}
	if !VerifyTrustedCredentialProof(&peerrpc.TrustedCredentialPubkeyProof{
		Credential:     credential,
		CredentialHmac: proof,
	}, "mesh-secret") {
		t.Fatal("valid proof must verify")
	}
	// A different secret, or a tampered credential, must fail.
	if VerifyTrustedCredentialProof(&peerrpc.TrustedCredentialPubkeyProof{
		Credential:     credential,
		CredentialHmac: proof,
	}, "other-secret") {
		t.Fatal("proof must not verify under a different secret")
	}
	tampered := append([]byte(nil), proof...)
	tampered[0] ^= 0xff
	if VerifyTrustedCredentialProof(&peerrpc.TrustedCredentialPubkeyProof{
		Credential:     credential,
		CredentialHmac: tampered,
	}, "mesh-secret") {
		t.Fatal("tampered proof must not verify")
	}
}

func TestVerifiedTrustedCredentialsFiltering(t *testing.T) {
	credential := &peerrpc.TrustedCredentialPubkey{
		Pubkey:     make([]byte, 32),
		AllowRelay: true,
	}
	proof, err := SignTrustedCredentialProof(credential, "mesh-secret")
	if err != nil {
		t.Fatal(err)
	}
	bogus := &peerrpc.TrustedCredentialPubkeyProof{
		Credential:     credential,
		CredentialHmac: make([]byte, 32),
	}
	verified := VerifiedTrustedCredentials(
		[]*peerrpc.TrustedCredentialPubkeyProof{{Credential: credential, CredentialHmac: proof}, bogus},
		"mesh-secret")
	if len(verified) != 1 {
		t.Fatalf("verified = %d, want 1", len(verified))
	}
	if !VerifiedCredentialAllowsRelay(verified, "mesh-secret") {
		t.Fatal("verified relay credential must grant relay")
	}
	if VerifiedCredentialAllowsRelay([]*peerrpc.TrustedCredentialPubkeyProof{bogus}, "mesh-secret") {
		t.Fatal("unverified proof must not grant relay")
	}
	if VerifiedTrustedCredentials([]*peerrpc.TrustedCredentialPubkeyProof{bogus}, "") != nil {
		t.Fatal("credential nodes hold no secret and must verify nothing")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		high := hexDigitValue(t, s[2*i])
		low := hexDigitValue(t, s[2*i+1])
		out[i] = high<<4 | low
	}
	return out
}

func hexDigitValue(t *testing.T, c byte) byte {
	t.Helper()
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		t.Fatalf("invalid hex digit %q", c)
		return 0
	}
}

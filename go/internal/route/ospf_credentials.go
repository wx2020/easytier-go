// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/EasyTier/EasyTier/go/internal/credential"
	peerrpc "github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
)

// credentialProofDomain is the reference HMAC message prefix for trusted
// credential proofs.
const credentialProofDomain = "easytier credential proof"

// SignTrustedCredentialProof computes the reference credential proof:
// HMAC-SHA256 keyed with the network secret over the domain prefix followed
// by the protobuf encoding of the credential. Admin nodes (holding the
// network secret) publish these proofs so every peer can verify the trust
// list without exchanging keys.
func SignTrustedCredentialProof(cred *peerrpc.TrustedCredentialPubkey, networkSecret string) ([]byte, error) {
	if cred == nil {
		return nil, fmt.Errorf("trusted credential is nil")
	}
	encoded, err := proto.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("encode trusted credential: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(networkSecret))
	mac.Write([]byte(credentialProofDomain))
	mac.Write(encoded)
	return mac.Sum(nil), nil
}

// SignTrustedCredentials attaches proofs to every credential.
func SignTrustedCredentials(credentials []*peerrpc.TrustedCredentialPubkey, networkSecret string) ([]*peerrpc.TrustedCredentialPubkeyProof, error) {
	proofs := make([]*peerrpc.TrustedCredentialPubkeyProof, 0, len(credentials))
	for _, cred := range credentials {
		proof, err := SignTrustedCredentialProof(cred, networkSecret)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, &peerrpc.TrustedCredentialPubkeyProof{
			Credential:     cred,
			CredentialHmac: proof,
		})
	}
	return proofs, nil
}

// VerifyTrustedCredentialProof reports whether one proof authenticates its
// credential under the network secret.
func VerifyTrustedCredentialProof(proof *peerrpc.TrustedCredentialPubkeyProof, networkSecret string) bool {
	if proof == nil || proof.GetCredential() == nil {
		return false
	}
	expected, err := SignTrustedCredentialProof(proof.GetCredential(), networkSecret)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, proof.GetCredentialHmac())
}

// VerifiedTrustedCredentials filters the proofs that authenticate under the
// network secret. With an empty secret (a credential node itself), nothing
// verifies and the result is empty.
func VerifiedTrustedCredentials(proofs []*peerrpc.TrustedCredentialPubkeyProof, networkSecret string) []*peerrpc.TrustedCredentialPubkeyProof {
	if networkSecret == "" {
		return nil
	}
	verified := make([]*peerrpc.TrustedCredentialPubkeyProof, 0, len(proofs))
	for _, proof := range proofs {
		if VerifyTrustedCredentialProof(proof, networkSecret) {
			verified = append(verified, proof)
		}
	}
	return verified
}

// VerifiedCredentialAllowsRelay reports whether any verified proof grants
// relay permission to its holder.
func VerifiedCredentialAllowsRelay(proofs []*peerrpc.TrustedCredentialPubkeyProof, networkSecret string) bool {
	for _, proof := range VerifiedTrustedCredentials(proofs, networkSecret) {
		if proof.GetCredential().GetAllowRelay() {
			return true
		}
	}
	return false
}

// TrustedCredentialPubkeyFrom converts a locally managed credential into the
// reference wire credential.
func TrustedCredentialPubkeyFrom(cred credential.Credential) *peerrpc.TrustedCredentialPubkey {
	cidrs := make([]string, 0, len(cred.ProxyCIDRs))
	for _, prefix := range cred.ProxyCIDRs {
		cidrs = append(cidrs, prefix.String())
	}
	reusable := cred.Reusable
	return &peerrpc.TrustedCredentialPubkey{
		Pubkey:            append([]byte(nil), cred.PublicKey[:]...),
		Groups:            append([]string(nil), cred.Groups...),
		AllowRelay:        cred.RelayAllowed,
		ExpiryUnix:        cred.ExpiresAt.Unix(),
		AllowedProxyCidrs: cidrs,
		Reusable:          &reusable,
	}
}

// SignManagedCredentials converts and signs locally managed credentials for
// publication in the node's own LSA.
func SignManagedCredentials(credentials []credential.Credential, networkSecret string) ([]*peerrpc.TrustedCredentialPubkeyProof, error) {
	wireCredentials := make([]*peerrpc.TrustedCredentialPubkey, 0, len(credentials))
	for _, cred := range credentials {
		wireCredentials = append(wireCredentials, TrustedCredentialPubkeyFrom(cred))
	}
	return SignTrustedCredentials(wireCredentials, networkSecret)
}

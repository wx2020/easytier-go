// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"crypto/ecdh"
	"fmt"
)

// WgKeyPair holds deterministic WireGuard X25519 keys derived from a network
// identity. It mirrors Rust's WgConfig::new_from_network_identity.
type WgKeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// DeriveWGPrivateKey reproduces Rust's WgConfig::new_from_network_identity
// key derivation: generate_digest_from_str(networkName, networkSecret).
func DeriveWGPrivateKey(networkName, networkSecret string) [32]byte {
	return GenerateDigestFromStrings(networkName, networkSecret)
}

// DeriveWGKeyPair derives both private and public parts for a network identity.
func DeriveWGKeyPair(networkName, networkSecret string) (WgKeyPair, error) {
	priv := DeriveWGPrivateKey(networkName, networkSecret)
	pub, err := wgPublicFromPrivate(priv)
	if err != nil {
		return WgKeyPair{}, fmt.Errorf("derive WG public key: %w", err)
	}
	return WgKeyPair{Private: priv, Public: pub}, nil
}

// DeriveWGKeyPairForPortal derives portal-specific keys like Rust's
// WgConfig::new_for_portal, which uses "server"/"client" as the first
// digest input and the concatenated network identity as the second.
func DeriveWGKeyPairForPortal(networkName, networkSecret string) (server WgKeyPair, client WgKeyPair, err error) {
	seed := networkName + networkSecret
	sPriv := DeriveWGPrivateKey("server", seed)
	cPriv := DeriveWGPrivateKey("client", seed)
	sPub, err := wgPublicFromPrivate(sPriv)
	if err != nil {
		return WgKeyPair{}, WgKeyPair{}, fmt.Errorf("derive server public: %w", err)
	}
	cPub, err := wgPublicFromPrivate(cPriv)
	if err != nil {
		return WgKeyPair{}, WgKeyPair{}, fmt.Errorf("derive client public: %w", err)
	}
	return WgKeyPair{Private: sPriv, Public: sPub}, WgKeyPair{Private: cPriv, Public: cPub}, nil
}

func wgPublicFromPrivate(priv [32]byte) ([32]byte, error) {
	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(priv[:])
	if err != nil {
		return [32]byte{}, err
	}
	b := key.PublicKey().Bytes()
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package vpnportal implements the WireGuard VPN portal for EasyTier Go.
// It mirrors Rust's vpn_portal/wireguard.rs and tunnel/wireguard.rs
// deterministic key derivation.
package vpnportal

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// WgConfig holds deterministic WireGuard keys derived from network identity.
// It mirrors Rust WgConfig::new_for_portal.
type WgConfig struct {
	ServerPrivate [32]byte
	ServerPublic  [32]byte
	ClientPrivate [32]byte
	ClientPublic  [32]byte
}

// GetWgConfig returns deterministic WireGuard keys for the given network
// identity. It reproduces Rust's get_wg_config_for_portal.
func GetWgConfig(networkName, networkSecret string) (WgConfig, error) {
	keySeed := networkName + networkSecret
	serverDigest := protocol.GenerateDigestFromStrings("server", keySeed)
	clientDigest := protocol.GenerateDigestFromStrings("client", keySeed)

	serverPub, err := derivePublic(serverDigest)
	if err != nil {
		return WgConfig{}, fmt.Errorf("derive server public key: %w", err)
	}
	clientPub, err := derivePublic(clientDigest)
	if err != nil {
		return WgConfig{}, fmt.Errorf("derive client public key: %w", err)
	}
	return WgConfig{
		ServerPrivate: serverDigest,
		ServerPublic:  serverPub,
		ClientPrivate: clientDigest,
		ClientPublic:  clientPub,
	}, nil
}

// GetWgConfigForPortal is an alias matching Rust naming.
func GetWgConfigForPortal(nid config.NetworkIdentity) (WgConfig, error) {
	return GetWgConfig(nid.NetworkName, nid.NetworkSecret)
}

func derivePublic(priv [32]byte) ([32]byte, error) {
	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(priv[:])
	if err != nil {
		return [32]byte{}, err
	}
	pub := key.PublicKey()
	b := pub.Bytes()
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// GenerateClientConfig builds the WireGuard INI configuration for a portal
// client. It mirrors Rust's WireGuard::dump_client_config.
func GenerateClientConfig(cfg config.Config) (string, error) {
	if cfg.VPNPortalConfig == nil {
		return "", fmt.Errorf("VPN portal config is not set")
	}
	wc, err := GetWgConfig(cfg.NetworkIdentity.NetworkName, cfg.NetworkIdentity.NetworkSecret)
	if err != nil {
		return "", err
	}
	// Collect AllowedIPs like Rust: proxy_cidrs + ipv4 + client_cidr
	var allowIPs []string
	for _, pn := range cfg.ProxyNetworks {
		allowIPs = append(allowIPs, pn.CIDR)
	}
	if cfg.IPv4 != "" {
		if prefix, ok, _ := cfg.IPv4Prefix(); ok {
			allowIPs = append(allowIPs, prefix.String())
		}
	}
	allowIPs = append(allowIPs, cfg.VPNPortalConfig.ClientCIDR)
	allowIPsStr := strings.Join(allowIPs, ",")

	clientCIDR := cfg.VPNPortalConfig.ClientCIDR
	firstAddr := clientCIDR
	if prefix, err := netip.ParsePrefix(clientCIDR); err == nil {
		firstAddr = prefix.Addr().String() + "/32"
	}

	clientPrivB64 := base64.StdEncoding.EncodeToString(wc.ClientPrivate[:])
	serverPubB64 := base64.StdEncoding.EncodeToString(wc.ServerPublic[:])
	listenAddr := cfg.VPNPortalConfig.WireGuardListen

	// Rust format includes leading newline; preserve it for compatibility.
	cfgStr := fmt.Sprintf("\n[Interface]\nPrivateKey = %s\nAddress = %s # should assign an ip from this cidr manually\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s # should be the public ip(or domain) of the vpn server\nPersistentKeepalive = 25\n",
		clientPrivB64, firstAddr, serverPubB64, allowIPsStr, listenAddr)
	return cfgStr, nil
}

// GenerateClientConfigWithRoutes is like GenerateClientConfig but can also
// incorporate routes when available. For now it delegates to GenerateClientConfig.
func GenerateClientConfigWithRoutes(cfg config.Config) (string, error) {
	return GenerateClientConfig(cfg)
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package config

import (
	"fmt"

	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// LegacyIdentity builds the reference-compatible identity used by the legacy
// peer handshake. Peer IDs are assigned by the peer manager, so callers pass
// the instance-local ID explicitly.
func (c Config) LegacyIdentity(peerID uint32) (peer.LegacyIdentity, error) {
	if c.NetworkIdentity.NetworkName == "" {
		return peer.LegacyIdentity{}, fmt.Errorf("network_identity.network_name is required")
	}
	return peer.LegacyIdentity{
		PeerID:              peerID,
		NetworkName:         c.NetworkIdentity.NetworkName,
		NetworkSecretDigest: protocol.GenerateDigestFromStrings(c.NetworkIdentity.NetworkName, c.NetworkIdentity.NetworkSecret),
	}, nil
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package peer implements EasyTier peer-session protocols.
package peer

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const NetworkSecretDigestSize = 32

// PacketChannel is the common packet transport required by the legacy peer
// handshake. TCP and UDP transports adapt their framing to this interface.
type PacketChannel interface {
	Send(context.Context, protocol.Packet) error
	Receive(context.Context) (protocol.Packet, error)
}

// LegacyIdentity describes the local network identity used in one handshake.
type LegacyIdentity struct {
	PeerID              uint32
	NetworkName         string
	NetworkSecretDigest [NetworkSecretDigestSize]byte
	Features            []string
}

// Validate rejects incomplete identities before packets are sent.
func (i LegacyIdentity) Validate() error {
	if i.PeerID == 0 {
		return fmt.Errorf("peer ID must not be zero")
	}
	if i.NetworkName == "" {
		return fmt.Errorf("network name is required")
	}
	return nil
}

// InitiateLegacyHandshake sends a reference-compatible HandShake packet and
// verifies the responder's network identity before returning it.
func InitiateLegacyHandshake(ctx context.Context, channel PacketChannel, local LegacyIdentity) (protocol.HandshakeRequest, error) {
	if err := local.Validate(); err != nil {
		return protocol.HandshakeRequest{}, err
	}
	request, err := handshakeRequest(local)
	if err != nil {
		return protocol.HandshakeRequest{}, err
	}
	payload, err := request.Marshal()
	if err != nil {
		return protocol.HandshakeRequest{}, fmt.Errorf("marshal handshake request: %w", err)
	}
	if err := channel.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: local.PeerID, PacketType: protocol.PacketTypeHandshake},
		Payload: payload,
	}); err != nil {
		return protocol.HandshakeRequest{}, fmt.Errorf("send handshake request: %w", err)
	}

	packet, err := channel.Receive(ctx)
	if err != nil {
		return protocol.HandshakeRequest{}, fmt.Errorf("receive handshake response: %w", err)
	}
	response, err := validateHandshakePacket(packet, local)
	if err != nil {
		return protocol.HandshakeRequest{}, fmt.Errorf("validate handshake response: %w", err)
	}
	if packet.Header.ToPeerID != 0 && packet.Header.ToPeerID != local.PeerID {
		return protocol.HandshakeRequest{}, fmt.Errorf("handshake response targets peer %d, want %d", packet.Header.ToPeerID, local.PeerID)
	}
	if response.MyPeerID != packet.Header.FromPeerID {
		return protocol.HandshakeRequest{}, fmt.Errorf("handshake peer ID %d does not match header source %d", response.MyPeerID, packet.Header.FromPeerID)
	}
	return response, nil
}

// RespondLegacyHandshake validates an incoming HandShake packet and sends the
// corresponding response on the same packet channel.
func RespondLegacyHandshake(ctx context.Context, channel PacketChannel, local LegacyIdentity, packet protocol.Packet) (protocol.HandshakeRequest, error) {
	if err := local.Validate(); err != nil {
		return protocol.HandshakeRequest{}, err
	}
	request, err := validateHandshakePacket(packet, local)
	if err != nil {
		return protocol.HandshakeRequest{}, fmt.Errorf("validate handshake request: %w", err)
	}
	if request.MyPeerID != packet.Header.FromPeerID {
		return protocol.HandshakeRequest{}, fmt.Errorf("handshake peer ID %d does not match header source %d", request.MyPeerID, packet.Header.FromPeerID)
	}

	response, err := handshakeRequest(local)
	if err != nil {
		return protocol.HandshakeRequest{}, err
	}
	payload, err := response.Marshal()
	if err != nil {
		return protocol.HandshakeRequest{}, fmt.Errorf("marshal handshake response: %w", err)
	}
	if err := channel.Send(ctx, protocol.Packet{
		Header: protocol.PeerManagerHeader{
			FromPeerID: local.PeerID,
			// Rust legacy handshakes use the default (zero) destination peer ID.
			ToPeerID:   0,
			PacketType: protocol.PacketTypeHandshake,
		},
		Payload: payload,
	}); err != nil {
		return protocol.HandshakeRequest{}, fmt.Errorf("send handshake response: %w", err)
	}
	return request, nil
}

func handshakeRequest(identity LegacyIdentity) (protocol.HandshakeRequest, error) {
	digest := make([]byte, NetworkSecretDigestSize)
	copy(digest, identity.NetworkSecretDigest[:])
	return protocol.HandshakeRequest{
		Magic:               protocol.HandshakeMagic,
		MyPeerID:            identity.PeerID,
		Version:             protocol.HandshakeVersion,
		Features:            identity.Features,
		NetworkName:         identity.NetworkName,
		NetworkSecretDigest: digest,
	}, nil
}

func validateHandshakePacket(packet protocol.Packet, local LegacyIdentity) (protocol.HandshakeRequest, error) {
	if packet.Header.PacketType != protocol.PacketTypeHandshake {
		return protocol.HandshakeRequest{}, fmt.Errorf("packet type %d is not a handshake", packet.Header.PacketType)
	}
	request, err := protocol.ParseHandshakeRequest(packet.Payload)
	if err != nil {
		return protocol.HandshakeRequest{}, err
	}
	if request.Magic != protocol.HandshakeMagic {
		return protocol.HandshakeRequest{}, fmt.Errorf("handshake magic %x is invalid", request.Magic)
	}
	if request.Version != protocol.HandshakeVersion {
		return protocol.HandshakeRequest{}, fmt.Errorf("handshake version %d is unsupported", request.Version)
	}
	if request.NetworkName != local.NetworkName {
		return protocol.HandshakeRequest{}, fmt.Errorf("handshake network %q does not match %q", request.NetworkName, local.NetworkName)
	}
	if len(request.NetworkSecretDigest) != NetworkSecretDigestSize {
		return protocol.HandshakeRequest{}, fmt.Errorf("handshake digest length %d is invalid", len(request.NetworkSecretDigest))
	}
	if subtle.ConstantTimeCompare(request.NetworkSecretDigest, local.NetworkSecretDigest[:]) != 1 {
		return protocol.HandshakeRequest{}, fmt.Errorf("handshake network secret digest does not match")
	}
	return request, nil
}

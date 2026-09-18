// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/flynn/noise"
)

const (
	directHandshakeVersion = 1
	directNetworkNameMax   = 64
	directConnectionIDSize = 16
	directRootKeySize      = 32
	directProofSize        = sha256.Size
)

var directNoisePrologue = []byte("easytier-peerconn-noise")

// AuthenticationLevel describes how the remote peer was authenticated.
type AuthenticationLevel uint8

const (
	// AuthenticationLevelNoiseStatic means Noise authenticated possession of the
	// remote static key, but that key was not pinned by the caller.
	AuthenticationLevelNoiseStatic AuthenticationLevel = iota + 1
	// AuthenticationLevelPinnedStatic means the remote Noise static key matched
	// the caller's configured pin.
	AuthenticationLevelPinnedStatic
	// AuthenticationLevelNetworkSecret means the initiator proved knowledge of
	// the configured network-secret digest.
	AuthenticationLevelNetworkSecret
)

// DirectPeerHandshakeConfig contains the local identity and expected remote
// identity for a direct Noise peer handshake.
type DirectPeerHandshakeConfig struct {
	LocalPeerID         uint32
	NetworkName         string
	NetworkSecret       string
	NetworkSecretDigest [NetworkSecretDigestSize]byte
	StaticKeypair       noise.DHKey
	PinnedRemoteStatic  []byte
	CipherSuite         CipherSuite
	// TrustedCredentialPubkeys lists remote static keys that authenticate as
	// credential (unprivileged) peers instead of admins.
	TrustedCredentialPubkeys [][]byte
}

// GenerateDirectPeerStaticKeypair creates a Curve25519 static keypair suitable
// for DirectPeerHandshakeConfig.
func GenerateDirectPeerStaticKeypair() (noise.DHKey, error) {
	return noise.DH25519.GenerateKeypair(rand.Reader)
}

// InitiateDirectPeerHandshake runs Noise_XX_25519_ChaChaPoly_SHA256 as the
// initiator and returns a session configured for initiator-to-responder TX.
func InitiateDirectPeerHandshake(ctx context.Context, channel PacketChannel, config DirectPeerHandshakeConfig) (*SecureDatagramSession, AuthenticationLevel, PeerIdentity, error) {
	if err := config.validate(); err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	handshake, err := newDirectNoiseHandshake(config, true)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	var initiatorID [directConnectionIDSize]byte
	if _, err := io.ReadFull(rand.Reader, initiatorID[:]); err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("generate initiator connection ID: %w", err)
	}

	message1, _, _, err := handshake.WriteMessage(nil, marshalDirectMsg1(config.NetworkName, initiatorID, config.CipherSuite))
	if err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("write Noise message 1: %w", err)
	}
	if err := sendDirectNoisePacket(ctx, channel, config.LocalPeerID, 0, protocol.PacketTypeNoiseHandshakeMsg1, message1); err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	message1HandshakeHash := append([]byte(nil), handshake.ChannelBinding()...)

	packet, err := receiveDirectNoisePacket(ctx, channel, protocol.PacketTypeNoiseHandshakeMsg2)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	if packet.Header.ToPeerID != config.LocalPeerID || packet.Header.FromPeerID == 0 {
		return nil, 0, PeerIdentityUnknown, errors.New("Noise message 2 peer IDs are invalid")
	}
	message2, _, _, err := handshake.ReadMessage(nil, packet.Payload)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("read Noise message 2: %w", err)
	}
	if err := validatePinnedStatic(config.PinnedRemoteStatic, handshake.PeerStatic()); err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	responderID, rootKey, epoch, responderProof, err := parseDirectMsg2(message2, config.NetworkName, initiatorID)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	if config.NetworkSecret != "" {
		wantProof := networkProof(config.NetworkSecret, message1HandshakeHash)
		if subtle.ConstantTimeCompare(responderProof[:], wantProof[:]) != 1 {
			return nil, 0, PeerIdentityUnknown, errors.New("responder network secret proof does not match")
		}
	}

	proof := networkProof(config.NetworkSecret, handshake.ChannelBinding())
	message3Payload := marshalDirectMsg3WithDigest(initiatorID, responderID, proof[:], config.NetworkSecretDigest[:])
	message3, _, _, err := handshake.WriteMessage(nil, message3Payload)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("write Noise message 3: %w", err)
	}
	if err := sendDirectNoisePacket(ctx, channel, config.LocalPeerID, packet.Header.FromPeerID, protocol.PacketTypeNoiseHandshakeMsg3, message3); err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}

	session, err := NewSecureDatagramSession(rootKey[:], config.CipherSuite, epoch, DirectionInitiatorToResponder, DirectionResponderToInitiator)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("create secure datagram session: %w", err)
	}
	level := directHandshakeLevel(config)
	return session, level, classifyDirectPeerIdentity(config, level, handshake.PeerStatic()), nil
}

// directHandshakeLevel derives the authentication level implied by the
// handshake configuration: a network secret proof outranks a static pin,
// which outranks an unauthenticated Noise exchange.
func directHandshakeLevel(config DirectPeerHandshakeConfig) AuthenticationLevel {
	if config.NetworkSecret != "" {
		return AuthenticationLevelNetworkSecret
	}
	if len(config.PinnedRemoteStatic) != 0 {
		return AuthenticationLevelPinnedStatic
	}
	return AuthenticationLevelNoiseStatic
}

// RespondDirectPeerHandshake runs Noise_XX_25519_ChaChaPoly_SHA256 as the
// responder and returns a session configured for responder-to-initiator TX.
func RespondDirectPeerHandshake(ctx context.Context, channel PacketChannel, config DirectPeerHandshakeConfig) (*SecureDatagramSession, AuthenticationLevel, PeerIdentity, error) {
	if err := config.validate(); err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	handshake, err := newDirectNoiseHandshake(config, false)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}

	packet, err := receiveDirectNoisePacket(ctx, channel, protocol.PacketTypeNoiseHandshakeMsg1)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	if packet.Header.FromPeerID == 0 || packet.Header.ToPeerID != 0 {
		return nil, 0, PeerIdentityUnknown, errors.New("Noise message 1 peer IDs are invalid")
	}
	message1, _, _, err := handshake.ReadMessage(nil, packet.Payload)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("read Noise message 1: %w", err)
	}
	initiatorID, suite, err := parseDirectMsg1(message1, config.NetworkName)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	if suite != config.CipherSuite {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("requested cipher suite %d does not match %d", suite, config.CipherSuite)
	}
	message1HandshakeHash := append([]byte(nil), handshake.ChannelBinding()...)

	var responderID [directConnectionIDSize]byte
	var rootKey [directRootKeySize]byte
	var epochBytes [4]byte
	if _, err := io.ReadFull(rand.Reader, responderID[:]); err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("generate responder connection ID: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, rootKey[:]); err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("generate root key: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, epochBytes[:]); err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("generate initial epoch: %w", err)
	}
	epoch := binary.BigEndian.Uint32(epochBytes[:])
	message2, _, _, err := handshake.WriteMessage(nil, marshalDirectMsg2(config.NetworkName, responderID, initiatorID, rootKey, epoch, networkProof(config.NetworkSecret, message1HandshakeHash)))
	if err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("write Noise message 2: %w", err)
	}
	if err := sendDirectNoisePacket(ctx, channel, config.LocalPeerID, packet.Header.FromPeerID, protocol.PacketTypeNoiseHandshakeMsg2, message2); err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}

	packet, err = receiveDirectNoisePacket(ctx, channel, protocol.PacketTypeNoiseHandshakeMsg3)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	if packet.Header.FromPeerID == 0 || packet.Header.ToPeerID != config.LocalPeerID {
		return nil, 0, PeerIdentityUnknown, errors.New("Noise message 3 peer IDs are invalid")
	}
	handshakeHash := append([]byte(nil), handshake.ChannelBinding()...)
	message3, _, _, err := handshake.ReadMessage(nil, packet.Payload)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("read Noise message 3: %w", err)
	}
	if err := validatePinnedStatic(config.PinnedRemoteStatic, handshake.PeerStatic()); err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	proof, err := parseDirectMsg3(message3, initiatorID, responderID)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, err
	}
	wantProof := networkProof(config.NetworkSecret, handshakeHash)
	// Reference auth matrix (credential -> admin): a remote whose static
	// key is in the admin's trusted credential list authenticates without
	// proving the network secret.
	if config.NetworkSecret != "" && !config.hasTrustedCredentialPubkey(handshake.PeerStatic()) {
		if subtle.ConstantTimeCompare(proof[:], wantProof[:]) != 1 {
			return nil, 0, PeerIdentityUnknown, errors.New("network secret proof does not match")
		}
	}

	session, err := NewSecureDatagramSession(rootKey[:], suite, epoch, DirectionResponderToInitiator, DirectionInitiatorToResponder)
	if err != nil {
		return nil, 0, PeerIdentityUnknown, fmt.Errorf("create secure datagram session: %w", err)
	}
	level := directHandshakeLevel(config)
	return session, level, classifyDirectPeerIdentity(config, level, handshake.PeerStatic()), nil
}

// PeerIdentity classifies the remote role observed at connection level,
// mirroring the reference PeerIdentityType: admins proved the network
// secret, credential peers authenticated a trusted credential key.
type PeerIdentity uint8

const (
	// PeerIdentityUnknown means the connection carried no identity claim.
	PeerIdentityUnknown PeerIdentity = iota
	// PeerIdentityAdmin means the peer proved possession of the network
	// secret (or a key the admin explicitly pinned).
	PeerIdentityAdmin
	// PeerIdentityCredential means the peer authenticated a static key that
	// the admin listed as a trusted credential.
	PeerIdentityCredential
)

// classifyDirectPeerIdentity applies the reference auth matrix: a trusted
// credential key makes the remote a credential peer; a secret proof or an
// admin-pinned key makes it an admin; anything else stays unknown.
func classifyDirectPeerIdentity(config DirectPeerHandshakeConfig, level AuthenticationLevel, peerStatic []byte) PeerIdentity {
	if config.hasTrustedCredentialPubkey(peerStatic) {
		return PeerIdentityCredential
	}
	switch level {
	case AuthenticationLevelNetworkSecret, AuthenticationLevelPinnedStatic:
		return PeerIdentityAdmin
	default:
		return PeerIdentityUnknown
	}
}

// hasTrustedCredentialPubkey reports whether the remote static key is one of
// the configured credential keys.
func (c DirectPeerHandshakeConfig) hasTrustedCredentialPubkey(peerStatic []byte) bool {
	for _, trusted := range c.TrustedCredentialPubkeys {
		if len(trusted) != 0 && bytes.Equal(trusted, peerStatic) {
			return true
		}
	}
	return false
}

func (c DirectPeerHandshakeConfig) validate() error {
	if c.LocalPeerID == 0 {
		return errors.New("local peer ID must not be zero")
	}
	if len(c.NetworkName) == 0 || len(c.NetworkName) > directNetworkNameMax {
		return fmt.Errorf("network name length %d is invalid", len(c.NetworkName))
	}
	if len(c.StaticKeypair.Private) != 32 || len(c.StaticKeypair.Public) != 32 {
		return errors.New("Noise static keypair must contain 32-byte private and public keys")
	}
	if len(c.PinnedRemoteStatic) != 0 && len(c.PinnedRemoteStatic) != 32 {
		return fmt.Errorf("pinned remote static key length %d is invalid", len(c.PinnedRemoteStatic))
	}
	if c.CipherSuite != CipherSuiteAESGCM && c.CipherSuite != CipherSuiteAES256GCM && c.CipherSuite != CipherSuiteChaCha20Poly1305 {
		return fmt.Errorf("unsupported cipher suite %d", c.CipherSuite)
	}
	return nil
}

func newDirectNoiseHandshake(config DirectPeerHandshakeConfig, initiator bool) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeXX,
		Initiator:     initiator,
		Prologue:      directNoisePrologue,
		StaticKeypair: config.StaticKeypair,
	})
}

func sendDirectNoisePacket(ctx context.Context, channel PacketChannel, fromPeerID, toPeerID uint32, packetType uint8, payload []byte) error {
	if err := channel.Send(ctx, protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: fromPeerID, ToPeerID: toPeerID, PacketType: packetType}, Payload: payload}); err != nil {
		return fmt.Errorf("send Noise packet type %d: %w", packetType, err)
	}
	return nil
}

func receiveDirectNoisePacket(ctx context.Context, channel PacketChannel, wantType uint8) (protocol.Packet, error) {
	packet, err := channel.Receive(ctx)
	if err != nil {
		return protocol.Packet{}, fmt.Errorf("receive Noise packet type %d: %w", wantType, err)
	}
	if packet.Header.PacketType != wantType {
		return protocol.Packet{}, fmt.Errorf("Noise packet type %d, want %d", packet.Header.PacketType, wantType)
	}
	return packet, nil
}

func marshalDirectMsg1(networkName string, initiatorID [directConnectionIDSize]byte, suite CipherSuite) []byte {
	return (peerConnNoiseMsg1{Version: directHandshakeVersion, NetworkName: networkName, ConnID: peerUUID(initiatorID), ClientEncryptionAlgorithm: cipherSuiteName(suite)}).marshal()
}

func parseDirectMsg1(payload []byte, expectedNetwork string) ([directConnectionIDSize]byte, CipherSuite, error) {
	var initiatorID [directConnectionIDSize]byte
	m, err := unmarshalPeerMsg1(payload)
	if err != nil {
		return initiatorID, 0, fmt.Errorf("Noise message 1 protobuf invalid: %w", err)
	}
	if m.Version != directHandshakeVersion {
		return initiatorID, 0, fmt.Errorf("Noise message 1 version is invalid: %d", m.Version)
	}
	if len(m.NetworkName) == 0 || len(m.NetworkName) > directNetworkNameMax {
		return initiatorID, 0, errors.New("Noise message 1 length is invalid")
	}
	if m.NetworkName != expectedNetwork {
		return initiatorID, 0, errors.New("Noise message 1 network name does not match")
	}
	copy(initiatorID[:], m.ConnID[:])
	suite, err := cipherSuiteFromName(m.ClientEncryptionAlgorithm)
	if err != nil {
		return initiatorID, 0, err
	}
	return initiatorID, suite, nil
}

func marshalDirectMsg2(networkName string, responderID, initiatorID [directConnectionIDSize]byte, rootKey [directRootKeySize]byte, epoch uint32, proof [directProofSize]byte) []byte {
	return (peerConnNoiseMsg2{NetworkName: networkName, RoleHint: 1, Action: 2, RootKey: rootKey[:], InitialEpoch: epoch, BConnID: peerUUID(responderID), AConnIDEcho: peerUUID(initiatorID), SecretProof: optionalProof(proof[:]), ServerEncryptionAlgorithm: cipherSuiteName(CipherSuiteChaCha20Poly1305)}).marshal()
}

func parseDirectMsg2(payload []byte, expectedNetwork string, wantInitiatorID [directConnectionIDSize]byte) ([directConnectionIDSize]byte, [directRootKeySize]byte, uint32, [directProofSize]byte, error) {
	var responderID [directConnectionIDSize]byte
	var rootKey [directRootKeySize]byte
	var proof [directProofSize]byte
	m, err := unmarshalPeerMsg2(payload)
	if err != nil {
		return responderID, rootKey, 0, proof, errors.New("Noise message 2 length is invalid")
	}
	if m.NetworkName != expectedNetwork {
		return responderID, rootKey, 0, proof, errors.New("Noise message 2 network name does not match")
	}
	copy(responderID[:], m.BConnID[:])
	copy(rootKey[:], m.RootKey)
	if subtle.ConstantTimeCompare(m.AConnIDEcho[:], wantInitiatorID[:]) != 1 {
		return responderID, rootKey, 0, proof, errors.New("Noise message 2 initiator connection ID does not match")
	}
	if isZero(rootKey[:]) {
		return responderID, rootKey, 0, proof, errors.New("Noise message 2 root key is invalid")
	}
	copy(proof[:], m.SecretProof)
	return responderID, rootKey, m.InitialEpoch, proof, nil
}

func marshalDirectMsg3(initiatorID, responderID [directConnectionIDSize]byte, proof [directProofSize]byte) []byte {
	return marshalDirectMsg3WithDigest(initiatorID, responderID, proof[:], make([]byte, directProofSize))
}

func marshalDirectMsg3WithDigest(initiatorID, responderID [directConnectionIDSize]byte, proof, digest []byte) []byte {
	return (peerConnNoiseMsg3{AConnIDEcho: peerUUID(initiatorID), BConnIDEcho: peerUUID(responderID), SecretProof: optionalProof(proof), SecretDigest: digest}).marshal()
}

func parseDirectMsg3(payload []byte, wantInitiatorID, wantResponderID [directConnectionIDSize]byte) ([directProofSize]byte, error) {
	var proof [directProofSize]byte
	m, err := unmarshalPeerMsg3(payload)
	if err != nil {
		return proof, errors.New("Noise message 3 length is invalid")
	}
	if subtle.ConstantTimeCompare(m.AConnIDEcho[:], wantInitiatorID[:]) != 1 {
		return proof, errors.New("Noise message 3 initiator connection ID does not match")
	}
	if subtle.ConstantTimeCompare(m.BConnIDEcho[:], wantResponderID[:]) != 1 {
		return proof, errors.New("Noise message 3 responder connection ID does not match")
	}
	copy(proof[:], m.SecretProof)
	return proof, nil
}

func optionalProof(proof []byte) []byte {
	if isZero(proof) {
		return nil
	}
	return proof
}
func cipherSuiteName(s CipherSuite) string {
	if s == CipherSuiteAESGCM {
		return "aes-gcm"
	}
	if s == CipherSuiteAES256GCM {
		return "aes-256-gcm"
	}
	return "chacha20"
}
func cipherSuiteFromName(name string) (CipherSuite, error) {
	switch name {
	case "aes-gcm":
		return CipherSuiteAESGCM, nil
	case "aes-256-gcm":
		return CipherSuiteAES256GCM, nil
	case "chacha20":
		return CipherSuiteChaCha20Poly1305, nil
	default:
		return 0, fmt.Errorf("cipher suite %q is unsupported", name)
	}
}

func networkProof(networkSecret string, handshakeHash []byte) [directProofSize]byte {
	if networkSecret == "" {
		return [directProofSize]byte{}
	}
	mac := hmac.New(sha256.New, []byte(networkSecret))
	_, _ = mac.Write([]byte("easytier secret proof"))
	_, _ = mac.Write(handshakeHash)
	var proof [directProofSize]byte
	copy(proof[:], mac.Sum(nil))
	return proof
}

func validatePinnedStatic(pinned, remote []byte) error {
	if len(remote) != 32 {
		return errors.New("remote Noise static key is invalid")
	}
	if len(pinned) != 0 && subtle.ConstantTimeCompare(pinned, remote) != 1 {
		return errors.New("remote Noise static key does not match pin")
	}
	return nil
}

func isZero(value []byte) bool {
	var combined byte
	for _, b := range value {
		combined |= b
	}
	return combined == 0
}

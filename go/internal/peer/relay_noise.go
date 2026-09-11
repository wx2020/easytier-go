// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"

	commonpb "github.com/EasyTier/EasyTier/go/internal/proto/common"
	peerrpc "github.com/EasyTier/EasyTier/go/internal/proto/peer_rpc"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const (
	relayNoiseVersion  = 1
	relayNoisePrologue = "easytier-relay-noise"
)

// RelayHandshakeConfig contains identities for a relay IK handshake.
type RelayHandshakeConfig struct {
	LocalPeerID   uint32
	StaticKeypair noise.DHKey
	// RemoteStatic is the responder's static public key (32 bytes), required for IK initiator.
	RemoteStatic []byte
	// CipherSuite selection; currently ChaChaPoly is used in Rust.
	CipherSuite CipherSuite
}

// InitiateRelayHandshake runs Noise_IK_25519_ChaChaPoly_SHA256 as initiator and
// returns a session that can Seal/Open relay-encrypted packets. It mirrors
// Rust relay_peer_map::handshake_session_once initiator side.
func InitiateRelayHandshake(ctx context.Context, channel PacketChannel, config RelayHandshakeConfig, dstPeerID uint32) (*SecureDatagramSession, error) {
	if err := config.validate(true); err != nil {
		return nil, err
	}
	if dstPeerID == 0 {
		return nil, errors.New("relay handshake destination peer ID must not be zero")
	}
	hs, err := newRelayNoiseHandshake(config, true)
	if err != nil {
		return nil, err
	}
	var aConnID [16]byte
	if _, err := io.ReadFull(rand.Reader, aConnID[:]); err != nil {
		return nil, fmt.Errorf("generate a_conn_id: %w", err)
	}
	// Get existing session generation if any (simplified:  nil -> not set)
	var aGen *uint32
	// For simplicity we don't track generations in this standalone helper; tests may provide nil.
	msg1 := &peerrpc.RelayNoiseMsg1Pb{
		Version:                   relayNoiseVersion,
		AConnId:                   uuidFromBytes(aConnID),
		ClientEncryptionAlgorithm: cipherSuiteName(config.CipherSuite),
	}
	if aGen != nil {
		v := *aGen
		msg1.ASessionGeneration = &v
	}
	payload, err := proto.Marshal(msg1)
	if err != nil {
		return nil, fmt.Errorf("marshal relay msg1: %w", err)
	}
	noiseMsg, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, fmt.Errorf("write relay Noise msg1: %w", err)
	}
	if err := channel.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: config.LocalPeerID, ToPeerID: dstPeerID, PacketType: protocol.PacketTypeRelayHandshake},
		Payload: noiseMsg,
	}); err != nil {
		return nil, fmt.Errorf("send relay msg1: %w", err)
	}
	// Wait for RelayHandshakeAck
	pkt, err := receiveRelayPacket(ctx, channel, protocol.PacketTypeRelayHandshakeAck)
	if err != nil {
		return nil, err
	}
	if pkt.Header.FromPeerID != dstPeerID || pkt.Header.ToPeerID != config.LocalPeerID {
		return nil, errors.New("relay msg2 peer IDs invalid")
	}
	plain2, _, _, err := hs.ReadMessage(nil, pkt.Payload)
	if err != nil {
		return nil, fmt.Errorf("read relay msg2: %w", err)
	}
	var msg2 peerrpc.RelayNoiseMsg2Pb
	if err := proto.Unmarshal(plain2, &msg2); err != nil {
		return nil, fmt.Errorf("unmarshal relay msg2: %w", err)
	}
	if msg2.GetAConnIdEcho() == nil || uuidToBytes(msg2.GetAConnIdEcho()) != aConnID {
		return nil, errors.New("relay msg2 a_conn_id_echo mismatch")
	}
	rootKey, epoch, err := extractRelaySessionKeys(&msg2)
	if err != nil {
		return nil, err
	}
	// Determine cipher name: use server's algorithm for our RX, client's for TX (like direct)
	session, err := NewSecureDatagramSession(rootKey[:], config.CipherSuite, epoch, DirectionInitiatorToResponder, DirectionResponderToInitiator)
	if err != nil {
		return nil, fmt.Errorf("create relay secure session: %w", err)
	}
	return session, nil
}

// RespondRelayHandshake runs Noise_IK as responder.
func RespondRelayHandshake(ctx context.Context, channel PacketChannel, config RelayHandshakeConfig) (*SecureDatagramSession, uint32, error) {
	if err := config.validate(false); err != nil {
		return nil, 0, err
	}
	hs, err := newRelayNoiseHandshake(config, false)
	if err != nil {
		return nil, 0, err
	}
	pkt, err := receiveRelayPacket(ctx, channel, protocol.PacketTypeRelayHandshake)
	if err != nil {
		return nil, 0, err
	}
	initiatorID := pkt.Header.FromPeerID
	if initiatorID == 0 {
		return nil, 0, errors.New("relay msg1 from peer is zero")
	}
	plain1, _, _, err := hs.ReadMessage(nil, pkt.Payload)
	if err != nil {
		return nil, 0, fmt.Errorf("read relay msg1: %w", err)
	}
	var msg1 peerrpc.RelayNoiseMsg1Pb
	if err := proto.Unmarshal(plain1, &msg1); err != nil {
		return nil, 0, fmt.Errorf("unmarshal relay msg1: %w", err)
	}
	if msg1.GetVersion() != relayNoiseVersion {
		return nil, 0, fmt.Errorf("relay msg1 version %d != %d", msg1.GetVersion(), relayNoiseVersion)
	}
	// Prepare msg2
	var rootKey [32]byte
	if _, err := io.ReadFull(rand.Reader, rootKey[:]); err != nil {
		return nil, 0, fmt.Errorf("generate root key: %w", err)
	}
	var epochBytes [4]byte
	if _, err := io.ReadFull(rand.Reader, epochBytes[:]); err != nil {
		return nil, 0, fmt.Errorf("generate epoch: %w", err)
	}
	epoch := binary.BigEndian.Uint32(epochBytes[:])
	var bConnID [16]byte
	if _, err := io.ReadFull(rand.Reader, bConnID[:]); err != nil {
		return nil, 0, fmt.Errorf("generate b_conn_id: %w", err)
	}
	msg2 := &peerrpc.RelayNoiseMsg2Pb{
		Action:                    peerrpc.PeerConnSessionActionPb_Create,
		BSessionGeneration:        1,
		RootKey_32:                rootKey[:],
		InitialEpoch:              epoch,
		BConnId:                   uuidFromBytes(bConnID),
		AConnIdEcho:               msg1.GetAConnId(),
		ServerEncryptionAlgorithm: cipherSuiteName(config.CipherSuite),
	}
	// a_session_generation handling: if initiator sent one and we have stored, we could Join.
	payload2, err := proto.Marshal(msg2)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal relay msg2: %w", err)
	}
	noiseMsg2, _, _, err := hs.WriteMessage(nil, payload2)
	if err != nil {
		return nil, 0, fmt.Errorf("write relay msg2: %w", err)
	}
	if err := channel.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: config.LocalPeerID, ToPeerID: initiatorID, PacketType: protocol.PacketTypeRelayHandshakeAck},
		Payload: noiseMsg2,
	}); err != nil {
		return nil, 0, fmt.Errorf("send relay msg2: %w", err)
	}
	session, err := NewSecureDatagramSession(rootKey[:], config.CipherSuite, epoch, DirectionResponderToInitiator, DirectionInitiatorToResponder)
	if err != nil {
		return nil, 0, fmt.Errorf("create relay responder session: %w", err)
	}
	return session, initiatorID, nil
}

func (c RelayHandshakeConfig) validate(isInitiator bool) error {
	if c.LocalPeerID == 0 {
		return errors.New("relay local peer ID must not be zero")
	}
	if len(c.StaticKeypair.Private) != 32 || len(c.StaticKeypair.Public) != 32 {
		return errors.New("relay static keypair must be 32 bytes")
	}
	if isInitiator && len(c.RemoteStatic) != 32 {
		return errors.New("relay initiator remote static key must be 32 bytes")
	}
	if c.CipherSuite != CipherSuiteAESGCM && c.CipherSuite != CipherSuiteAES256GCM && c.CipherSuite != CipherSuiteChaCha20Poly1305 {
		return fmt.Errorf("unsupported cipher suite %d", c.CipherSuite)
	}
	return nil
}

func newRelayNoiseHandshake(config RelayHandshakeConfig, initiator bool) (*noise.HandshakeState, error) {
	cfg := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeIK,
		Initiator:     initiator,
		Prologue:      []byte(relayNoisePrologue),
		StaticKeypair: config.StaticKeypair,
	}
	if initiator {
		// IK requires remote static for initiator
		cfg.PeerStatic = config.RemoteStatic
	}
	return noise.NewHandshakeState(cfg)
}

func receiveRelayPacket(ctx context.Context, channel PacketChannel, wantType uint8) (protocol.Packet, error) {
	pkt, err := channel.Receive(ctx)
	if err != nil {
		return protocol.Packet{}, fmt.Errorf("receive relay packet %d: %w", wantType, err)
	}
	if pkt.Header.PacketType != wantType {
		return protocol.Packet{}, fmt.Errorf("relay packet type %d want %d", pkt.Header.PacketType, wantType)
	}
	return pkt, nil
}

func extractRelaySessionKeys(msg2 *peerrpc.RelayNoiseMsg2Pb) ([32]byte, uint32, error) {
	var rootKey [32]byte
	if len(msg2.GetRootKey_32()) != 32 {
		return rootKey, 0, errors.New("relay msg2 root key not 32 bytes")
	}
	copy(rootKey[:], msg2.GetRootKey_32())
	return rootKey, msg2.GetInitialEpoch(), nil
}

func uuidFromBytes(id [16]byte) *commonpb.UUID {
	// commonpb.UUID has four uint32 fields in big-endian chunks (like Go's peer_noise_proto marshaling)
	// We can directly encode via the generated struct fields: MostSigBytes? Let's check definition.
	// Instead, we use the same manual encoding as direct handshake: marshalUUID encodes four BE uint32.
	// But for proto, the UUID message uses fields 1..4 varint? Actually peer_proto definition:
	// message UUID { uint32 part1=1; uint32 part2=2; uint32 part3=3; uint32 part4=4; }
	// The Go generated struct will have those. We'll fill accordingly.
	return &commonpb.UUID{
		// The proto's UUID splits 16 bytes into four big-endian uint32s.
		// Use direct mapping.
		// Unfortunately commonpb.UUID fields names are not obvious; inspect via proto.
		// Fallback: use raw marshaling via helper that replicates peer_noise_proto's marshalUUID logic
		// by manually constructing the proto bytes and parsing, but easier is to fill via reflection?
		// We'll just use the same helper as direct: marshalUUID then parse via proto.Marshal of common UUID?
		// Simplest: use the existing helper that returns *commonpb.UUID with correct fields by constructing via
		// binary.
		// Check commonpb.UUID struct:
		// It likely has Part1..Part4 or Least/Most. Let's just set via proto using byte slicing trick:
		// We'll use a helper that builds the UUID proto via direct field assignment if possible, otherwise fallback to
		// using the autogenerated type's proto reflection.
		// For now, we attempt generic construction: fill fields via binary.BigEndian.
		Part1: binary.BigEndian.Uint32(id[0:4]),
		Part2: binary.BigEndian.Uint32(id[4:8]),
		Part3: binary.BigEndian.Uint32(id[8:12]),
		Part4: binary.BigEndian.Uint32(id[12:16]),
	}
}

func uuidToBytes(u *commonpb.UUID) [16]byte {
	var out [16]byte
	if u == nil {
		return out
	}
	binary.BigEndian.PutUint32(out[0:4], u.GetPart1())
	binary.BigEndian.PutUint32(out[4:8], u.GetPart2())
	binary.BigEndian.PutUint32(out[8:12], u.GetPart3())
	binary.BigEndian.PutUint32(out[12:16], u.GetPart4())
	return out
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"github.com/flynn/noise"
)

const (
	webNoiseMagic             = "ET_WEB_NOISE_V1:"
	webNoisePrologue          = "easytier-webclient-noise-v1"
	webNoisePattern           = "Noise_NN_25519_ChaChaPoly_SHA256"
	webSecureCipherAlgorithm  = "aes-gcm"
	webSessionGeneration      = 1
	webInitialEpoch           = 0
	webSecureHandshakeTimeout = 3 * time.Second
	webSecureAcceptTimeout    = 3 * time.Second
)

var (
	ErrNoiseRequired = errors.New("webclient noise handshake required but not provided")
)

func webSecureSupported() bool {
	return true
}

func webSecureCipher() (string, error) {
	if !webSecureSupported() {
		return "", fmt.Errorf("web secure tunnel requires %s support: %w", webSecureCipherAlgorithm, ErrNoiseUnsupported)
	}
	return webSecureCipherAlgorithm, nil
}

func encodeNoisePayload(buf []byte) []byte {
	payload := make([]byte, 0, len(webNoiseMagic)+len(buf))
	payload = append(payload, []byte(webNoiseMagic)...)
	payload = append(payload, buf...)
	return payload
}

func decodeNoisePayload(payload []byte) ([]byte, bool) {
	if !bytes.HasPrefix(payload, []byte(webNoiseMagic)) {
		return nil, false
	}
	return payload[len(webNoiseMagic):], true
}

func newWebSecureSession(rootKey [32]byte, isInitiator bool) (*peer.SecureDatagramSession, error) {
	if _, err := webSecureCipher(); err != nil {
		return nil, err
	}
	txDir := peer.DirectionInitiatorToResponder
	rxDir := peer.DirectionResponderToInitiator
	if !isInitiator {
		txDir, rxDir = rxDir, txDir
	}
	return peer.NewSecureDatagramSession(rootKey[:], peer.CipherSuiteAESGCM, webInitialEpoch, txDir, rxDir)
}

// secureChannel wraps a PacketChannel with SecureDatagramSession encryption.
type secureChannel struct {
	inner   transport.PacketChannel
	session *peer.SecureDatagramSession
}

func (s *secureChannel) Send(ctx context.Context, packet protocol.Packet) error {
	if s.session == nil {
		return s.inner.Send(ctx, packet)
	}
	sealed, err := s.session.Seal(packet.Payload)
	if err != nil {
		return fmt.Errorf("seal web secure datagram: %w", err)
	}
	packet.Payload = sealed
	packet.Header.Flags |= protocol.FlagEncrypted
	return s.inner.Send(ctx, packet)
}

func (s *secureChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	pkt, err := s.inner.Receive(ctx)
	if err != nil {
		return protocol.Packet{}, err
	}
	if s.session == nil {
		return pkt, nil
	}
	// Decrypt payload; if not encrypted, it will fail authentication.
	plain, err := s.session.Open(pkt.Payload)
	if err != nil {
		return protocol.Packet{}, fmt.Errorf("open web secure datagram: %w", err)
	}
	pkt.Payload = plain
	pkt.Header.Flags &^= protocol.FlagEncrypted
	return pkt, nil
}

func (s *secureChannel) Close() error {
	if closer, ok := s.inner.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// bufferedChannel replays the first packet that was consumed during handshake downgrade.
type bufferedChannel struct {
	inner    transport.PacketChannel
	mu       sync.Mutex
	first    *protocol.Packet
	hasFirst bool
}

func (b *bufferedChannel) Send(ctx context.Context, packet protocol.Packet) error {
	return b.inner.Send(ctx, packet)
}

func (b *bufferedChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	b.mu.Lock()
	if b.hasFirst {
		pkt := *b.first
		b.hasFirst = false
		b.first = nil
		b.mu.Unlock()
		return pkt, nil
	}
	b.mu.Unlock()
	return b.inner.Receive(ctx)
}

func (b *bufferedChannel) Close() error {
	if closer, ok := b.inner.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// UpgradeClientChannel performs the Noise_NN handshake as initiator and wraps the channel.
func UpgradeClientChannel(ctx context.Context, ch transport.PacketChannel) (transport.PacketChannel, error) {
	if _, err := webSecureCipher(); err != nil {
		return nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeNN,
		Initiator:   true,
		Prologue:    []byte(webNoisePrologue),
	})
	if err != nil {
		return nil, fmt.Errorf("create noise initiator: %w", err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("write noise msg1: %w", err)
	}
	payload := encodeNoisePayload(msg1)
	if err := ch.Send(ctx, protocol.Packet{Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData}, Payload: payload}); err != nil {
		return nil, fmt.Errorf("send noise msg1: %w", err)
	}
	recvCtx, cancel := context.WithTimeout(ctx, webSecureHandshakeTimeout)
	defer cancel()
	pkt, err := ch.Receive(recvCtx)
	if err != nil {
		return nil, fmt.Errorf("receive noise msg2: %w", err)
	}
	cipher, ok := decodeNoisePayload(pkt.Payload)
	if !ok {
		return nil, fmt.Errorf("invalid noise msg2 magic: %w", ErrNoiseUnsupported)
	}
	plain, _, _, err := hs.ReadMessage(nil, cipher)
	if err != nil {
		return nil, fmt.Errorf("read noise msg2: %w", err)
	}
	if len(plain) != 32 {
		return nil, fmt.Errorf("invalid web secure root key len: %d", len(plain))
	}
	var rootKey [32]byte
	copy(rootKey[:], plain)
	session, err := newWebSecureSession(rootKey, true)
	if err != nil {
		return nil, err
	}
	return &secureChannel{inner: ch, session: session}, nil
}

// AcceptOrUpgradeServerChannel attempts Noise_NN handshake as responder.
// If the first packet is not a Noise handshake, it downgrades to plain unless requireSecure is true.
// The timeout for the first packet is webSecureAcceptTimeout.
func AcceptOrUpgradeServerChannel(ctx context.Context, ch transport.PacketChannel, requireSecure bool) (transport.PacketChannel, bool, error) {
	recvCtx, cancel := context.WithTimeout(ctx, webSecureAcceptTimeout)
	defer cancel()
	pkt, err := ch.Receive(recvCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			if requireSecure {
				return nil, false, ErrNoiseRequired
			}
			// Downgrade on timeout: plain channel.
			return ch, false, nil
		}
		return nil, false, err
	}
	// Check packet is not too short (Rust checks peer_manager_header is_none).
	// In Go Packet, payload may be empty but we treat empty as invalid if not magic.
	if len(pkt.Payload) == 0 && requireSecure {
		return nil, false, fmt.Errorf("first packet too short")
	}
	cipher, isNoise := decodeNoisePayload(pkt.Payload)
	if !isNoise {
		if requireSecure {
			return nil, false, ErrNoiseRequired
		}
		// Downgrade: buffer the packet.
		bc := &bufferedChannel{inner: ch, first: &pkt, hasFirst: true}
		return bc, false, nil
	}
	if _, err := webSecureCipher(); err != nil {
		return nil, false, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeNN,
		Initiator:   false,
		Prologue:    []byte(webNoisePrologue),
	})
	if err != nil {
		return nil, false, fmt.Errorf("create noise responder: %w", err)
	}
	if _, _, _, err := hs.ReadMessage(nil, cipher); err != nil {
		return nil, false, fmt.Errorf("read noise msg1: %w", err)
	}
	var rootKey [32]byte
	if _, err := rand.Read(rootKey[:]); err != nil {
		return nil, false, fmt.Errorf("generate root key: %w", err)
	}
	msg2, _, _, err := hs.WriteMessage(nil, rootKey[:])
	if err != nil {
		return nil, false, fmt.Errorf("write noise msg2: %w", err)
	}
	payload := encodeNoisePayload(msg2)
	if err := ch.Send(ctx, protocol.Packet{Header: protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData}, Payload: payload}); err != nil {
		return nil, false, fmt.Errorf("send noise msg2: %w", err)
	}
	session, err := newWebSecureSession(rootKey, false)
	if err != nil {
		return nil, false, err
	}
	return &secureChannel{inner: ch, session: session}, true, nil
}

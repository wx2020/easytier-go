// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package transport WireGuard data-plane encryption.
//
// Rust reference: easytier/src/tunnel/wireguard.rs (boringtun Tunn).
// Rust derives both sides' static X25519 keys from the network identity
// digest (WgConfig::new_from_network_identity) and lets boringtun run the
// Noise_IKpsk2 handshake plus the ChaCha20-Poly1305 transport.
//
// The Go core keeps the existing WGService framing (20-byte synthetic IPv4
// header + peer body) and adds a real authenticated data plane here:
// X25519 static-static ECDH -> HKDF-SHA256 epoch keys ->
// ChaCha20-Poly1305 transport packets with key rotation and replay
// protection. The portal asymmetric mode (server/client seeds) is supported
// through DeriveWGKeyPairForPortal.
package transport

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const (
	// wgCryptoVersion is the data-plane wire version.
	wgCryptoVersion = 1
	// wgCryptoTypeData mirrors WireGuard's message type 4 (transport data).
	wgCryptoTypeData = 4
	// wgCryptoHeaderSize = type(1) + version(1) + epoch(4) + nonce(12).
	wgCryptoHeaderSize = 1 + 1 + 4 + 12
	// wgCryptoOverhead is the AEAD tag size.
	wgCryptoOverhead = 16
	// wgCryptoMaxPayload bounds one sealed transport packet.
	wgCryptoMaxPayload = protocol.UDPMaxPayloadSize + 256
	// wgCryptoRekeyAfterPackets rotates the epoch key after this many sends.
	wgCryptoRekeyAfterPackets = 1 << 20
	// wgCryptoRekeyAfter bounds the epoch lifetime.
	wgCryptoRekeyAfter = 120 * time.Second
	// wgCryptoPrevKeyOverlap keeps the previous epoch key for decrypting
	// in-flight packets after a rotation.
	wgCryptoPrevKeyOverlap = 5 * time.Second
	// wgCryptoReplayWindow is the sliding replay window in packets.
	wgCryptoReplayWindow = 1024
)

// WgCryptoConfig holds the static key material for one WG crypto endpoint.
// For mesh (InternalUse) both sides derive the same pair from the network
// identity; for portal (ExternalUse) server and client use distinct seeds.
type WgCryptoConfig struct {
	Private    [32]byte
	PeerPublic [32]byte
}

// NewWgCryptoConfigFromNetworkIdentity mirrors
// WgConfig::new_from_network_identity: both ends share one digest-derived
// keypair, so the peer public key is the local public key.
func NewWgCryptoConfigFromNetworkIdentity(networkName, networkSecret string) (WgCryptoConfig, error) {
	pair, err := protocol.DeriveWGKeyPair(networkName, networkSecret)
	if err != nil {
		return WgCryptoConfig{}, err
	}
	return WgCryptoConfig{Private: pair.Private, PeerPublic: pair.Public}, nil
}

// NewWgCryptoConfigForPortal mirrors WgConfig::new_for_portal. isServer
// selects the server or client seed.
func NewWgCryptoConfigForPortal(networkName, networkSecret string, isServer bool) (WgCryptoConfig, error) {
	server, client, err := protocol.DeriveWGKeyPairForPortal(networkName, networkSecret)
	if err != nil {
		return WgCryptoConfig{}, err
	}
	if isServer {
		return WgCryptoConfig{Private: server.Private, PeerPublic: client.Public}, nil
	}
	return WgCryptoConfig{Private: client.Private, PeerPublic: server.Public}, nil
}

// wgEpochKey is one AEAD key plus its validity window.
type wgEpochKey struct {
	aead      cipher.AEAD
	epoch     uint32
	createdAt time.Time
}

// WgCryptoState encrypts and decrypts WG transport payloads with automatic
// epoch rotation and replay protection.
type WgCryptoState struct {
	master []byte

	// established is when the current key material became valid: state
	// creation for the static-key epochs, or the last adopted handshake.
	// Keys past REJECT_AFTER_TIME are refused on both paths until the
	// session rekeys.
	established time.Time

	mu          sync.Mutex
	sendEpoch   uint32
	sendCount   uint64
	sendKey     *wgEpochKey
	prevKey     *wgEpochKey
	recvKeys    map[uint32]*wgEpochKey
	recvHighest uint64
	recvSeen    map[uint64]struct{}
	recvWindow  []uint64
}

// NewWgCryptoState runs X25519 ECDH(private, peerPublic) and expands the
// shared secret with HKDF-SHA256 into the epoch-0 master key.
func NewWgCryptoState(cfg WgCryptoConfig) (*WgCryptoState, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(cfg.Private[:])
	if err != nil {
		return nil, fmt.Errorf("wg crypto private key: %w", err)
	}
	pub, err := curve.NewPublicKey(cfg.PeerPublic[:])
	if err != nil {
		return nil, fmt.Errorf("wg crypto peer public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("wg crypto ECDH: %w", err)
	}
	master := make([]byte, 32)
	h := hkdf.New(sha256.New, shared, nil, []byte("easytier-wg-v1/data-master"))
	if _, err := fullRead(h, master); err != nil {
		return nil, fmt.Errorf("wg crypto master key: %w", err)
	}
	state := &WgCryptoState{
		master:      master,
		established: time.Now(),
		recvKeys:    make(map[uint32]*wgEpochKey),
		recvSeen:    make(map[uint64]struct{}),
	}
	key, err := state.epochKey(0)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	state.sendKey = &wgEpochKey{aead: key, epoch: 0, createdAt: now}
	state.recvKeys[0] = &wgEpochKey{aead: key, epoch: 0, createdAt: now}
	return state, nil
}

func (s *WgCryptoState) epochKey(epoch uint32) (cipher.AEAD, error) {
	var epochLE [4]byte
	binary.LittleEndian.PutUint32(epochLE[:], epoch)
	key := make([]byte, 32)
	h := hkdf.New(sha256.New, s.master, epochLE[:], []byte("easytier-wg-v1/epoch"))
	if _, err := fullRead(h, key); err != nil {
		return nil, fmt.Errorf("wg crypto epoch key: %w", err)
	}
	return chacha20poly1305.New(key)
}

func (s *WgCryptoState) ensureSendKey(now time.Time) error {
	key := s.sendKey
	if key != nil && s.sendCount < wgCryptoRekeyAfterPackets && now.Sub(key.createdAt) < wgCryptoRekeyAfter {
		return nil
	}
	var next uint32
	if key != nil {
		next = key.epoch + 1
	}
	aead, err := s.epochKey(next)
	if err != nil {
		return err
	}
	if key != nil {
		s.prevKey = key
	}
	s.sendKey = &wgEpochKey{aead: aead, epoch: next, createdAt: now}
	s.recvKeys[next] = &wgEpochKey{aead: aead, epoch: next, createdAt: now}
	s.sendCount = 0
	return nil
}

func (s *WgCryptoState) pruneKeys(now time.Time) {
	for epoch, key := range s.recvKeys {
		if s.sendKey != nil && epoch == s.sendKey.epoch {
			continue
		}
		if s.prevKey != nil && epoch == s.prevKey.epoch && now.Sub(key.createdAt) < wgCryptoPrevKeyOverlap {
			continue
		}
		if now.Sub(key.createdAt) > wgCryptoRekeyAfter+wgCryptoPrevKeyOverlap {
			delete(s.recvKeys, epoch)
		}
	}
	if s.prevKey != nil && now.Sub(s.prevKey.createdAt) > wgCryptoRekeyAfter+wgCryptoPrevKeyOverlap {
		s.prevKey = nil
	}
}

// isExpired reports whether the current key material is past
// REJECT_AFTER_TIME since it was established.
func (s *WgCryptoState) isExpired(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Sub(s.established) >= wgRejectAfterTime
}

// sessionEstablishedAt reports when the current key material was
// established (state creation or the last adopted handshake).
func (s *WgCryptoState) sessionEstablishedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.established
}

// Seal encrypts plaintext (typically a marshaled peer body) into one
// transport datagram: type(1) version(1) epoch(4LE) nonce(12) ciphertext.
func (s *WgCryptoState) Seal(plaintext []byte) ([]byte, error) {
	if len(plaintext) > wgCryptoMaxPayload {
		return nil, fmt.Errorf("wg crypto plaintext %d exceeds limit", len(plaintext))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.established) >= wgRejectAfterTime {
		return nil, ErrWGSessionExpired
	}
	if err := s.ensureSendKey(now); err != nil {
		return nil, err
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("wg crypto nonce: %w", err)
	}
	out := make([]byte, 0, wgCryptoHeaderSize+len(plaintext)+wgCryptoOverhead)
	out = append(out, wgCryptoTypeData, wgCryptoVersion)
	var epochLE [4]byte
	binary.LittleEndian.PutUint32(epochLE[:], s.sendKey.epoch)
	out = append(out, epochLE[:]...)
	out = append(out, nonce[:]...)
	out = s.sendKey.aead.Seal(out, nonce[:], plaintext, out[:6])
	s.sendCount++
	s.pruneKeys(now)
	return out, nil
}

// Open authenticates and decrypts one transport datagram. It enforces the
// epoch key, the AEAD tag, and a sliding replay window over a sequence
// number carried as the first 8 bytes of the plaintext.
func (s *WgCryptoState) Open(datagram []byte) ([]byte, error) {
	if len(datagram) < wgCryptoHeaderSize+8+wgCryptoOverhead {
		return nil, errors.New("wg crypto datagram is truncated")
	}
	if datagram[0] != wgCryptoTypeData {
		return nil, fmt.Errorf("wg crypto type %d is not data", datagram[0])
	}
	if datagram[1] != wgCryptoVersion {
		return nil, fmt.Errorf("wg crypto version %d is unsupported", datagram[1])
	}
	epoch := binary.LittleEndian.Uint32(datagram[2:6])
	var nonce [12]byte
	copy(nonce[:], datagram[6:18])
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.established) >= wgRejectAfterTime {
		return nil, ErrWGSessionExpired
	}
	key := s.recvKeys[epoch]
	if key == nil {
		if s.prevKey != nil && s.prevKey.epoch == epoch {
			key = s.prevKey
		} else {
			return nil, fmt.Errorf("wg crypto epoch %d has no key", epoch)
		}
	}
	plaintext, err := key.aead.Open(nil, nonce[:], datagram[wgCryptoHeaderSize:], datagram[:6])
	if err != nil {
		return nil, fmt.Errorf("wg crypto open: %w", err)
	}
	if len(plaintext) < 8 {
		return nil, errors.New("wg crypto plaintext is missing its sequence")
	}
	seq := binary.BigEndian.Uint64(plaintext[:8])
	if !s.noteSequence(seq) {
		return nil, errors.New("wg crypto replay rejected")
	}
	s.pruneKeys(time.Now())
	out := make([]byte, len(plaintext)-8)
	copy(out, plaintext[8:])
	return out, nil
}

// SealSequenced prepends an 8-byte big-endian sequence to plaintext before
// sealing so Open can enforce replay protection.
func (s *WgCryptoState) SealSequenced(seq uint64, plaintext []byte) ([]byte, error) {
	buffer := make([]byte, 8+len(plaintext))
	binary.BigEndian.PutUint64(buffer[:8], seq)
	copy(buffer[8:], plaintext)
	return s.Seal(buffer)
}

func (s *WgCryptoState) noteSequence(seq uint64) bool {
	if _, dup := s.recvSeen[seq]; dup {
		return false
	}
	if s.recvHighest != 0 && seq+wgCryptoReplayWindow < s.recvHighest {
		return false
	}
	s.recvSeen[seq] = struct{}{}
	s.recvWindow = append(s.recvWindow, seq)
	if seq > s.recvHighest {
		s.recvHighest = seq
	}
	if len(s.recvWindow) > wgCryptoReplayWindow*2 {
		for _, old := range s.recvWindow[:wgCryptoReplayWindow] {
			delete(s.recvSeen, old)
		}
		s.recvWindow = append([]uint64(nil), s.recvWindow[wgCryptoReplayWindow:]...)
	}
	return true
}

// SendEpoch reports the current sending epoch (for tests and metrics).
func (s *WgCryptoState) SendEpoch() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendKey == nil {
		return 0
	}
	return s.sendKey.epoch
}

// SealPeerPacket marshals packet and seals it for the WG data plane.
func (s *WgCryptoState) SealPeerPacket(seq uint64, packet interface {
	MarshalBody() ([]byte, error)
}) ([]byte, error) {
	body, err := packet.MarshalBody()
	if err != nil {
		return nil, err
	}
	return s.SealSequenced(seq, body)
}

func fullRead(h interface{ Read([]byte) (int, error) }, out []byte) (int, error) {
	total := 0
	for total < len(out) {
		n, err := h.Read(out[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

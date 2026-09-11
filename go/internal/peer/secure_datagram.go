// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	secureDatagramNonceSize = 12
	secureDatagramTagSize   = 16
	replayWindowSize        = 256
	previousEpochMaxIdle    = 30 * time.Second
	maxAESGCMPlaintext      = uint64((1<<32 - 2) * aes.BlockSize)
	maxChaChaPlaintext      = uint64(1<<38 - 64)
)

// CipherSuite selects the AEAD used by a SecureDatagramSession.
type CipherSuite uint8

const (
	CipherSuiteAESGCM CipherSuite = iota + 1
	CipherSuiteAES256GCM
	CipherSuiteChaCha20Poly1305
)

// Direction identifies one half of a peer session. Peers must configure
// opposite TX and RX directions.
const (
	DirectionInitiatorToResponder byte = iota
	DirectionResponderToInitiator
)

// SecureDatagramSession protects datagrams for one peer-session direction.
// It does not perform key agreement; rootKey must already be shared.
type SecureDatagramSession struct {
	rootKey     []byte
	suite       CipherSuite
	txDirection byte
	rxDirection byte

	mu          sync.Mutex
	txEpoch     uint32
	txSequence  uint64
	txExhausted bool
	rxCurrent   replayEpoch
	rxPrevious  *replayEpoch
	now         func() time.Time
}

type replayEpoch struct {
	epoch  uint32
	window replayWindow
	lastRX time.Time
}

// NewSecureDatagramSession creates a session at initialEpoch. Sequence
// counters start at zero, and the initial receive epoch has an empty window.
func NewSecureDatagramSession(rootKey []byte, suite CipherSuite, initialEpoch uint32, txDirection, rxDirection byte) (*SecureDatagramSession, error) {
	return newSecureDatagramSession(rootKey, suite, initialEpoch, txDirection, rxDirection, time.Now)
}

func newSecureDatagramSession(rootKey []byte, suite CipherSuite, initialEpoch uint32, txDirection, rxDirection byte, now func() time.Time) (*SecureDatagramSession, error) {
	if len(rootKey) == 0 {
		return nil, errors.New("root key is required")
	}
	if suite != CipherSuiteAESGCM && suite != CipherSuiteAES256GCM && suite != CipherSuiteChaCha20Poly1305 {
		return nil, fmt.Errorf("unsupported cipher suite %d", suite)
	}
	if !validDirection(txDirection) || !validDirection(rxDirection) || txDirection == rxDirection {
		return nil, fmt.Errorf("secure datagram directions must be opposite protocol directions")
	}
	if now == nil {
		return nil, errors.New("secure datagram clock is nil")
	}
	return &SecureDatagramSession{
		rootKey:     append([]byte(nil), rootKey...),
		suite:       suite,
		txDirection: txDirection,
		rxDirection: rxDirection,
		txEpoch:     initialEpoch,
		rxCurrent:   replayEpoch{epoch: initialEpoch, lastRX: now()},
		now:         now,
	}, nil
}

// Seal encrypts plaintext. Its wire format is ciphertext || tag16 || nonce12,
// where nonce is epoch (big endian) followed by sequence (big endian).
func (s *SecureDatagramSession) Seal(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.txExhausted {
		return nil, errors.New("transmit sequence exhausted")
	}
	if uint64(len(plaintext)) > maxPlaintextSize(s.suite) {
		return nil, errors.New("plaintext is too large")
	}

	var nonce [secureDatagramNonceSize]byte
	binary.BigEndian.PutUint32(nonce[:4], s.txEpoch)
	binary.BigEndian.PutUint64(nonce[4:], s.txSequence)
	aead, err := s.aead(s.txEpoch, s.txDirection)
	if err != nil {
		return nil, err
	}
	packet := aead.Seal(nil, nonce[:], plaintext, nil)
	packet = append(packet, nonce[:]...)
	if s.txSequence == math.MaxUint64 {
		s.txExhausted = true
	} else {
		s.txSequence++
	}
	return packet, nil
}

// Open authenticates and decrypts one wire-format datagram. Only the current
// receive epoch and its immediately preceding epoch are accepted.
func (s *SecureDatagramSession) Open(packet []byte) ([]byte, error) {
	if len(packet) < secureDatagramNonceSize+secureDatagramTagSize {
		return nil, errors.New("secure datagram is too short")
	}
	nonceOffset := len(packet) - secureDatagramNonceSize
	nonce := packet[nonceOffset:]
	epoch := binary.BigEndian.Uint32(nonce[:4])
	sequence := binary.BigEndian.Uint64(nonce[4:])

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expirePreviousLocked(now)
	state := &s.rxCurrent
	promote := false
	if epoch != state.epoch {
		if epoch == state.epoch+1 && state.epoch != math.MaxUint32 {
			state = &replayEpoch{epoch: epoch, lastRX: now}
			promote = true
		} else if s.rxPrevious != nil && epoch == s.rxPrevious.epoch {
			state = s.rxPrevious
		} else {
			return nil, fmt.Errorf("receive epoch %d is not current or previous", epoch)
		}
	}
	if state.window.rejected(sequence) {
		return nil, errors.New("replayed or expired secure datagram")
	}
	aead, err := s.aead(epoch, s.rxDirection)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, packet[:nonceOffset], nil)
	if err != nil {
		return nil, errors.New("secure datagram authentication failed")
	}
	state.window.accept(sequence)
	state.lastRX = now
	if promote {
		previous := s.rxCurrent
		s.rxPrevious = &previous
		s.rxCurrent = *state
	}
	return plaintext, nil
}

// RotateTXEpoch advances the transmit epoch by one and resets its sequence.
func (s *SecureDatagramSession) RotateTXEpoch() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.txEpoch == math.MaxUint32 {
		return errors.New("transmit epoch exhausted")
	}
	s.txEpoch++
	s.txSequence = 0
	s.txExhausted = false
	return nil
}

// RotateRXEpoch advances the receive epoch by one. Datagrams from the prior
// epoch remain valid subject to their own replay window.
func (s *SecureDatagramSession) RotateRXEpoch() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rxCurrent.epoch == math.MaxUint32 {
		return errors.New("receive epoch exhausted")
	}
	previous := s.rxCurrent
	s.rxPrevious = &previous
	s.rxCurrent = replayEpoch{epoch: previous.epoch + 1, lastRX: s.now()}
	return nil
}

func (s *SecureDatagramSession) aead(epoch uint32, direction byte) (cipher.AEAD, error) {
	key := trafficKey(s.rootKey, epoch, direction)
	switch s.suite {
	case CipherSuiteAESGCM:
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case CipherSuiteAES256GCM:
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case CipherSuiteChaCha20Poly1305:
		return chacha20poly1305.New(key[:])
	default:
		return nil, fmt.Errorf("unsupported cipher suite %d", s.suite)
	}
}

func trafficKey(rootKey []byte, epoch uint32, direction byte) [32]byte {
	prkMac := hmac.New(sha256.New, make([]byte, sha256.Size))
	_, _ = prkMac.Write(rootKey)
	prk := prkMac.Sum(nil)
	info := make([]byte, 0, len("et-traffic")+4+2)
	info = append(info, "et-traffic"...)
	var epochBytes [4]byte
	binary.BigEndian.PutUint32(epochBytes[:], epoch)
	info = append(info, epochBytes[:]...)
	info = append(info, direction, 0x01)
	keyMac := hmac.New(sha256.New, prk)
	_, _ = keyMac.Write(info)
	var key [32]byte
	copy(key[:], keyMac.Sum(nil))
	return key
}

func (s *SecureDatagramSession) expirePreviousLocked(now time.Time) {
	if s.rxPrevious != nil && now.Sub(s.rxPrevious.lastRX) > previousEpochMaxIdle {
		s.rxPrevious = nil
	}
}

func validDirection(direction byte) bool {
	return direction == DirectionInitiatorToResponder || direction == DirectionResponderToInitiator
}

func maxPlaintextSize(suite CipherSuite) uint64 {
	if suite == CipherSuiteChaCha20Poly1305 {
		return maxChaChaPlaintext
	}
	return maxAESGCMPlaintext
}

type replayWindow struct {
	initialized bool
	highest     uint64
	bits        [replayWindowSize / 64]uint64
}

func (w *replayWindow) rejected(sequence uint64) bool {
	if !w.initialized || sequence > w.highest {
		return false
	}
	delta := w.highest - sequence
	if delta >= replayWindowSize {
		return true
	}
	return w.bits[delta/64]&(uint64(1)<<(delta%64)) != 0
}

func (w *replayWindow) accept(sequence uint64) {
	if !w.initialized {
		w.initialized = true
		w.highest = sequence
		w.bits[0] = 1
		return
	}
	if sequence > w.highest {
		shiftReplayBits(&w.bits, sequence-w.highest)
		w.highest = sequence
		w.bits[0] |= 1
		return
	}
	delta := w.highest - sequence
	w.bits[delta/64] |= uint64(1) << (delta % 64)
}

func shiftReplayBits(bits *[replayWindowSize / 64]uint64, shift uint64) {
	if shift >= replayWindowSize {
		*bits = [replayWindowSize / 64]uint64{}
		return
	}
	words, offset := shift/64, shift%64
	var shifted [replayWindowSize / 64]uint64
	for index := len(bits) - 1; index >= 0; index-- {
		if uint64(index) < words {
			continue
		}
		shifted[index] = bits[uint64(index)-words] << offset
		if offset != 0 && uint64(index) > words {
			shifted[index] |= bits[uint64(index)-words-1] >> (64 - offset)
		}
	}
	*bits = shifted
}

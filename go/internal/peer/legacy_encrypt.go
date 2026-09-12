// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// StandardAeadTailSize is the size of the reference AEAD traffic tail:
// authentication tag (16 bytes) followed by the nonce (12 bytes).
const StandardAeadTailSize = 16 + 12

var (
	ErrLegacyPacketTooShort    = errors.New("legacy encrypted packet is too short")
	ErrLegacyDecryptionFailed  = errors.New("legacy decryption failed")
	ErrLegacyEncryptionFailed  = errors.New("legacy encryption failed")
	ErrLegacyXorEmptyKey       = errors.New("legacy xor key must not be empty")
	ErrLegacyUnsupportedScheme = errors.New("legacy cipher scheme not available")
)

// LegacyCipher applies the reference global traffic encryption to peer
// packets. Every peer in a network derives the same keys from the shared
// network secret, so no key exchange happens on the wire; the encrypted flag
// in the peer header marks transformed payloads.
type LegacyCipher interface {
	Encrypt(packet *protocol.Packet) error
	Decrypt(packet *protocol.Packet) error
}

// NullLegacyCipher mirrors the reference behaviour when encryption is
// disabled: outbound packets pass through untouched, while inbound packets
// claiming to be encrypted are rejected.
type NullLegacyCipher struct{}

// Encrypt implements LegacyCipher.
func (NullLegacyCipher) Encrypt(_ *protocol.Packet) error { return nil }

// Decrypt implements LegacyCipher.
func (NullLegacyCipher) Decrypt(packet *protocol.Packet) error {
	if packet != nil && packet.Header.IsEncrypted() {
		return ErrLegacyDecryptionFailed
	}
	return nil
}

// XorLegacyCipher XORs the payload with the repeating 128-bit network key.
// The transform is symmetric and does not extend the payload.
type XorLegacyCipher struct {
	key []byte
}

// NewXorLegacyCipher builds the repeating-key XOR cipher.
func NewXorLegacyCipher(key []byte) (*XorLegacyCipher, error) {
	if len(key) == 0 {
		return nil, ErrLegacyXorEmptyKey
	}
	return &XorLegacyCipher{key: append([]byte(nil), key...)}, nil
}

func (c *XorLegacyCipher) apply(packet *protocol.Packet) {
	for i := range packet.Payload {
		packet.Payload[i] ^= c.key[i%len(c.key)]
	}
}

// Encrypt implements LegacyCipher.
func (c *XorLegacyCipher) Encrypt(packet *protocol.Packet) error {
	if packet == nil || packet.Header.IsEncrypted() {
		return nil
	}
	c.apply(packet)
	packet.Header.SetEncrypted(true)
	return nil
}

// Decrypt implements LegacyCipher.
func (c *XorLegacyCipher) Decrypt(packet *protocol.Packet) error {
	if packet == nil || !packet.Header.IsEncrypted() {
		return nil
	}
	c.apply(packet)
	packet.Header.SetEncrypted(false)
	return nil
}

// AeadLegacyCipher seals packets with an AEAD (AES-GCM or ChaCha20-Poly1305)
// using the wire tail ciphertext || tag[16] || nonce[12] and no associated
// data. Nonces are random per packet.
type AeadLegacyCipher struct {
	aead   cipher.AEAD
	random bool
}

// NewAesGcmLegacyCipher builds the reference aes-gcm (AES-128-GCM) cipher.
func NewAesGcmLegacyCipher(key128 [16]byte) (*AeadLegacyCipher, error) {
	block, err := aes.NewCipher(key128[:])
	if err != nil {
		return nil, fmt.Errorf("create aes-gcm cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create aes-gcm gcm: %w", err)
	}
	return &AeadLegacyCipher{aead: aead, random: true}, nil
}

// NewAes256GcmLegacyCipher builds the reference aes-256-gcm cipher.
func NewAes256GcmLegacyCipher(key256 [32]byte) (*AeadLegacyCipher, error) {
	block, err := aes.NewCipher(key256[:])
	if err != nil {
		return nil, fmt.Errorf("create aes-256-gcm cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create aes-256-gcm gcm: %w", err)
	}
	return &AeadLegacyCipher{aead: aead, random: true}, nil
}

// NewChaCha20LegacyCipher builds the reference chacha20 (ChaCha20-Poly1305)
// cipher.
func NewChaCha20LegacyCipher(key256 [32]byte) (*AeadLegacyCipher, error) {
	aead, err := chacha20poly1305.New(key256[:])
	if err != nil {
		return nil, fmt.Errorf("create chacha20 cipher: %w", err)
	}
	return &AeadLegacyCipher{aead: aead, random: true}, nil
}

// Encrypt implements LegacyCipher.
func (c *AeadLegacyCipher) Encrypt(packet *protocol.Packet) error {
	if packet == nil || packet.Header.IsEncrypted() {
		return nil
	}
	var nonce [12]byte
	if c.random {
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("generate legacy nonce: %w", err)
		}
	}
	return c.encryptWithNonce(packet, nonce)
}

func (c *AeadLegacyCipher) encryptWithNonce(packet *protocol.Packet, nonce [12]byte) error {
	if c.aead.NonceSize() != len(nonce) {
		return ErrLegacyEncryptionFailed
	}
	sealed := c.aead.Seal(nil, nonce[:], packet.Payload, nil)
	if len(sealed) != len(packet.Payload)+c.aead.Overhead() {
		return ErrLegacyEncryptionFailed
	}
	packet.Payload = append(sealed, nonce[:]...)
	packet.Header.SetEncrypted(true)
	return nil
}

// Decrypt implements LegacyCipher.
func (c *AeadLegacyCipher) Decrypt(packet *protocol.Packet) error {
	if packet == nil || !packet.Header.IsEncrypted() {
		return nil
	}
	payload := packet.Payload
	if len(payload) < StandardAeadTailSize {
		return ErrLegacyPacketTooShort
	}
	body := payload[:len(payload)-12]
	nonce := payload[len(payload)-12:]
	plaintext, err := c.aead.Open(nil, nonce, body, nil)
	if err != nil {
		return ErrLegacyDecryptionFailed
	}
	packet.Payload = plaintext
	packet.Header.SetEncrypted(false)
	if !packet.Header.IsCompressed() {
		packet.Header.Length = uint32(len(plaintext))
	}
	return nil
}

// NewLegacyCipher selects the reference global encryption scheme by config
// name. Unknown names fall back to the reference default (aes-gcm).
func NewLegacyCipher(algorithm string, key128 [16]byte, key256 [32]byte) (LegacyCipher, error) {
	switch algorithm {
	case "xor":
		return NewXorLegacyCipher(key128[:])
	case "aes-gcm", "":
		return NewAesGcmLegacyCipher(key128)
	case "aes-256-gcm":
		return NewAes256GcmLegacyCipher(key256)
	case "chacha20":
		return NewChaCha20LegacyCipher(key256)
	default:
		return NewAesGcmLegacyCipher(key128)
	}
}

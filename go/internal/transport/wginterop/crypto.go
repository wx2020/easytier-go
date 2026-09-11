// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package wginterop

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

func newBlake2s256() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

// hashWriter aliases hash.Hash for hmac constructors.
type hashWriter = hash.Hash

// TAI64N base: 2^62 + 37 seconds, matching boringtun TimeStamper.
const tai64Base uint64 = (1 << 62) + 37

// hash2 is boringtun b2s_hash: BLAKE2s-256(data1 || data2).
func hash2(data1, data2 []byte) [32]byte {
	h, _ := blake2s.New256(nil)
	h.Write(data1)
	h.Write(data2)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hmac1 is boringtun b2s_hmac: HMAC-BLAKE2s-256 (not keyed BLAKE2s).
func hmac1(key, data1 []byte) [32]byte {
	m := hmac.New(func() hashWriter { return newBlake2s256() }, key)
	m.Write(data1)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// hmac2 is boringtun b2s_hmac2.
func hmac2(key, data1, data2 []byte) [32]byte {
	m := hmac.New(func() hashWriter { return newBlake2s256() }, key)
	m.Write(data1)
	m.Write(data2)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// mac16 is boringtun b2s_keyed_mac_16: keyed BLAKE2s truncated to 16.
func mac16(key, data []byte) [16]byte {
	h, _ := blake2s.New128(key)
	h.Write(data)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// mac16x2 is boringtun b2s_keyed_mac_16_2.
func mac16x2(key, data1, data2 []byte) [16]byte {
	h, _ := blake2s.New128(key)
	h.Write(data1)
	h.Write(data2)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// mac24 is boringtun b2s_mac_24: keyed BLAKE2s-256 truncated to 24.
func mac24(key, data []byte) [24]byte {
	h, _ := blake2s.New256(key)
	h.Write(data)
	var out [24]byte
	copy(out[:], h.Sum(nil)[:24])
	return out
}

// sealAEAD seals plaintext with ChaCha20-Poly1305, nonce = 0x0*4 || LE64(counter).
func sealAEAD(dst, key []byte, counter uint64, plaintext, aad []byte) []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(dst, nonce[:], plaintext, aad)
}

// openAEAD opens in place semantics: returns plaintext or ErrInvalidTag.
func openAEAD(key []byte, counter uint64, data, aad []byte) ([]byte, error) {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	plaintext, err := aead.Open(nil, nonce[:], data, aad)
	if err != nil {
		return nil, ErrInvalidTag
	}
	return plaintext, nil
}

// verifyEqual is constant-time comparison for MACs/keys.
func verifyEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// tai64Now stamps current time like boringtun TimeStamper.
func tai64Now() [12]byte {
	now := time.Now()
	var out [12]byte
	binary.BigEndian.PutUint64(out[:8], uint64(now.Unix())+tai64Base)
	binary.BigEndian.PutUint32(out[8:], uint32(now.Nanosecond()))
	return out
}

// tai64After reports whether stamp is strictly after other.
func tai64After(stamp, other [12]byte) bool {
	secs := binary.BigEndian.Uint64(stamp[:8])
	otherSecs := binary.BigEndian.Uint64(other[:8])
	if secs != otherSecs {
		return secs > otherSecs
	}
	return binary.BigEndian.Uint32(stamp[8:]) > binary.BigEndian.Uint32(other[8:])
}

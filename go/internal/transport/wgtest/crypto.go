// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package wgtest

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

func newBLAKE() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

func newHMAC(key []byte) hash.Hash { return hmac.New(newBLAKE, key) }

func hmac2BLAKE(key, d1, d2 []byte) [32]byte {
	h := newHMAC(key)
	h.Write(d1)
	h.Write(d2)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func keyedMAC16(key, data []byte) [16]byte {
	h, _ := blake2s.New128(key)
	h.Write(data)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func sealCounter(key []byte, counter uint64, plaintext, aad []byte) []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, nonce[:], plaintext, aad)
}

func openCounter(key []byte, counter uint64, data, aad []byte) ([]byte, error) {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead.Open(nil, nonce[:], data, aad)
}

func initialChainKey() [32]byte {
	return [32]byte{
		96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208,
		22, 235, 66, 6, 248, 114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
	}
}

func initialChainHash() [32]byte {
	return [32]byte{
		34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50,
		45, 156, 108, 102, 34, 147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
	}
}

func tai64Now() [12]byte {
	now := time.Now()
	var out [12]byte
	binary.BigEndian.PutUint64(out[:8], uint64(now.Unix())+(1<<62)+37)
	binary.BigEndian.PutUint32(out[8:], uint32(now.Nanosecond()))
	return out
}

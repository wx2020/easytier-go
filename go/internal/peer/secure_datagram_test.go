// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestSecureDatagramAESGCMWireVector(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x42}, 32)
	const epoch uint32 = 0x10203040
	plaintext := []byte("independently constructed AES-GCM datagram")
	session, err := NewSecureDatagramSession(rootKey, CipherSuiteAES256GCM, epoch, DirectionInitiatorToResponder, DirectionResponderToInitiator)
	if err != nil {
		t.Fatal(err)
	}

	got, err := session.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	key := referenceTrafficKey(rootKey, epoch, DirectionInitiatorToResponder)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[:4], epoch)
	// The first emitted datagram has sequence zero.
	want := aead.Seal(nil, nonce[:], plaintext, nil)
	want = append(want, nonce[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire datagram = %x, want independently constructed %x", got, want)
	}
}

func TestSecureDatagramAES128UsesRustDefaultKeySize(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x42}, 32)
	session, err := NewSecureDatagramSession(rootKey, CipherSuiteAESGCM, 0, DirectionInitiatorToResponder, DirectionResponderToInitiator)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := session.Seal([]byte("aes-128"))
	if err != nil {
		t.Fatal(err)
	}
	key := referenceTrafficKey(rootKey, 0, DirectionInitiatorToResponder)
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte
	want := aead.Seal(nil, nonce[:], []byte("aes-128"), nil)
	want = append(want, nonce[:]...)
	if !bytes.Equal(packet, want) {
		t.Fatalf("AES-128 wire packet = %x, want %x", packet, want)
	}
}

func TestChaCha20Poly1305RFC8439Vector(t *testing.T) {
	key := [32]byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f}
	nonce := []byte{0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47}
	aad := []byte{0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7}
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}
	got := aead.Seal(nil, nonce, plaintext, aad)
	// RFC 8439, section 2.8.2, independently confirms the ciphertext prefix
	// and complete 16-byte tag.
	wantPrefix := []byte{0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2}
	wantTag := []byte{0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91}
	if !bytes.Equal(got[:len(wantPrefix)], wantPrefix) || !bytes.Equal(got[len(got)-secureDatagramTagSize:], wantTag) {
		t.Fatalf("RFC 8439 ciphertext and tag = %x", got)
	}
	got, err = aead.Open(nil, nonce, got, aad)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("RFC 8439 Open() = %q, %v", got, err)
	}
}

func TestSecureDatagramChaCha20Poly1305RoundTrip(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x24}, 32)
	tx, err := NewSecureDatagramSession(rootKey, CipherSuiteChaCha20Poly1305, 7, DirectionInitiatorToResponder, DirectionResponderToInitiator)
	if err != nil {
		t.Fatal(err)
	}
	rx, err := NewSecureDatagramSession(rootKey, CipherSuiteChaCha20Poly1305, 7, DirectionResponderToInitiator, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := tx.Seal([]byte("chacha session payload"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := rx.Open(packet)
	if err != nil || string(got) != "chacha session payload" {
		t.Fatalf("Open() = %q, %v", got, err)
	}
}

func TestSecureDatagramRejectsTamperAndReplay(t *testing.T) {
	tx, rx := testSessionPair(t, CipherSuiteAESGCM, 11)
	packet, err := tx.Seal([]byte("authenticated"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), packet...)
	tampered[0] ^= 0x80
	if _, err := rx.Open(tampered); err == nil {
		t.Fatal("Open(tampered) succeeded")
	}
	if got, err := rx.Open(packet); err != nil || string(got) != "authenticated" {
		t.Fatalf("Open(packet) = %q, %v", got, err)
	}
	if _, err := rx.Open(packet); err == nil {
		t.Fatal("Open(replay) succeeded")
	}
}

func TestSecureDatagramAcceptsReorderingWithinReplayWindow(t *testing.T) {
	tx, rx := testSessionPair(t, CipherSuiteAESGCM, 3)
	packets := make([][]byte, 3)
	for i := range packets {
		var err error
		packets[i], err = tx.Seal([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, index := range []int{2, 0, 1} {
		got, err := rx.Open(packets[index])
		if err != nil || len(got) != 1 || got[0] != byte(index) {
			t.Fatalf("Open(packet %d) = %x, %v", index, got, err)
		}
	}
	if _, err := rx.Open(packets[0]); err == nil {
		t.Fatal("Open(duplicate reordered packet) succeeded")
	}

	for i := 0; i < replayWindowSize; i++ {
		packet, err := tx.Seal([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rx.Open(packet); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := rx.Open(packets[1]); err == nil {
		t.Fatal("Open(expired packet) succeeded")
	}
}

func TestSecureDatagramEpochAcceptance(t *testing.T) {
	tx, rx := testSessionPair(t, CipherSuiteAESGCM, 41)
	previous, err := tx.Seal([]byte("previous epoch"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.RotateTXEpoch(); err != nil {
		t.Fatal(err)
	}
	current, err := tx.Seal([]byte("current epoch"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rx.Open(current); err != nil || string(got) != "current epoch" {
		t.Fatalf("Open(current epoch) = %q, %v", got, err)
	}
	if got, err := rx.Open(previous); err != nil || string(got) != "previous epoch" {
		t.Fatalf("Open(previous epoch) = %q, %v", got, err)
	}
	if err := tx.RotateTXEpoch(); err != nil {
		t.Fatal(err)
	}
	newest, err := tx.Seal([]byte("newest epoch"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rx.Open(newest); err != nil {
		t.Fatal(err)
	}
	if _, err := rx.Open(previous); err == nil {
		t.Fatal("Open(two epochs old) succeeded")
	}
}

func TestSecureDatagramRejectsSameDirections(t *testing.T) {
	if _, err := NewSecureDatagramSession([]byte("key"), CipherSuiteAESGCM, 0, DirectionInitiatorToResponder, DirectionInitiatorToResponder); err == nil {
		t.Fatal("same directions were accepted")
	}
}

func TestSecureDatagramExpiresPreviousEpoch(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	root := bytes.Repeat([]byte{1}, 32)
	tx, err := newSecureDatagramSession(root, CipherSuiteAESGCM, 0, DirectionInitiatorToResponder, DirectionResponderToInitiator, clock)
	if err != nil {
		t.Fatal(err)
	}
	rx, err := newSecureDatagramSession(root, CipherSuiteAESGCM, 0, DirectionResponderToInitiator, DirectionInitiatorToResponder, clock)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := tx.Seal([]byte("previous"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.RotateTXEpoch(); err != nil {
		t.Fatal(err)
	}
	current, err := tx.Seal([]byte("current"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rx.Open(current); err != nil {
		t.Fatal(err)
	}
	now = now.Add(previousEpochMaxIdle + time.Second)
	if _, err := rx.Open(previous); err == nil {
		t.Fatal("expired previous epoch was accepted")
	}
}

func testSessionPair(t *testing.T, suite CipherSuite, epoch uint32) (*SecureDatagramSession, *SecureDatagramSession) {
	t.Helper()
	rootKey := bytes.Repeat([]byte{0x5a}, 32)
	tx, err := NewSecureDatagramSession(rootKey, suite, epoch, DirectionInitiatorToResponder, DirectionResponderToInitiator)
	if err != nil {
		t.Fatal(err)
	}
	rx, err := NewSecureDatagramSession(rootKey, suite, epoch, DirectionResponderToInitiator, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	return tx, rx
}

func referenceTrafficKey(rootKey []byte, epoch uint32, direction byte) [32]byte {
	prk := hmac.New(sha256.New, make([]byte, 32))
	_, _ = prk.Write(rootKey)
	extract := prk.Sum(nil)
	expand := hmac.New(sha256.New, extract)
	_, _ = expand.Write([]byte("et-traffic"))
	var epochBytes [4]byte
	binary.BigEndian.PutUint32(epochBytes[:], epoch)
	_, _ = expand.Write(epochBytes[:])
	_, _ = expand.Write([]byte{direction, 0x01})
	var key [32]byte
	copy(key[:], expand.Sum(nil))
	return key
}

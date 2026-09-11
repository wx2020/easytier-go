// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package wginterop

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/transport/wgtest"
	"golang.org/x/crypto/chacha20poly1305"
)

// RFC 7539 ChaCha20-Poly1305 vector, copied from boringtun
// noise/handshake.rs chacha20_seal_rfc7530_test_vector.
func TestChaChaSealRFCVector(t *testing.T) {
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	aad := []byte{0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7}
	key := []byte{
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
		0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
		0x9c, 0x9d, 0x9e, 0x9f,
	}
	var nonce [12]byte
	copy(nonce[:], []byte{0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47})
	sealed := sealAEADCounter(key, nonce, plaintext, aad)
	wantCT := []byte{
		0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
		0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
		0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
		0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
		0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
		0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
		0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
		0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
		0x61, 0x16,
	}
	wantTag := []byte{
		0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
		0x06, 0x91,
	}
	if !bytes.Equal(sealed[:len(plaintext)], wantCT) {
		t.Fatal("ciphertext mismatch")
	}
	if !bytes.Equal(sealed[len(plaintext):], wantTag) {
		t.Fatal("tag mismatch")
	}
}

func TestInitialChainConstants(t *testing.T) {
	// Transcription guard against boringtun noise/handshake.rs.
	wantKey := "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"
	wantHash := "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"
	if got := bytesToHex(initialChainKey[:]); got != wantKey {
		t.Fatalf("chain key = %s", got)
	}
	if got := bytesToHex(initialChainHash[:]); got != wantHash {
		t.Fatalf("chain hash = %s", got)
	}
}

func TestPythonOracleVectors(t *testing.T) {
	// Independent oracle: Python hashlib/hmac.
	hmacVector := hmac1([]byte("key"), []byte("The quick brown fox jumps over the lazy dog"))
	if got := bytesToHex(hmacVector[:]); got != "f93215bb90d4af4c3061cd932fb169fb8bb8a91d0b4022baea1271e1323cd9a0" {
		t.Fatalf("hmac = %s", got)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	m := mac16(key, []byte(" WireGuard MAC test "))
	if got := bytesToHex(m[:]); got != "6f22675a4daf7f5b1a34b6f8573101a7" {
		t.Fatalf("mac16 = %s", got)
	}
}

// Replay bitmap vector, ported statement-by-statement from boringtun
// noise/session.rs test_replay_counter.
func TestReplayCounterVector(t *testing.T) {
	s := NewSession(1, 2, [32]byte{1}, [32]byte{2})
	mustAccept := func(counter uint64) {
		t.Helper()
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.willAccept(counter); err != nil {
			t.Fatalf("willAccept(%d): %v", counter, err)
		}
		if err := s.markReceived(counter); err != nil {
			t.Fatalf("markReceived(%d): %v", counter, err)
		}
	}
	mustReject := func(counter uint64) {
		t.Helper()
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.markReceived(counter); err == nil {
			t.Fatalf("markReceived(%d) must fail", counter)
		}
	}
	mustAccept(0)
	mustReject(0)
	mustAccept(1)
	mustReject(1)
	mustAccept(63)
	mustReject(63)
	mustAccept(15)
	mustReject(15)
	for i := uint64(64); i < replayNBits+128; i++ {
		mustAccept(i)
		mustReject(i)
	}
	s.mu.Lock()
	if err := s.markReceived(replayNBits * 3); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	for i := uint64(0); i <= replayNBits*2; i++ {
		s.mu.Lock()
		acceptErr := s.willAccept(i)
		markErr := s.markReceived(i)
		s.mu.Unlock()
		if acceptErr == nil || markErr == nil {
			t.Fatalf("counter %d must be too old", i)
		}
	}
}

func TestResponderHandshakeRoundTrip(t *testing.T) {
	var initPriv, respPriv [32]byte
	if _, err := randRead(initPriv[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := randRead(respPriv[:]); err != nil {
		t.Fatal(err)
	}
	respPub, err := x25519Public(respPriv)
	if err != nil {
		t.Fatal(err)
	}
	initPub, err := x25519Public(initPriv)
	if err != nil {
		t.Fatal(err)
	}
	tunn, err := NewTunn(respPriv, initPub, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := wgtest.New(initPriv, respPub)
	if err != nil {
		t.Fatal(err)
	}
	init, err := initiator.BuildInit()
	if err != nil {
		t.Fatal(err)
	}
	result := tunn.HandleDatagram(nil, init)
	if result.Kind != KindNetwork || len(result.ToNetwork) != HandshakeRespSize {
		t.Fatalf("result = %+v", result.Kind)
	}
	if err := initiator.OpenResponse(result.ToNetwork); err != nil {
		t.Fatal(err)
	}

	// Data initiator -> responder.
	sealed := initiator.Seal([]byte("stock-hello"))
	result = tunn.HandleDatagram(nil, sealed)
	if result.Kind != KindTunnel || string(result.ToTunnel) != "stock-hello" {
		t.Fatalf("tunnel = %q kind = %v", result.ToTunnel, result.Kind)
	}
	// Data responder -> initiator.
	back, ok := tunn.SealData([]byte("stock-world"))
	if !ok {
		t.Fatal("no session to seal with")
	}
	got, err := initiator.Open(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "stock-world" {
		t.Fatalf("back = %q", got)
	}
	// Replay of the same data packet must fail.
	if res := tunn.HandleDatagram(nil, sealed); res.Kind != KindError {
		t.Fatal("replayed data must be rejected")
	}
}

func TestResponderRejects(t *testing.T) {
	var initPriv, respPriv [32]byte
	if _, err := randRead(initPriv[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := randRead(respPriv[:]); err != nil {
		t.Fatal(err)
	}
	respPub, err := x25519Public(respPriv)
	if err != nil {
		t.Fatal(err)
	}
	initPub, err := x25519Public(initPriv)
	if err != nil {
		t.Fatal(err)
	}
	newTunn := func() *Tunn {
		t.Helper()
		tunn, err := NewTunn(respPriv, initPub, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		return tunn
	}
	initiator, err := wgtest.New(initPriv, respPub)
	if err != nil {
		t.Fatal(err)
	}
	good, err := initiator.BuildInit()
	if err != nil {
		t.Fatal(err)
	}

	bad := append([]byte(nil), good...)
	bad[50] ^= 0xff
	if res := newTunn().HandleDatagram(nil, bad); res.Kind != KindError {
		t.Fatal("tampered init must be rejected")
	}
	short := good[:100]
	if res := newTunn().HandleDatagram(nil, short); res.Kind != KindError {
		t.Fatal("truncated init must be rejected")
	}
	wrongMac := append([]byte(nil), good...)
	for i := 116; i < 132; i++ {
		wrongMac[i] ^= 0x01
	}
	if res := newTunn().HandleDatagram(nil, wrongMac); res.Kind != KindError {
		t.Fatal("bad mac1 must be rejected")
	}
	// Timestamp replay: same initiation twice.
	tunn := newTunn()
	if res := tunn.HandleDatagram(nil, good); res.Kind != KindNetwork {
		t.Fatalf("first init kind = %v", res.Kind)
	}
	if res := tunn.HandleDatagram(nil, good); res.Kind != KindError {
		t.Fatal("replayed timestamp must be rejected")
	}
	// Unknown data session.
	data := make([]byte, DataHeaderSize+16)
	binary.LittleEndian.PutUint32(data[0:4], MsgTypeData)
	binary.LittleEndian.PutUint32(data[4:8], 0xdead)
	if res := tunn.HandleDatagram(nil, data); res.Kind != KindError {
		t.Fatal("unknown session data must be rejected")
	}
}

func TestCookieUnderLoad(t *testing.T) {
	var initPriv, respPriv [32]byte
	if _, err := randRead(initPriv[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := randRead(respPriv[:]); err != nil {
		t.Fatal(err)
	}
	respPub, _ := x25519Public(respPriv)
	initPub, _ := x25519Public(initPriv)
	tunn, err := NewTunn(respPriv, initPub, 1)
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := wgtest.New(initPriv, respPub)
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.BuildInit()
	if err != nil {
		t.Fatal(err)
	}
	if res := tunn.HandleDatagram(loopbackIP(), first); res.Kind != KindNetwork || len(res.ToNetwork) != HandshakeRespSize {
		t.Fatalf("first init under fresh limiter kind = %v", res.Kind)
	}
	second, err := initiator.BuildInit()
	if err != nil {
		t.Fatal(err)
	}
	res := tunn.HandleDatagram(loopbackIP(), second)
	if res.Kind != KindNetwork || len(res.ToNetwork) != CookieReplySize {
		t.Fatalf("loaded limiter must emit cookie reply, kind = %v len = %d", res.Kind, len(res.ToNetwork))
	}
	if binary.LittleEndian.Uint32(res.ToNetwork[0:4]) != MsgTypeCookieReply {
		t.Fatal("cookie reply type wrong")
	}
	if got := binary.LittleEndian.Uint32(res.ToNetwork[4:8]); got != binary.LittleEndian.Uint32(second[4:8]) {
		t.Fatal("cookie reply must echo the sender index")
	}
}

func sealAEADCounter(key []byte, nonce [12]byte, plaintext, aad []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, nonce[:], plaintext, aad)
}

func bytesToHex(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		out = append(out, digits[b>>4], digits[b&0xf])
	}
	return string(out)
}

func randRead(data []byte) (int, error) { return rand.Read(data) }

func loopbackIP() net.IP { return net.ParseIP("127.0.0.1") }

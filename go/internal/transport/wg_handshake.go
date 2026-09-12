// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// WireGuard-style Noise handshake for the WG crypto data plane.
//
// Rust reference: easytier/src/tunnel/wireguard.rs via boringtun
// (Noise_IKpsk2 handshake + ChaCha20-Poly1305 transport). This file
// implements the handshake message exchange between EasyTier-native
// endpoints: an ephemeral X25519 exchange authenticated by the pre-shared
// static identity keys, yielding a session key with forward secrecy that
// WgCryptoState adopts (see AdoptSessionKey).
//
// Wire format (all integers little-endian unless noted):
//
//	HsInit: type(1)=1 ver(1) senderIdx(4) ePub(32) box(56)
//	HsResp: type(2)=2 ver(1) senderIdx(4) rPub(32) box(52)
//
// The init box seals (initiatorStaticPub || unixSeconds BE) under a key
// derived from the static-static shared secret and the ephemeral public
// key. The response box seals (responderStaticPub || senderIdx) under a
// key derived from the static secret and both ephemeral keys. The session
// key mixes the static secret with DH1 (ephemeral-initiator × static
// responder) and DH2 (ephemeral-responder × static-initiator), so both
// ephemeral compromises and later static compromises preserve secrecy of
// recorded traffic.
package transport

import (
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
)

const (
	wgHsVersion  = 1
	wgHsTypeInit = 1
	wgHsTypeResp = 2

	wgHsInitSize = 1 + 1 + 4 + 32 + 56
	wgHsRespSize = 1 + 1 + 4 + 32 + 52

	// wgHsMaxSkew bounds the initiator timestamp error.
	wgHsMaxSkew = 300 * time.Second
	// wgHsReplayCache caps remembered initiator ephemeral keys.
	wgHsReplayCache = 1024
)

// WgHandshakeKeys is the outcome of a completed handshake.
type WgHandshakeKeys struct {
	// SessionKey seeds fresh epoch keys on both sides.
	SessionKey [32]byte
	// PeerStatic is the authenticated remote static public key.
	PeerStatic [32]byte
}

func wgCurve() ecdh.Curve { return ecdh.X25519() }

func ecdhShared(priv, pub [32]byte) ([32]byte, error) {
	curve := wgCurve()
	privateKey, err := curve.NewPrivateKey(priv[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("wg handshake private key: %w", err)
	}
	publicKey, err := curve.NewPublicKey(pub[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("wg handshake public key: %w", err)
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("wg handshake ECDH: %w", err)
	}
	var out [32]byte
	copy(out[:], shared)
	return out, nil
}

func generateEphemeral() (priv, pub [32]byte, err error) {
	key, err := wgCurve().GenerateKey(rand.Reader)
	if err != nil {
		return priv, pub, fmt.Errorf("wg handshake ephemeral key: %w", err)
	}
	copy(priv[:], key.Bytes())
	copy(pub[:], key.PublicKey().Bytes())
	return priv, pub, nil
}

func wgPublicKey(priv [32]byte) ([32]byte, error) {
	key, err := wgCurve().NewPrivateKey(priv[:])
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], key.PublicKey().Bytes())
	return out, nil
}

func hkdf32(secret, salt, info []byte) ([32]byte, error) {
	var out [32]byte
	h := hkdf.New(sha256.New, secret, salt, info)
	if _, err := fullRead(h, out[:]); err != nil {
		return out, err
	}
	return out, nil
}

// staticShared derives the long-term shared secret for cfg.
func staticShared(cfg WgCryptoConfig) ([32]byte, error) {
	return ecdhShared(cfg.Private, cfg.PeerPublic)
}

// BuildHsInit creates one handshake initiation for cfg. It returns the
// datagram, the sender index to match the response, and the ephemeral
// secret needed to complete the handshake.
func BuildHsInit(cfg WgCryptoConfig, senderIdx uint32) (datagram []byte, ePriv [32]byte, err error) {
	shared, err := staticShared(cfg)
	if err != nil {
		return nil, ePriv, err
	}
	ePriv, ePub, err := generateEphemeral()
	if err != nil {
		return nil, ePriv, err
	}
	boxKeyRaw, err := hkdf32(shared[:], ePub[:], []byte("easytier-wg-v1/hs-init"))
	if err != nil {
		return nil, ePriv, err
	}
	boxAEAD, err := chacha20poly1305.New(boxKeyRaw[:])
	if err != nil {
		return nil, ePriv, err
	}
	myPub, err := wgPublicKey(cfg.Private)
	if err != nil {
		return nil, ePriv, err
	}
	plaintext := make([]byte, 40)
	copy(plaintext[:32], myPub[:])
	binary.BigEndian.PutUint64(plaintext[32:40], uint64(time.Now().Unix()))
	var nonce [12]byte
	copy(nonce[:4], ePub[:4])
	sealed := boxAEAD.Seal(nil, nonce[:], plaintext, ePub[:])
	datagram = make([]byte, 0, wgHsInitSize)
	datagram = append(datagram, wgHsTypeInit, wgHsVersion)
	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], senderIdx)
	datagram = append(datagram, idx[:]...)
	datagram = append(datagram, ePub[:]...)
	datagram = append(datagram, sealed...)
	return datagram, ePriv, nil
}

// hsInitData is a parsed initiation.
type hsInitData struct {
	senderIdx uint32
	ePub      [32]byte
	sealed    []byte
}

// ParseHsInit validates framing of one initiation datagram.
func ParseHsInit(datagram []byte) (hsInitData, error) {
	if len(datagram) != wgHsInitSize {
		return hsInitData{}, fmt.Errorf("wg handshake init size %d, want %d", len(datagram), wgHsInitSize)
	}
	if datagram[0] != wgHsTypeInit {
		return hsInitData{}, fmt.Errorf("wg handshake type %d is not init", datagram[0])
	}
	if datagram[1] != wgHsVersion {
		return hsInitData{}, fmt.Errorf("wg handshake version %d unsupported", datagram[1])
	}
	var init hsInitData
	init.senderIdx = binary.LittleEndian.Uint32(datagram[2:6])
	copy(init.ePub[:], datagram[6:38])
	init.sealed = datagram[38:]
	return init, nil
}

// hsRespData is a parsed response.
type hsRespData struct {
	senderIdx uint32
	rPub      [32]byte
	sealed    []byte
}

// ParseHsResp validates framing of one response datagram.
func ParseHsResp(datagram []byte) (hsRespData, error) {
	if len(datagram) != wgHsRespSize {
		return hsRespData{}, fmt.Errorf("wg handshake response size %d, want %d", len(datagram), wgHsRespSize)
	}
	if datagram[0] != wgHsTypeResp {
		return hsRespData{}, fmt.Errorf("wg handshake type %d is not response", datagram[0])
	}
	if datagram[1] != wgHsVersion {
		return hsRespData{}, fmt.Errorf("wg handshake version %d unsupported", datagram[1])
	}
	var resp hsRespData
	resp.senderIdx = binary.LittleEndian.Uint32(datagram[2:6])
	copy(resp.rPub[:], datagram[6:38])
	resp.sealed = datagram[38:]
	return resp, nil
}

// WgHandshakeResponder answers initiations for cfg with replay and
// timestamp protection.
type WgHandshakeResponder struct {
	cfg WgCryptoConfig

	mu   sync.Mutex
	seen map[[32]byte]time.Time
}

// NewWgHandshakeResponder creates a responder bound to cfg.
func NewWgHandshakeResponder(cfg WgCryptoConfig) *WgHandshakeResponder {
	return &WgHandshakeResponder{cfg: cfg, seen: make(map[[32]byte]time.Time)}
}

// Respond authenticates init and builds the response datagram plus the
// agreed session keys.
func (r *WgHandshakeResponder) Respond(init hsInitData) (respDatagram []byte, keys WgHandshakeKeys, err error) {
	shared, err := staticShared(r.cfg)
	if err != nil {
		return nil, keys, err
	}
	r.mu.Lock()
	if _, dup := r.seen[init.ePub]; dup {
		r.mu.Unlock()
		return nil, keys, errors.New("wg handshake initiation replayed")
	}
	if len(r.seen) >= wgHsReplayCache {
		for key := range r.seen {
			delete(r.seen, key)
			break
		}
	}
	r.seen[init.ePub] = time.Now()
	r.mu.Unlock()

	boxKeyRaw, err := hkdf32(shared[:], init.ePub[:], []byte("easytier-wg-v1/hs-init"))
	if err != nil {
		return nil, keys, err
	}
	boxAEAD, err := chacha20poly1305.New(boxKeyRaw[:])
	if err != nil {
		return nil, keys, err
	}
	var nonce [12]byte
	copy(nonce[:4], init.ePub[:4])
	plaintext, err := boxAEAD.Open(nil, nonce[:], init.sealed, init.ePub[:])
	if err != nil || len(plaintext) != 40 {
		return nil, keys, errors.New("wg handshake initiation authentication failed")
	}
	var initiatorPub [32]byte
	copy(initiatorPub[:], plaintext[:32])
	if initiatorPub != r.cfg.PeerPublic {
		return nil, keys, errors.New("wg handshake initiator is not the pinned peer")
	}
	sentAt := time.Unix(int64(binary.BigEndian.Uint64(plaintext[32:40])), 0)
	if delta := time.Since(sentAt); delta > wgHsMaxSkew || delta < -wgHsMaxSkew {
		return nil, keys, errors.New("wg handshake initiation timestamp out of range")
	}

	rPriv, rPub, err := generateEphemeral()
	if err != nil {
		return nil, keys, err
	}
	dh1, err := ecdhShared(r.cfg.Private, init.ePub)
	if err != nil {
		return nil, keys, err
	}
	dh2, err := ecdhShared(rPriv, initiatorPub)
	if err != nil {
		return nil, keys, err
	}
	sessionKey, err := wgSessionKey(shared, dh1, dh2, init.ePub, rPub)
	if err != nil {
		return nil, keys, err
	}
	respKeyRaw, err := hkdf32(shared[:], append(append([]byte(nil), init.ePub[:]...), rPub[:]...), []byte("easytier-wg-v1/hs-resp"))
	if err != nil {
		return nil, keys, err
	}
	respAEAD, err := chacha20poly1305.New(respKeyRaw[:])
	if err != nil {
		return nil, keys, err
	}
	myPub, err := wgPublicKey(r.cfg.Private)
	if err != nil {
		return nil, keys, err
	}
	respPlain := make([]byte, 36)
	copy(respPlain[:32], myPub[:])
	binary.LittleEndian.PutUint32(respPlain[32:36], init.senderIdx)
	var respNonce [12]byte
	copy(respNonce[:4], rPub[:4])
	sealed := respAEAD.Seal(nil, respNonce[:], respPlain, rPub[:])
	respDatagram = make([]byte, 0, wgHsRespSize)
	respDatagram = append(respDatagram, wgHsTypeResp, wgHsVersion)
	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], init.senderIdx)
	respDatagram = append(respDatagram, idx[:]...)
	respDatagram = append(respDatagram, rPub[:]...)
	respDatagram = append(respDatagram, sealed...)
	keys = WgHandshakeKeys{SessionKey: sessionKey, PeerStatic: initiatorPub}
	return respDatagram, keys, nil
}

// CompleteInit processes a response to an initiation built by BuildHsInit.
func CompleteInit(cfg WgCryptoConfig, ePriv [32]byte, senderIdx uint32, resp hsRespData) (WgHandshakeKeys, error) {
	var keys WgHandshakeKeys
	if resp.senderIdx != senderIdx {
		return keys, errors.New("wg handshake response index mismatch")
	}
	shared, err := staticShared(cfg)
	if err != nil {
		return keys, err
	}
	ePub, err := wgPublicKey(ePriv)
	if err != nil {
		return keys, err
	}
	respKeyRaw, err := hkdf32(shared[:], append(append([]byte(nil), ePub[:]...), resp.rPub[:]...), []byte("easytier-wg-v1/hs-resp"))
	if err != nil {
		return keys, err
	}
	respAEAD, err := chacha20poly1305.New(respKeyRaw[:])
	if err != nil {
		return keys, err
	}
	var respNonce [12]byte
	copy(respNonce[:4], resp.rPub[:4])
	plaintext, err := respAEAD.Open(nil, respNonce[:], resp.sealed, resp.rPub[:])
	if err != nil || len(plaintext) != 36 {
		return keys, errors.New("wg handshake response authentication failed")
	}
	var responderPub [32]byte
	copy(responderPub[:], plaintext[:32])
	if responderPub != cfg.PeerPublic {
		return keys, errors.New("wg handshake responder is not the pinned peer")
	}
	if binary.LittleEndian.Uint32(plaintext[32:36]) != senderIdx {
		return keys, errors.New("wg handshake response echoes wrong index")
	}
	dh1, err := ecdhShared(ePriv, cfg.PeerPublic)
	if err != nil {
		return keys, err
	}
	dh2, err := ecdhShared(cfg.Private, resp.rPub)
	if err != nil {
		return keys, err
	}
	sessionKey, err := wgSessionKey(shared, dh1, dh2, ePub, resp.rPub)
	if err != nil {
		return keys, err
	}
	keys = WgHandshakeKeys{SessionKey: sessionKey, PeerStatic: responderPub}
	return keys, nil
}

func wgSessionKey(staticShared, dh1, dh2 [32]byte, ePub, rPub [32]byte) ([32]byte, error) {
	secret := make([]byte, 0, 96)
	secret = append(secret, staticShared[:]...)
	secret = append(secret, dh1[:]...)
	secret = append(secret, dh2[:]...)
	salt := make([]byte, 0, 64)
	salt = append(salt, ePub[:]...)
	salt = append(salt, rPub[:]...)
	return hkdf32(secret, salt, []byte("easytier-wg-v1/session"))
}

// AdoptSessionKey reseeds the data plane with a handshaked session key,
// giving forward secrecy over the static identity keys. Epoch numbering
// continues monotonically and the replay window restarts for the new key.
// The REJECT_AFTER_TIME expiry window restarts with the new material.
func (s *WgCryptoState) AdoptSessionKey(key [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.master = append([]byte(nil), key[:]...)
	s.established = time.Now()
	var next uint32 = 1
	if s.sendKey != nil {
		next = s.sendKey.epoch + 1
	}
	aead, err := s.epochKey(next)
	if err != nil {
		return
	}
	now := time.Now()
	if s.sendKey != nil {
		s.prevKey = s.sendKey
	}
	s.sendKey = &wgEpochKey{aead: aead, epoch: next, createdAt: now}
	s.recvKeys[next] = &wgEpochKey{aead: aead, epoch: next, createdAt: now}
	s.sendCount = 0
	s.recvSeen = make(map[uint64]struct{})
	s.recvWindow = nil
	s.recvHighest = 0
	s.pruneKeys(now)
}

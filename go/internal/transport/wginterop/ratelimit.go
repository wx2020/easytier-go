// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package wginterop

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Rate limiter constants, matching boringtun noise/rate_limiter.rs.
const (
	cookieRefreshSeconds = 128
	resetPeriodSeconds   = 1
)

// RateLimiter gates handshake processing under load, mirroring boringtun
// noise/rate_limiter.rs: MAC1 is always verified; when the per-second
// packet count exceeds limit, MAC2 (cookie) is required and a cookie reply
// is emitted for valid MAC1.
type RateLimiter struct {
	mac1Key   [32]byte
	cookieKey [32]byte
	secretKey [32]byte
	nonceKey  [32]byte
	limit     uint64

	count     atomic.Uint64
	nonceCtr  atomic.Uint64
	mu        sync.Mutex
	lastReset time.Time
	startTime time.Time
}

// NewRateLimiter creates a limiter for our static public key. limit is the
// per-second handshake packet budget before cookies are demanded.
func NewRateLimiter(ourPublic [32]byte, limit uint64) *RateLimiter {
	var secret, nonceKey [32]byte
	_, _ = rand.Read(secret[:])
	_, _ = rand.Read(nonceKey[:])
	now := time.Now()
	return &RateLimiter{
		mac1Key:   hash2([]byte(labelMAC1), ourPublic[:]),
		cookieKey: hash2([]byte(labelCookie), ourPublic[:]),
		secretKey: secret,
		nonceKey:  nonceKey,
		limit:     limit,
		lastReset: now,
		startTime: now,
	}
}

func (l *RateLimiter) resetCount() {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastReset).Seconds() >= resetPeriodSeconds {
		l.count.Store(0)
		l.lastReset = now
	}
}

func (l *RateLimiter) currentCookie(addr net.IP) [16]byte {
	var addrBytes [16]byte
	if v4 := addr.To4(); v4 != nil {
		copy(addrBytes[:4], v4)
	} else if v6 := addr.To16(); v6 != nil {
		copy(addrBytes[:], v6)
	}
	counter := uint64(time.Since(l.startTime).Seconds()) / cookieRefreshSeconds
	var counterLE [8]byte
	binary.LittleEndian.PutUint64(counterLE[:], counter)
	return mac16x2(l.secretKey[:], counterLE[:], addrBytes[:])
}

func (l *RateLimiter) nextNonce() [24]byte {
	ctr := l.nonceCtr.Add(1)
	var ctrLE [8]byte
	binary.LittleEndian.PutUint64(ctrLE[:], ctr)
	return mac24(l.nonceKey[:], ctrLE[:])
}

// FormatCookieReply builds a 64-byte cookie reply, mirroring
// format_cookie_reply (XChaCha20-Poly1305 over the cookie, aad = mac1).
func (l *RateLimiter) FormatCookieReply(receiverIdx uint32, cookie [16]byte, mac1 []byte) ([]byte, error) {
	out := make([]byte, CookieReplySize)
	binary.LittleEndian.PutUint32(out[0:4], MsgTypeCookieReply)
	binary.LittleEndian.PutUint32(out[4:8], receiverIdx)
	nonce := l.nextNonce()
	copy(out[8:32], nonce[:])
	aead, err := chacha20poly1305.NewX(l.cookieKey[:])
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce[:], cookie[:], mac1)
	copy(out[32:64], sealed)
	return out, nil
}

// OpenCookieReply decrypts a cookie reply for cookie-based tests/clients.
func (l *RateLimiter) OpenCookieReply(datagram, mac1 []byte) ([16]byte, uint32, error) {
	var cookie [16]byte
	if len(datagram) != CookieReplySize || binary.LittleEndian.Uint32(datagram[0:4]) != MsgTypeCookieReply {
		return cookie, 0, ErrInvalidPacket
	}
	aead, err := chacha20poly1305.NewX(l.cookieKey[:])
	if err != nil {
		return cookie, 0, err
	}
	var nonce [24]byte
	copy(nonce[:], datagram[8:32])
	plaintext, err := aead.Open(nil, nonce[:], datagram[32:64], mac1)
	if err != nil || len(plaintext) != CookieSize {
		return cookie, 0, ErrInvalidTag
	}
	copy(cookie[:], plaintext)
	return cookie, binary.LittleEndian.Uint32(datagram[4:8]), nil
}

// verifyResult is the rate limiter verdict.
type verifyResult int

const (
	verifyAccept verifyResult = iota
	verifyNeedCookie
	verifyDrop
)

// Verify checks MAC1 and load state for a handshake datagram, mirroring
// verify_packet. Cookie is the current cookie for addr (computed by the
// caller via CurrentCookieFor); reply bytes are built by the caller with
// FormatCookieReply.
func (l *RateLimiter) Verify(addr net.IP, datagram []byte) (senderIdx uint32, mac1 []byte, result verifyResult) {
	if len(datagram) < 32 {
		return 0, nil, verifyDrop
	}
	msg := datagram[:len(datagram)-32]
	m1 := datagram[len(datagram)-32 : len(datagram)-16]
	computed := mac16(l.mac1Key[:], msg)
	if !verifyEqual(computed[:], m1) {
		return 0, nil, verifyDrop
	}
	// sender index sits at offset 4 in init and response alike.
	senderIdx = binary.LittleEndian.Uint32(datagram[4:8])
	l.resetCount()
	// Mirrors is_under_load (fetch_add >= limit): the first limit packets
	// pass without a cookie.
	if l.count.Add(1) <= l.limit {
		return senderIdx, append([]byte(nil), m1...), verifyAccept
	}
	if addr == nil {
		return senderIdx, nil, verifyDrop
	}
	cookie := l.currentCookie(addr)
	m2 := datagram[len(datagram)-16:]
	computedMac2 := mac16(cookie[:], datagram[:len(datagram)-16])
	if verifyEqual(computedMac2[:], m2) {
		return senderIdx, append([]byte(nil), m1...), verifyAccept
	}
	return senderIdx, append([]byte(nil), m1...), verifyNeedCookie
}

// CurrentCookieFor exposes the current cookie (for cookie-reply paths).
func (l *RateLimiter) CurrentCookieFor(addr net.IP) [16]byte {
	return l.currentCookie(addr)
}

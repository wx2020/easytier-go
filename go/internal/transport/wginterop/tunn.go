// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package wginterop

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// Session ring constants, matching boringtun noise/mod.rs.
const (
	nSessions      = 8
	sessionIdleTTL = 180 * time.Second
)

// Result is the responder outcome, mirroring boringtun TunnResult.
type Result struct {
	Kind ResultKind
	// ToNetwork holds response bytes for KindNetwork.
	ToNetwork []byte
	// ToTunnel holds the decapsulated IP packet for KindTunnel.
	ToTunnel []byte
}

// ResultKind classifies Result.
type ResultKind int

const (
	// KindDone means no action.
	KindDone ResultKind = iota
	// KindNetwork means send ToNetwork back to the sender.
	KindNetwork
	// KindTunnel means deliver ToTunnel to the local stack.
	KindTunnel
	// KindError means drop with a logged error.
	KindError
)

// Tunn is a responder-side WireGuard endpoint, mirroring the responder
// half of boringtun Tunn: initiation → response, data decapsulation,
// cookie replies under load, dual decrypt sessions, idle expiry.
type Tunn struct {
	staticPriv [32]byte
	staticPub  [32]byte
	peerPub    [32]byte

	responder *Responder
	limiter   *RateLimiter

	mu       sync.Mutex
	sessions map[uint32]*Session
	activity map[uint32]time.Time
	index    uint32
}

// NewTunn creates a responder for staticPriv expecting peerPub.
// rateLimit is the per-second handshake budget (boringtun default scale:
// thousands); session indexes start from a random base like Tunn::new.
func NewTunn(staticPriv, peerPub [32]byte, rateLimit uint64) (*Tunn, error) {
	responder, err := NewResponder(staticPriv, peerPub)
	if err != nil {
		return nil, err
	}
	myPub, err := PublicKey(staticPriv)
	if err != nil {
		return nil, err
	}
	return &Tunn{
		staticPriv: staticPriv,
		staticPub:  myPub,
		peerPub:    peerPub,
		responder:  responder,
		limiter:    NewRateLimiter(myPub, rateLimit),
		sessions:   make(map[uint32]*Session),
		activity:   make(map[uint32]time.Time),
	}, nil
}

// HandleDatagram processes one UDP payload from addr, mirroring
// decapsulate (rate limit → dispatch). Callers send KindNetwork bytes
// back and deliver KindTunnel locally.
func (t *Tunn) HandleDatagram(addr net.IP, datagram []byte) Result {
	if len(datagram) < 4 {
		return Result{Kind: KindError}
	}
	msgType := binary.LittleEndian.Uint32(datagram[0:4])
	switch msgType {
	case MsgTypeHandshakeInit:
		return t.handleInit(addr, datagram)
	case MsgTypeData:
		return t.handleData(datagram)
	case MsgTypeHandshakeResponse, MsgTypeCookieReply:
		// Responder-only endpoint: unexpected.
		return Result{Kind: KindDone}
	default:
		return Result{Kind: KindError}
	}
}

func (t *Tunn) handleInit(addr net.IP, datagram []byte) Result {
	init, err := parseInitiation(datagram)
	if err != nil {
		return Result{Kind: KindError}
	}
	senderIdx, mac1, verdict := t.limiter.Verify(addr, datagram)
	_ = senderIdx
	switch verdict {
	case verifyDrop:
		return Result{Kind: KindError}
	case verifyNeedCookie:
		cookie := t.limiter.CurrentCookieFor(addr)
		reply, err := t.limiter.FormatCookieReply(init.senderIdx, cookie, mac1)
		if err != nil {
			return Result{Kind: KindError}
		}
		return Result{Kind: KindNetwork, ToNetwork: reply}
	default:
	}
	response, localIndex, receivingKey, sendingKey, err := t.responder.Respond(init)
	if err != nil {
		return Result{Kind: KindError}
	}
	session := NewSession(localIndex, init.senderIdx, receivingKey, sendingKey)
	t.mu.Lock()
	t.sessions[session.receivingIndex] = session
	t.activity[session.receivingIndex] = time.Now()
	// Cap memory: drop the oldest idle entry beyond the ring size.
	if len(t.sessions) > nSessions*2 {
		var oldest uint32
		var oldestTime time.Time
		first := true
		for index, at := range t.activity {
			if first || at.Before(oldestTime) {
				oldest, oldestTime, first = index, at, false
			}
		}
		delete(t.sessions, oldest)
		delete(t.activity, oldest)
	}
	t.mu.Unlock()
	return Result{Kind: KindNetwork, ToNetwork: response}
}

func (t *Tunn) handleData(datagram []byte) Result {
	packet, err := parseData(datagram)
	if err != nil {
		return Result{Kind: KindError}
	}
	t.mu.Lock()
	session, ok := t.sessions[packet.receiverIndex]
	t.mu.Unlock()
	if !ok {
		return Result{Kind: KindError}
	}
	plaintext, err := session.OpenData(datagram)
	if err != nil {
		return Result{Kind: KindError}
	}
	t.mu.Lock()
	t.activity[packet.receiverIndex] = time.Now()
	t.mu.Unlock()
	if len(plaintext) == 0 {
		return Result{Kind: KindDone}
	}
	return Result{Kind: KindTunnel, ToTunnel: append([]byte(nil), plaintext...)}
}

// SealData encrypts plaintext towards the peer under the newest session,
// mirroring encapsulate (data path). It reports false when no session
// exists yet (caller should wait for / trigger a handshake).
func (t *Tunn) SealData(plaintext []byte) ([]byte, bool) {
	t.mu.Lock()
	var newest *Session
	var newestAt time.Time
	for index, session := range t.sessions {
		if at := t.activity[index]; newest == nil || at.After(newestAt) {
			newest, newestAt = session, at
		}
	}
	t.mu.Unlock()
	if newest == nil {
		return nil, false
	}
	return newest.SealData(plaintext), true
}

// ExpireIdle drops sessions idle longer than sessionIdleTTL (boringtun
// session timers equivalent for the responder side).
func (t *Tunn) ExpireIdle(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	dropped := 0
	for index, at := range t.activity {
		if now.Sub(at) > sessionIdleTTL {
			delete(t.sessions, index)
			delete(t.activity, index)
			dropped++
		}
	}
	return dropped
}

// SessionCount reports live sessions (tests/metrics).
func (t *Tunn) SessionCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

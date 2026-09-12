// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// WireGuard session timers for the EasyTier-native WG tunnel.
//
// Rust reference: easytier/src/tunnel/wireguard.rs runs one boringtun
// routine_task per peer, whose update_timers implements the WireGuard
// protocol timers: rekey after REKEY_AFTER_TIME, retry failed handshakes
// every REKEY_TIMEOUT within REKEY_ATTEMPT_TIME, keep the session alive
// with keepalives after KEEPALIVE_TIMEOUT of outbound silence, and drop
// keys once REJECT_AFTER_TIME has elapsed since the last handshake
// (ConnectionExpired triggers a fresh handshake on the initiator).
//
// The Go tunnel mirrors those semantics: dialed sessions act as the
// handshake initiator and accepted sessions as the responder, the
// initiator rekeys on schedule, both sides send keepalives while the
// peer is responsive, and the listener recycles peers that have been
// silent for more than one minute (peer_map.retain in the oracle).
package transport

import (
	"context"
	"errors"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// Timer constants mirror boringtun's WireGuard timers.
const (
	// wgRekeyAfterTime is REKEY_AFTER_TIME: the initiator re-handshakes
	// once the current session is this old.
	wgRekeyAfterTime = 120 * time.Second
	// wgRejectAfterTime is REJECT_AFTER_TIME: keys older than this are
	// refused on both the send and receive path.
	wgRejectAfterTime = 180 * time.Second
	// wgRekeyTimeout is REKEY_TIMEOUT: spacing between handshake retries.
	wgRekeyTimeout = 5 * time.Second
	// wgRekeyAttemptTime is REKEY_ATTEMPT_TIME: total budget for a
	// handshake before the session is abandoned.
	wgRekeyAttemptTime = 90 * time.Second
	// wgKeepaliveTimeout is KEEPALIVE_TIMEOUT: outbound silence before a
	// keepalive is sent.
	wgKeepaliveTimeout = 10 * time.Second
)

// wgPeerIdleTTL mirrors the oracle listener retaining peers whose last
// received datagram is at most 61 seconds old. It is a variable so tests
// can shrink the recycle window.
var wgPeerIdleTTL = 61 * time.Second

// wgNativeKindKeepalive is the native body kind reserved for keepalive
// datagrams (magic + kind, nothing else). Sealed data always starts with
// the AEAD transport type (4), so the kind byte space of 1..3 stays free.
const wgNativeKindKeepalive = 3

// ErrWGSessionExpired reports that the session keys are past
// REJECT_AFTER_TIME and were not refreshed by a handshake.
var ErrWGSessionExpired = errors.New("WG session keys are expired")

// wgSessionTimers holds the tunable timer intervals for one session.
// Production uses wgDefaultSessionTimers; tests shrink the intervals.
type wgSessionTimers struct {
	keepalive    time.Duration
	rekeyAfter   time.Duration
	rekeyTimeout time.Duration
	rekeyAttempt time.Duration
	tick         time.Duration
}

// wgDefaultSessionTimers mirrors the boringtun timer constants.
var wgDefaultSessionTimers = wgSessionTimers{
	keepalive:    wgKeepaliveTimeout,
	rekeyAfter:   wgRekeyAfterTime,
	rekeyTimeout: wgRekeyTimeout,
	rekeyAttempt: wgRekeyAttemptTime,
	tick:         time.Second,
}

// wgTimers is the package-level timer source so tests can shrink the
// intervals without changing production defaults.
var wgTimers = wgDefaultSessionTimers

// clamped returns the timers with a tick fast enough for the configured
// intervals.
func (t wgSessionTimers) clamped() wgSessionTimers {
	tick := t.keepalive
	if t.rekeyTimeout < tick {
		tick = t.rekeyTimeout
	}
	tick /= 4
	const minTick = 10 * time.Millisecond
	if tick < minTick {
		tick = minTick
	}
	if tick > time.Second {
		tick = time.Second
	}
	t.tick = tick
	return t
}

// startRoutine launches the WireGuard routine task for a crypto session.
// It exits when the session closes.
func (s *WGSession) startRoutine() {
	if s.crypto == nil {
		return
	}
	s.timers = wgTimers.clamped()
	go s.routineLoop()
}

// routineLoop drives rekey and keepalive decisions. The body runs once
// before the first tick so a freshly dialed session begins its handshake
// immediately (the oracle performs the handshake during connect), then
// every tick re-evaluates the timers. Handshake attempts run inline: a
// failed attempt waits up to rekeyTimeout for a response before the next
// tick retries it, mirroring boringtun's serialized routine task.
func (s *WGSession) routineLoop() {
	ticker := time.NewTicker(s.timers.tick)
	defer ticker.Stop()
	var lastAttempt time.Time
	var attemptStart time.Time
	for {
		now := time.Now()
		if s.role == wgRoleInitiator {
			if s.rekeyDue(now) && now.Sub(lastAttempt) >= s.timers.rekeyTimeout {
				if attemptStart.IsZero() {
					attemptStart = now
				}
				if now.Sub(attemptStart) > s.timers.rekeyAttempt {
					// REKEY_ATTEMPT_TIME exhausted: the session cannot
					// authenticate the peer, so it is abandoned.
					s.shutdown()
					return
				}
				lastAttempt = now
				attemptCtx, cancel := context.WithTimeout(context.Background(), s.timers.rekeyTimeout)
				err := s.Handshake(attemptCtx)
				cancel()
				if err == nil {
					attemptStart = time.Time{}
				}
			}
		}
		if now.Sub(s.lastSendTime()) >= s.timers.keepalive && now.Sub(s.lastRecvTime()) <= s.timers.keepalive*2 {
			s.sendKeepalive()
		}
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
	}
}

// rekeyDue reports whether the initiator owes a handshake: a session that
// has never completed one (the oracle handshakes during connect), one that
// reached REKEY_AFTER_TIME, or one whose keys are already expired.
func (s *WGSession) rekeyDue(now time.Time) bool {
	if s.crypto == nil {
		return false
	}
	if !s.handshaked.Load() {
		return true
	}
	return now.Sub(s.crypto.sessionEstablishedAt()) >= s.timers.rekeyAfter || s.crypto.isExpired(now)
}

// sendKeepalive writes one native keepalive datagram. Failures are
// ignored: keepalives are best-effort liveness probes on UDP.
func (s *WGSession) sendKeepalive() {
	body := []byte{wgNativeMagic, wgNativeKindKeepalive}
	header := protocol.MarshalWGTunnelHeader(len(body))
	datagram := make([]byte, 0, len(header)+len(body))
	datagram = append(datagram, header...)
	datagram = append(datagram, body...)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writeUDP(ctx, s.socket, datagram, s.remote); err == nil {
		s.markSend()
		s.keepalivesSent.Add(1)
	}
}

// markRecv records inbound activity for keepalive pacing and the
// listener's idle-session recycling.
func (s *WGSession) markRecv() { s.lastRecv.Store(time.Now().UnixNano()) }

// markSend records outbound activity.
func (s *WGSession) markSend() { s.lastSend.Store(time.Now().UnixNano()) }

func (s *WGSession) lastRecvTime() time.Time { return time.Unix(0, s.lastRecv.Load()) }
func (s *WGSession) lastSendTime() time.Time { return time.Unix(0, s.lastSend.Load()) }

// pruneIdleSessions shuts down listener-side peers that have been silent
// longer than wgPeerIdleTTL, mirroring the oracle's peer_map.retain.
func (s *WGService) pruneIdleSessions(now time.Time) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	var stale []*WGSession
	for key, session := range s.sessions {
		if now.Sub(session.lastRecvTime()) > wgPeerIdleTTL {
			delete(s.sessions, key)
			stale = append(stale, session)
		}
	}
	s.mu.Unlock()
	for _, session := range stale {
		session.shutdown()
	}
}

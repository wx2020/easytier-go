// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package vpnportal

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/EasyTier/EasyTier/go/internal/transport"
)

// Native crypto client authentication.
//
// The stock-WireGuard path (real Noise handshake via boringtun) still needs
// an external handshake implementation; those packets keep the best-effort
// tracking in serve(). This file adds authentication for EasyTier-native
// clients: the client seals its registration with the portal client key
// (WgConfig::new_for_portal client seed) and the portal only tracks
// endpoints whose first packet authenticates. Undecryptable packets are
// ignored instead of registering the sender.
type nativeCrypto struct {
	cfg transport.WgCryptoConfig

	mu     sync.Mutex
	states map[string]*transport.WgCryptoState
	seq    atomic.Uint64
}

// EnableNativeCrypto arms sealed-client authentication derived from the
// portal network identity (server seed). It is idempotent.
func (p *Portal) EnableNativeCrypto() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native != nil {
		return nil
	}
	cfg, err := transport.NewWgCryptoConfigForPortal(p.nid.NetworkName, p.nid.NetworkSecret, true)
	if err != nil {
		return fmt.Errorf("portal native crypto config: %w", err)
	}
	p.native = &nativeCrypto{cfg: cfg, states: make(map[string]*transport.WgCryptoState)}
	return nil
}

// NativeCryptoEnabled reports whether sealed-client authentication is armed.
func (p *Portal) NativeCryptoEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.native != nil
}

// handleNativePacket authenticates one datagram from addr. Valid native
// datagrams register/track the endpoint; anything else is ignored so
// strangers (e.g. wrong network secret) leave no state. reply sends raw
// bytes back to the sender.
func (p *Portal) handleNativePacket(_ context.Context, addr string, datagram []byte, reply func([]byte) error) bool {
	p.mu.RLock()
	native := p.native
	p.mu.RUnlock()
	if native == nil {
		return false
	}
	native.mu.Lock()
	state := native.states[addr]
	native.mu.Unlock()

	if state == nil {
		ephemeral, err := transport.NewWgCryptoState(native.cfg)
		if err != nil {
			return false
		}
		if _, err := ephemeral.Open(datagram); err != nil {
			return false
		}
		native.mu.Lock()
		if existing := native.states[addr]; existing != nil {
			state = existing
		} else {
			native.states[addr] = ephemeral
			state = ephemeral
		}
		native.mu.Unlock()
		p.RegisterClient(addr)
		// Sealed acknowledgement proves portal liveness to the client.
		if ack, err := state.SealSequenced(native.seq.Add(1), []byte("portal-ack")); err == nil {
			_ = reply(ack)
		}
		return true
	}
	if _, err := state.Open(datagram); err != nil {
		return false
	}
	p.RegisterClient(addr)
	return true
}

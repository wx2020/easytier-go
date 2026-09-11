// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"bytes"
	"testing"
)

func TestWGHandshakeAgreesSessionKey(t *testing.T) {
	initCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	respCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	initDatagram, ePriv, err := BuildHsInit(initCfg, 1234)
	if err != nil {
		t.Fatal(err)
	}
	if len(initDatagram) != wgHsInitSize {
		t.Fatalf("init size = %d", len(initDatagram))
	}
	init, err := ParseHsInit(initDatagram)
	if err != nil {
		t.Fatal(err)
	}
	responder := NewWgHandshakeResponder(respCfg)
	respDatagram, respKeys, err := responder.Respond(init)
	if err != nil {
		t.Fatal(err)
	}
	if len(respDatagram) != wgHsRespSize {
		t.Fatalf("response size = %d", len(respDatagram))
	}
	resp, err := ParseHsResp(respDatagram)
	if err != nil {
		t.Fatal(err)
	}
	initKeys, err := CompleteInit(initCfg, ePriv, 1234, resp)
	if err != nil {
		t.Fatal(err)
	}
	if initKeys.SessionKey != respKeys.SessionKey {
		t.Fatal("initiator and responder disagree on the session key")
	}
	if initKeys.PeerStatic != respKeys.PeerStatic {
		t.Fatal("peer static mismatch")
	}
}

func TestWGHandshakeRejectsWrongPeer(t *testing.T) {
	initCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	strangerCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "wrong")
	if err != nil {
		t.Fatal(err)
	}
	initDatagram, _, err := BuildHsInit(initCfg, 7)
	if err != nil {
		t.Fatal(err)
	}
	init, err := ParseHsInit(initDatagram)
	if err != nil {
		t.Fatal(err)
	}
	stranger := NewWgHandshakeResponder(strangerCfg)
	if _, _, err := stranger.Respond(init); err == nil {
		t.Fatal("responder with wrong identity must reject")
	}
}

func TestWGHandshakeRejectsReplayAndTamper(t *testing.T) {
	cfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	initDatagram, _, err := BuildHsInit(cfg, 9)
	if err != nil {
		t.Fatal(err)
	}
	init, err := ParseHsInit(initDatagram)
	if err != nil {
		t.Fatal(err)
	}
	responder := NewWgHandshakeResponder(cfg)
	if _, _, err := responder.Respond(init); err != nil {
		t.Fatal(err)
	}
	if _, _, err := responder.Respond(init); err == nil {
		t.Fatal("replayed initiation must be rejected")
	}
	tampered := append([]byte(nil), initDatagram...)
	tampered[len(tampered)-1] ^= 0xff
	badInit, err := ParseHsInit(tampered)
	if err != nil {
		t.Fatal(err)
	}
	fresh := NewWgHandshakeResponder(cfg)
	if _, _, err := fresh.Respond(badInit); err == nil {
		t.Fatal("tampered initiation must fail authentication")
	}
	if _, err := ParseHsInit([]byte{1, 1, 0}); err == nil {
		t.Fatal("truncated initiation must fail")
	}
	if _, err := ParseHsResp([]byte{2, 1, 0}); err == nil {
		t.Fatal("truncated response must fail")
	}
}

func TestWGHandshakeSessionKeyEncrypts(t *testing.T) {
	initCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	respCfg, err := NewWgCryptoConfigFromNetworkIdentity("mesh", "secret")
	if err != nil {
		t.Fatal(err)
	}
	initDatagram, ePriv, err := BuildHsInit(initCfg, 42)
	if err != nil {
		t.Fatal(err)
	}
	init, err := ParseHsInit(initDatagram)
	if err != nil {
		t.Fatal(err)
	}
	responder := NewWgHandshakeResponder(respCfg)
	respDatagram, respKeys, err := responder.Respond(init)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ParseHsResp(respDatagram)
	if err != nil {
		t.Fatal(err)
	}
	initKeys, err := CompleteInit(initCfg, ePriv, 42, resp)
	if err != nil {
		t.Fatal(err)
	}
	// Both sides adopt the session key and exchange data under it.
	a, err := NewWgCryptoState(initCfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewWgCryptoState(respCfg)
	if err != nil {
		t.Fatal(err)
	}
	a.AdoptSessionKey(initKeys.SessionKey)
	b.AdoptSessionKey(respKeys.SessionKey)
	sealed, err := a.SealSequenced(1, []byte("post-handshake"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := b.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, []byte("post-handshake")) {
		t.Fatalf("round trip = %q", opened)
	}
	// Old static-key epochs no longer decrypt after adoption.
	stale, err := NewWgCryptoState(initCfg)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := stale.SealSequenced(1, []byte("pre-handshake"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(legacy); err == nil {
		t.Fatal("pre-handshake epoch must not survive adoption")
	}
}

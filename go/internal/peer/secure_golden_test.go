// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenSecureFixtures(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "compat", "secure", "fixtures.json")
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join("testdata", "compat", "secure", "fixtures.json")
		if _, err2 := os.Stat(path); err2 != nil {
			path = filepath.Join("go", "testdata", "compat", "secure", "fixtures.json")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read secure fixtures: %v", err)
	}
	var fixtures []struct {
		Name         string `json:"name"`
		SuiteID      uint8  `json:"suite_id"`
		RootKeyHex   string `json:"root_key_hex"`
		Epoch        uint32 `json:"epoch"`
		Seq          uint64 `json:"seq"`
		PlaintextHex string `json:"plaintext_hex"`
		WireHex      string `json:"wire_hex"`
		NonceHex     string `json:"nonce_hex"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("unmarshal secure fixtures: %v", err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			key, _ := hex.DecodeString(f.RootKeyHex)
			pt, _ := hex.DecodeString(f.PlaintextHex)
			wireWant, _ := hex.DecodeString(f.WireHex)
			nonceWant, _ := hex.DecodeString(f.NonceHex)
			suite := CipherSuite(f.SuiteID)
			// Create session at epoch, advance to seq, then Seal
			s, err := NewSecureDatagramSession(key, suite, f.Epoch, DirectionInitiatorToResponder, DirectionResponderToInitiator)
			if err != nil {
				t.Fatalf("NewSecureDatagramSession: %v", err)
			}
			for i := uint64(0); i < f.Seq; i++ {
				_, _ = s.Seal([]byte("pad"))
			}
			wire, err := s.Seal(pt)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if hex.EncodeToString(wire) != f.WireHex {
				t.Fatalf("wire mismatch: got %s want %s", hex.EncodeToString(wire), f.WireHex)
			}
			// Nonce check
			if hex.EncodeToString(wire[len(wire)-12:]) != f.NonceHex {
				t.Fatalf("nonce mismatch: got %s want %s", hex.EncodeToString(wire[len(wire)-12:]), f.NonceHex)
			}
			_ = nonceWant
			_ = wireWant
			// Open via peer session
			peer, err := NewSecureDatagramSession(key, suite, f.Epoch, DirectionResponderToInitiator, DirectionInitiatorToResponder)
			if err != nil {
				t.Fatalf("peer session: %v", err)
			}
			// Advance peer's rx to same epoch if needed (Open handles epoch promotion)
			for i := uint64(0); i < f.Seq; i++ {
				// peer needs to have seen previous seq to avoid replay, but we test single packet open, so create fresh peer and open directly
				// The peer's window will accept seq directly if it's first
				_ = i
			}
			// For the test, we need to ensure peer can open the wire at correct epoch/seq
			// If seq>0, peer's window starts at 0, but wire at seq 42 should be accepted as future seq (highest+42)
			// Our replay window allows future seq (seq > highest) without rejection, so it should pass
			got, err := peer.Open(wire)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if hex.EncodeToString(got) != f.PlaintextHex {
				t.Fatalf("plaintext mismatch: got %s want %s", hex.EncodeToString(got), f.PlaintextHex)
			}
		})
	}
}

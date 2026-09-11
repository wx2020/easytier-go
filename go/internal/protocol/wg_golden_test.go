// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenWGFixtures(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "compat", "wg", "fixtures.json")
	if _, err := os.Stat(path); err != nil {
		// fallback for other working dirs
		path = filepath.Join("testdata", "compat", "wg", "fixtures.json")
		if _, err2 := os.Stat(path); err2 != nil {
			path = filepath.Join("go", "testdata", "compat", "wg", "fixtures.json")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read wg fixtures: %v", err)
	}
	var fixtures []struct {
		Name       string `json:"name"`
		PayloadLen int    `json:"payload_len"`
		HeaderHex  string `json:"header_hex"`
		TotalLen   int    `json:"total_len"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("unmarshal wg fixtures: %v", err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			got := MarshalWGTunnelHeader(f.PayloadLen)
			if hex.EncodeToString(got) != f.HeaderHex {
				t.Fatalf("header mismatch: got %s want %s", hex.EncodeToString(got), f.HeaderHex)
			}
			if len(got)+f.PayloadLen+PeerManagerHeaderSize != f.TotalLen {
				t.Fatalf("total_len mismatch: got %d want %d", len(got)+f.PayloadLen+PeerManagerHeaderSize, f.TotalLen)
			}
			if got[0] != 0x45 || got[8] != 64 {
				t.Fatalf("header fields invalid: %x", got)
			}
		})
	}
}

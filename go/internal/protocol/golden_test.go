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

func compatPath(t *testing.T, rel string) string {
	t.Helper()
	// From go/internal/protocol -> ../../testdata/compat/<rel>
	for _, p := range []string{
		filepath.Join("..", "..", "testdata", "compat", rel),
		filepath.Join("testdata", "compat", rel),
		filepath.Join("go", "testdata", "compat", rel),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatalf("fixture %q not found", rel)
	return ""
}

func TestGoldenPacketFixtures(t *testing.T) {
	path := compatPath(t, "packet/fixtures.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read packet fixtures: %v", err)
	}
	var fixtures []struct {
		Name           string `json:"name"`
		FromPeerID     uint32 `json:"from_peer_id"`
		ToPeerID       uint32 `json:"to_peer_id"`
		PacketType     uint8  `json:"packet_type"`
		Flags          uint8  `json:"flags"`
		ForwardCounter uint8  `json:"forward_counter"`
		PayloadHex     string `json:"payload_hex"`
		BodyHex        string `json:"body_hex"`
		PayloadLength  uint32 `json:"payload_length"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("unmarshal packet fixtures: %v", err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			body, err := hex.DecodeString(f.BodyHex)
			if err != nil {
				t.Fatalf("decode body hex: %v", err)
			}
			pkt, err := ParseBody(body)
			if err != nil {
				t.Fatalf("ParseBody failed: %v", err)
			}
			if pkt.Header.FromPeerID != f.FromPeerID || pkt.Header.ToPeerID != f.ToPeerID || pkt.Header.PacketType != f.PacketType || pkt.Header.Flags != f.Flags || pkt.Header.ForwardCounter != f.ForwardCounter {
				t.Fatalf("header mismatch: got %+v want from=%d to=%d type=%d flags=%d fwd=%d", pkt.Header, f.FromPeerID, f.ToPeerID, f.PacketType, f.Flags, f.ForwardCounter)
			}
			if pkt.Header.Length != f.PayloadLength {
				t.Fatalf("payload_length mismatch: got %d want %d", pkt.Header.Length, f.PayloadLength)
			}
			if want, _ := hex.DecodeString(f.PayloadHex); string(pkt.Payload) != string(want) && f.Flags&FlagCompressed == 0 {
				// For compressed, payload is wire payload, not original
				if hex.EncodeToString(pkt.Payload) != f.PayloadHex {
					t.Fatalf("payload hex mismatch: got %s want %s", hex.EncodeToString(pkt.Payload), f.PayloadHex)
				}
			}
			// Round-trip: marshal and parse again, except compressed where Length is original
			if f.Flags&FlagCompressed == 0 {
				encoded, err := pkt.MarshalBody()
				if err != nil {
					t.Fatalf("MarshalBody failed: %v", err)
				}
				if hex.EncodeToString(encoded) != f.BodyHex {
					t.Fatalf("marshal mismatch: got %s want %s", hex.EncodeToString(encoded), f.BodyHex)
				}
			}
		})
	}
}

func TestGoldenHandshakeFixtures(t *testing.T) {
	path := compatPath(t, "handshake/fixtures.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read handshake fixtures: %v", err)
	}
	var fixtures []struct {
		Name                   string   `json:"name"`
		Magic                  uint32   `json:"magic"`
		MyPeerID               uint32   `json:"my_peer_id"`
		Version                uint32   `json:"version"`
		Features               []string `json:"features"`
		NetworkName            string   `json:"network_name"`
		NetworkSecretDigestHex string   `json:"network_secret_digest_hex"`
		WireHex                string   `json:"wire_hex"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("unmarshal handshake fixtures: %v", err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(f.WireHex)
			if err != nil {
				t.Fatalf("decode wire hex: %v", err)
			}
			req, err := ParseHandshakeRequest(wire)
			if err != nil {
				t.Fatalf("ParseHandshakeRequest failed: %v", err)
			}
			if req.Magic != f.Magic || req.MyPeerID != f.MyPeerID || req.Version != f.Version || req.NetworkName != f.NetworkName {
				t.Fatalf("field mismatch: got %+v want magic=%d peer=%d version=%d net=%q", req, f.Magic, f.MyPeerID, f.Version, f.NetworkName)
			}
			if len(req.Features) != len(f.Features) {
				t.Fatalf("features len mismatch: got %v want %v", req.Features, f.Features)
			}
			for i, v := range f.Features {
				if req.Features[i] != v {
					t.Fatalf("feature %d mismatch: got %q want %q", i, req.Features[i], v)
				}
			}
			digestWant, _ := hex.DecodeString(f.NetworkSecretDigestHex)
			if len(digestWant) != len(req.NetworkSecretDigest) || (len(digestWant) != 0 && hex.EncodeToString(req.NetworkSecretDigest) != f.NetworkSecretDigestHex) {
				t.Fatalf("digest mismatch: got %s want %s", hex.EncodeToString(req.NetworkSecretDigest), f.NetworkSecretDigestHex)
			}
			// Marshal round-trip
			encoded, err := req.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if hex.EncodeToString(encoded) != f.WireHex {
				t.Fatalf("marshal mismatch: got %s want %s", hex.EncodeToString(encoded), f.WireHex)
			}
		})
	}
}

func TestGoldenDigestFixtures(t *testing.T) {
	path := compatPath(t, "digest/fixtures.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read digest fixtures: %v", err)
	}
	var fixtures []struct {
		Name      string `json:"name"`
		Str1      string `json:"str1"`
		Str2      string `json:"str2"`
		DigestHex string `json:"digest_hex"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("unmarshal digest fixtures: %v", err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			d := GenerateDigestFromStrings(f.Str1, f.Str2)
			if got := hex.EncodeToString(d[:]); got != f.DigestHex {
				t.Fatalf("digest mismatch: got %s want %s", got, f.DigestHex)
			}
		})
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"encoding/hex"
	"testing"
)

func TestPeerNoiseMsg1KnownVector(t *testing.T) {
	var id peerUUID
	id[3], id[7], id[11], id[15] = 1, 2, 3, 4
	m := peerConnNoiseMsg1{Version: 1, NetworkName: "mesh", ConnID: id, ClientEncryptionAlgorithm: "chacha20"}
	want := "080112046d657368220808011002180320042a086368616368613230"
	if got := hex.EncodeToString(m.marshal()); got != want {
		t.Fatalf("msg1 = %s, want %s", got, want)
	}
	if decoded, err := unmarshalPeerMsg1(m.marshal()); err != nil || decoded.NetworkName != "mesh" || decoded.ConnID != id {
		t.Fatalf("decode = %#v, %v", decoded, err)
	}
}

func TestPeerNoiseMessagesMatchRustFixtureVectors(t *testing.T) {
	const wantMsg1 = "0807120b666978747572652d6e65741809221808c4e68889011088ef99ab0518ccf7aacd092080febbef0d2a074145532d47434d"
	decoded, err := unmarshalPeerMsg1(mustHex(wantMsg1))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(decoded.marshal()); got != wantMsg1 {
		t.Fatalf("fixture msg1 roundtrip = %s, want %s", got, wantMsg1)
	}
}

func mustHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func TestPeerNoiseMsg2KnownVector(t *testing.T) {
	var a, b peerUUID
	for i := range a {
		a[i] = byte(i + 1)
		b[i] = byte(16 - i)
	}
	root := make([]byte, 32)
	proof := make([]byte, 32)
	m := peerConnNoiseMsg2{NetworkName: "mesh", RoleHint: 1, Action: 2, SessionGeneration: 3, RootKey: root, InitialEpoch: 4, BConnID: b, AConnIDEcho: a, SecretProof: proof, ServerEncryptionAlgorithm: "chacha20"}
	if decoded, err := unmarshalPeerMsg2(m.marshal()); err != nil || decoded.Action != 2 || len(decoded.RootKey) != 32 || decoded.BConnID != b {
		t.Fatalf("decode = %#v, %v", decoded, err)
	}
}

func TestPeerNoiseRejectsInvalidLengthsAndSkipsUnknown(t *testing.T) {
	var id peerUUID
	m := peerConnNoiseMsg1{Version: 1, NetworkName: "mesh", ConnID: id, ClientEncryptionAlgorithm: "chacha20"}
	data := append(m.marshal(), 0x30, 0x01, 0x40, 0x01)
	if _, err := unmarshalPeerMsg1(data); err != nil {
		t.Fatal(err)
	}
	bad := peerConnNoiseMsg2{RootKey: make([]byte, 31)}.marshal()
	if _, err := unmarshalPeerMsg2(bad); err == nil {
		t.Fatal("expected root key length error")
	}
}

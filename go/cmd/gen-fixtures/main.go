// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/route"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
)

func main() {
	out := flag.String("out", "go/testdata/compat", "output directory")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintf(os.Stderr, "gen-fixtures: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("fixtures written to %s\n", *out)
}

func run(out string) error {
	for _, d := range []string{"packet", "handshake", "digest", "rpc", "config", "secure", "route", "wg", "noise"} {
		if err := os.MkdirAll(filepath.Join(out, d), 0o755); err != nil {
			return err
		}
	}
	if err := genPacket(out); err != nil {
		return err
	}
	if err := genHandshake(out); err != nil {
		return err
	}
	if err := genDigest(out); err != nil {
		return err
	}
	if err := genRPC(out); err != nil {
		return err
	}
	if err := genConfig(out); err != nil {
		return err
	}
	if err := genWG(out); err != nil {
		return err
	}
	if err := genSecure(out); err != nil {
		return err
	}
	if err := genRoute(out); err != nil {
		return err
	}
	return nil
}

type PacketFixture struct {
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

func genPacket(out string) error {
	fixtures := []PacketFixture{
		newPacket("data-small", 0x11223344, 0x55667788, protocol.PacketTypeData, protocol.FlagEncrypted, 1, []byte("hello")),
		newPacket("data-empty", 1, 2, protocol.PacketTypeData, 0, 0, []byte{}),
		newPacket("handshake", 100, 0, protocol.PacketTypeHandshake, 0, 1, []byte{0x08, 0x01}),
		newPacket("ping", 0x01020304, 0x05060708, protocol.PacketTypePing, 0, 7, []byte("ping")),
		newPacketCompressed("compressed", 0x11223344, 0x55667788, 1, protocol.FlagCompressed, 2, []byte{0xaa, 0xbb, 0x01}, 3),
		newPacket("max-forward", 1, 2, protocol.PacketTypeData, 0, 7, []byte("x")),
	}
	if err := writeJSON(filepath.Join(out, "packet/fixtures.json"), fixtures); err != nil {
		return err
	}
	for _, f := range fixtures {
		b, _ := hex.DecodeString(f.BodyHex)
		_ = os.WriteFile(filepath.Join(out, "packet", f.Name+".bin"), b, 0o644)
	}
	return nil
}

func newPacket(name string, from, to uint32, pt, flags, fwd uint8, payload []byte) PacketFixture {
	p := protocol.Packet{Header: protocol.PeerManagerHeader{FromPeerID: from, ToPeerID: to, PacketType: pt, Flags: flags, ForwardCounter: fwd}, Payload: payload}
	body, _ := p.MarshalBody()
	return PacketFixture{
		Name: name, FromPeerID: from, ToPeerID: to, PacketType: pt, Flags: flags, ForwardCounter: fwd,
		PayloadHex: hex.EncodeToString(payload), BodyHex: hex.EncodeToString(body), PayloadLength: uint32(len(payload)),
	}
}
func newPacketCompressed(name string, from, to uint32, pt, flags, fwd uint8, wirePayload []byte, origLen uint32) PacketFixture {
	// For compressed, header Length is original, flags has COMPRESSED, wire payload is compressed+tail
	// Build body manually to keep Length as origLen
	payloadHex := hex.EncodeToString(wirePayload)
	body := make([]byte, 16+len(wirePayload))
	// little endian header
	body[0] = byte(from); body[1] = byte(from >> 8); body[2] = byte(from >> 16); body[3] = byte(from >> 24)
	body[4] = byte(to); body[5] = byte(to >> 8); body[6] = byte(to >> 16); body[7] = byte(to >> 24)
	body[8] = pt; body[9] = flags; body[10] = fwd; body[11] = 0
	body[12] = byte(origLen); body[13] = byte(origLen >> 8); body[14] = byte(origLen >> 16); body[15] = byte(origLen >> 24)
	copy(body[16:], wirePayload)
	return PacketFixture{
		Name: name, FromPeerID: from, ToPeerID: to, PacketType: pt, Flags: flags, ForwardCounter: fwd,
		PayloadHex: payloadHex, BodyHex: hex.EncodeToString(body), PayloadLength: origLen,
	}
}

type HandshakeFixture struct {
	Name                    string   `json:"name"`
	Magic                   uint32   `json:"magic"`
	MyPeerID                uint32   `json:"my_peer_id"`
	Version                 uint32   `json:"version"`
	Features                []string `json:"features"`
	NetworkName             string   `json:"network_name"`
	NetworkSecretDigestHex  string   `json:"network_secret_digest_hex"`
	WireHex                 string   `json:"wire_hex"`
}

func genHandshake(out string) error {
	digest1 := make([]byte, 32)
	for i := range digest1 {
		digest1[i] = byte(i)
	}
	fixtures := []HandshakeFixture{
		newHandshake("handshake-1", protocol.HandshakeMagic, 0x10203040, protocol.HandshakeVersion, []string{"tcp", "quic"}, "mesh", digest1),
		newHandshake("handshake-empty-features", protocol.HandshakeMagic, 12345, protocol.HandshakeVersion, []string{}, "testnet", nil),
		newHandshake("handshake-minimal", protocol.HandshakeMagic, 1, protocol.HandshakeVersion, []string{}, "", nil),
		newHandshakeDigest("handshake-with-digest", protocol.HandshakeMagic, 999, protocol.HandshakeVersion, []string{"tcp"}, "prod", "prod", "secret"),
	}
	return writeJSON(filepath.Join(out, "handshake/fixtures.json"), fixtures)
}
func newHandshake(name string, magic, peerID, version uint32, features []string, netName string, digest []byte) HandshakeFixture {
	req := protocol.HandshakeRequest{Magic: magic, MyPeerID: peerID, Version: version, Features: features, NetworkName: netName, NetworkSecretDigest: digest}
	wire, _ := req.Marshal()
	return HandshakeFixture{Name: name, Magic: magic, MyPeerID: peerID, Version: version, Features: features, NetworkName: netName, NetworkSecretDigestHex: hex.EncodeToString(digest), WireHex: hex.EncodeToString(wire)}
}
func newHandshakeDigest(name string, magic, peerID, version uint32, features []string, netName, s1, s2 string) HandshakeFixture {
	d := protocol.GenerateDigestFromStrings(s1, s2)
	return newHandshake(name, magic, peerID, version, features, netName, d[:])
}

type DigestFixture struct {
	Name      string `json:"name"`
	Str1      string `json:"str1"`
	Str2      string `json:"str2"`
	DigestHex string `json:"digest_hex"`
}

func genDigest(out string) error {
	fixtures := []DigestFixture{
		{"mesh-secret", "mesh", "secret", hex.EncodeToString(slice32(protocol.GenerateDigestFromStrings("mesh", "secret")))},
		{"empty-machine-id", "", "machine-id", hex.EncodeToString(slice32(protocol.GenerateDigestFromStrings("", "machine-id")))},
		{"test-empty", "test", "", hex.EncodeToString(slice32(protocol.GenerateDigestFromStrings("test", "")))},
		{"easytier-network", "easytier", "default-secret", hex.EncodeToString(slice32(protocol.GenerateDigestFromStrings("easytier", "default-secret")))},
		{"prod-secret", "prod", "secret", hex.EncodeToString(slice32(protocol.GenerateDigestFromStrings("prod", "secret")))},
		{"empty-empty", "", "", hex.EncodeToString(slice32(protocol.GenerateDigestFromStrings("", "")))},
	}
	return writeJSON(filepath.Join(out, "digest/fixtures.json"), fixtures)
}
func slice32(a [32]byte) []byte { b := make([]byte, 32); copy(b, a[:]); return b }

type RpcDescriptorFixture struct {
	Name        string `json:"name"`
	DomainName  string `json:"domain_name"`
	ProtoName   string `json:"proto_name"`
	ServiceName string `json:"service_name"`
	MethodIndex uint32 `json:"method_index"`
	WireHex     string `json:"wire_hex"`
}
type RpcPacketFixture struct {
	Name          string                  `json:"name"`
	FromPeer      uint32                  `json:"from_peer"`
	ToPeer        uint32                  `json:"to_peer"`
	TransactionID int64                   `json:"transaction_id"`
	Descriptor    *RpcDescriptorFixture   `json:"descriptor"`
	BodyHex       string                  `json:"body_hex"`
	IsRequest     bool                    `json:"is_request"`
	TotalPieces   uint32                  `json:"total_pieces"`
	PieceIdx      uint32                  `json:"piece_idx"`
	TraceID       int32                   `json:"trace_id"`
	WireHex       string                  `json:"wire_hex"`
}

func genRPC(out string) error {
	desc1 := RpcDescriptorFixture{Name: "desc-1", DomainName: "d", ProtoName: "p", ServiceName: "s", MethodIndex: 7}
	d1 := rpc.RpcDescriptor{DomainName: desc1.DomainName, ProtoName: desc1.ProtoName, ServiceName: desc1.ServiceName, MethodIndex: desc1.MethodIndex}
	w1, _ := d1.Marshal()
	desc1.WireHex = hex.EncodeToString(w1)

	desc2 := RpcDescriptorFixture{Name: "desc-easytier", DomainName: "easytier", ProtoName: "common", ServiceName: "TestService", MethodIndex: 1}
	d2 := rpc.RpcDescriptor{DomainName: desc2.DomainName, ProtoName: desc2.ProtoName, ServiceName: desc2.ServiceName, MethodIndex: desc2.MethodIndex}
	w2, _ := d2.Marshal()
	desc2.WireHex = hex.EncodeToString(w2)

	if err := writeJSON(filepath.Join(out, "rpc/descriptors.json"), []RpcDescriptorFixture{desc1, desc2}); err != nil {
		return err
	}

	pkt1Desc := d1
	pkt1 := RpcPacketFixture{Name: "rpc-packet-1", FromPeer: 1, ToPeer: 2, TransactionID: -1, Descriptor: &desc1, BodyHex: hex.EncodeToString([]byte{0xaa, 0xbb}), IsRequest: true, TotalPieces: 2, PieceIdx: 1, TraceID: -2}
	p1 := rpc.RpcPacket{FromPeer: pkt1.FromPeer, ToPeer: pkt1.ToPeer, TransactionID: pkt1.TransactionID, Descriptor: &pkt1Desc, Body: []byte{0xaa, 0xbb}, IsRequest: true, TotalPieces: 2, PieceIdx: 1, TraceID: -2}
	w3, _ := p1.Marshal()
	pkt1.WireHex = hex.EncodeToString(w3)

	pkt2 := RpcPacketFixture{Name: "rpc-packet-minimal", FromPeer: 123, ToPeer: 0, TransactionID: 0, BodyHex: hex.EncodeToString([]byte("hello")), IsRequest: true}
	p2 := rpc.RpcPacket{FromPeer: 123, Body: []byte("hello"), IsRequest: true}
	w4, _ := p2.Marshal()
	pkt2.WireHex = hex.EncodeToString(w4)

	return writeJSON(filepath.Join(out, "rpc/fixtures.json"), []RpcPacketFixture{pkt1, pkt2})
}

type ConfigFixture struct {
	Name           string `json:"name"`
	Toml           string `json:"toml"`
	NormalizedToml string `json:"normalized_toml"`
}

func genConfig(out string) error {
	fixtures := []ConfigFixture{
		{Name: "minimal", Toml: "network_name = \"test\"\n", NormalizedToml: "network_name = \"test\"\n"},
		{Name: "full", Toml: "network_name = \"mesh\"\nnetwork_secret = \"secret\"\nipv4 = \"10.144.144.1\"\nlisteners = [\"tcp://0.0.0.0:11010\", \"udp://0.0.0.0:11010\"]\n", NormalizedToml: "network_name = \"mesh\"\nnetwork_secret = \"secret\"\nipv4 = \"10.144.144.1\"\nlisteners = [\"tcp://0.0.0.0:11010\", \"udp://0.0.0.0:11010\"]\n"},
	}
	return writeJSON(filepath.Join(out, "config/fixtures.json"), fixtures)
}

type WGFixture struct {
	Name         string `json:"name"`
	PayloadLen   int    `json:"payload_len"`
	PeerHeaderLen int   `json:"peer_header_len"`
	HeaderHex    string `json:"header_hex"`
	TotalLen     int    `json:"total_len"`
}

func wgHeader(payloadLen int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	h[1] = 0
	total := payloadLen + 16 + 20
	h[2] = byte(total >> 8)
	h[3] = byte(total)
	h[4] = 0; h[5] = 0
	h[6] = 0; h[7] = 0
	h[8] = 64
	h[9] = 0
	h[10] = 0; h[11] = 0
	h[12]=0; h[13]=0; h[14]=0; h[15]=0
	h[16]=0; h[17]=0; h[18]=0; h[19]=0
	return h
}

func genWG(out string) error {
	fixtures := []WGFixture{
		{"wg-empty", 0, 16, hex.EncodeToString(wgHeader(0)), 36},
		{"wg-small", 5, 16, hex.EncodeToString(wgHeader(5)), 41},
		{"wg-100", 100, 16, hex.EncodeToString(wgHeader(100)), 136},
		{"wg-mtu", 1380, 16, hex.EncodeToString(wgHeader(1380)), 1416},
	}
	return writeJSON(filepath.Join(out, "wg/fixtures.json"), fixtures)
}

type SecureFixture struct {
	Name        string `json:"name"`
	Suite       string `json:"suite"`
	SuiteID     uint8  `json:"suite_id"`
	RootKeyHex  string `json:"root_key_hex"`
	Epoch       uint32 `json:"epoch"`
	Seq         uint64 `json:"seq"`
	PlaintextHex string `json:"plaintext_hex"`
	WireHex     string `json:"wire_hex"`
	NonceHex    string `json:"nonce_hex"`
}

func genSecure(out string) error {
	rootKey := make([]byte, 32)
	for i := range rootKey { rootKey[i] = 0x11 }
	rootKey2 := make([]byte, 32)
	for i := range rootKey2 { rootKey2[i] = byte(i) }
	fixtures := []SecureFixture{}
	for _, tc := range []struct{
		name string; suite peer.CipherSuite; suiteName string; key []byte; epoch uint32; seq uint64; pt []byte;
	}{
		{"aes128-epoch0-seq0", peer.CipherSuiteAESGCM, "aes-gcm", rootKey, 0, 0, []byte("hello world")},
		{"aes128-epoch1-seq5", peer.CipherSuiteAESGCM, "aes-gcm", rootKey, 1, 5, []byte("test")},
		{"aes256-seq0", peer.CipherSuiteAES256GCM, "aes-256-gcm", rootKey, 0, 0, []byte("hello world")},
		{"chacha20-seq42", peer.CipherSuiteChaCha20Poly1305, "chacha20", rootKey, 42, 42, []byte("easytier secure datagram")},
		{"chacha20-empty", peer.CipherSuiteChaCha20Poly1305, "chacha20", rootKey2, 0, 0, []byte{}},
	} {
		s2, err := peer.NewSecureDatagramSession(tc.key, tc.suite, tc.epoch, peer.DirectionInitiatorToResponder, peer.DirectionResponderToInitiator)
		if err != nil { return err }
		for i := uint64(0); i < tc.seq; i++ {
			_, _ = s2.Seal([]byte("pad"))
		}
		wire, err := s2.Seal(tc.pt)
		if err != nil { return err }
		nonce := wire[len(wire)-12:]
		fixtures = append(fixtures, SecureFixture{
			Name: tc.name, Suite: tc.suiteName, SuiteID: uint8(tc.suite), RootKeyHex: hex.EncodeToString(tc.key), Epoch: tc.epoch, Seq: tc.seq,
			PlaintextHex: hex.EncodeToString(tc.pt), WireHex: hex.EncodeToString(wire), NonceHex: hex.EncodeToString(nonce),
		})
	}
	return writeJSON(filepath.Join(out, "secure/fixtures.json"), fixtures)
}

type RouteFixture struct {
	Name           string  `json:"name"`
	LocalPeerID    uint32  `json:"local_peer_id"`
	Links          []Link  `json:"links"`
	ExpectedRoutes []Route `json:"expected_routes"`
}
type Link struct { A, B, Cost uint32 }
type Route struct { Destination, NextHop uint32; Cost uint64 }

func genRoute(out string) error {
	fixtures := []RouteFixture{
		{
			Name: "line-3", LocalPeerID: 1,
			Links: []Link{{1,2,10},{2,3,10}},
			ExpectedRoutes: []Route{{2,2,10},{3,2,20}},
		},
		{
			Name: "triangle", LocalPeerID: 1,
			Links: []Link{{1,2,5},{2,3,5},{1,3,15}},
			ExpectedRoutes: []Route{{2,2,5},{3,2,10}},
		},
		{
			Name: "equal-cost", LocalPeerID: 1,
			Links: []Link{{1,2,10},{1,3,10},{2,4,10},{3,4,10}},
			ExpectedRoutes: []Route{{2,2,10},{3,3,10},{4,2,20}},
		},
		{
			Name: "star-5", LocalPeerID: 1,
			Links: []Link{{1,2,1},{1,3,1},{1,4,1},{1,5,1}},
			ExpectedRoutes: []Route{{2,2,1},{3,3,1},{4,4,1},{5,5,1}},
		},
	}
	// verify via Engine
	for _, f := range fixtures {
		e := route.NewEngine(f.LocalPeerID)
		for _, l := range f.Links { e.AddLink(l.A, l.B, l.Cost) }
		got := e.Snapshot()
		m := make(map[uint32]Route)
		for _, r := range got { m[r.Destination] = Route{r.Destination, r.NextHop, r.Cost} }
		for _, exp := range f.ExpectedRoutes {
			if g, ok := m[exp.Destination]; !ok || g.NextHop != exp.NextHop || g.Cost != exp.Cost {
				return fmt.Errorf("route fixture %q mismatch: got %+v want %+v", f.Name, g, exp)
			}
		}
	}
	return writeJSON(filepath.Join(out, "route/fixtures.json"), fixtures)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

func TestHandshakeRequestKnownWireVector(t *testing.T) {
	digest := make([]byte, handshakeDigestSize)
	for i := range digest {
		digest[i] = byte(i)
	}
	request := HandshakeRequest{
		Magic:               HandshakeMagic,
		MyPeerID:            0x10203040,
		Version:             HandshakeVersion,
		Features:            []string{"tcp", "quic"},
		NetworkName:         "mesh",
		NetworkSecretDigest: digest,
	}

	got, err := request.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x08, 0xe1, 0xcb, 0x86, 0x8f, 0x0d,
		0x10, 0xc0, 0xe0, 0x80, 0x81, 0x01,
		0x18, 0x01,
		0x22, 0x03, 't', 'c', 'p',
		0x22, 0x04, 'q', 'u', 'i', 'c',
		0x2a, 0x04, 'm', 'e', 's', 'h',
		0x32, 0x20,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire data = %x, want %x", got, want)
	}

	parsed, err := ParseHandshakeRequest(want)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, request) {
		t.Fatalf("parsed = %#v, want %#v", parsed, request)
	}
}

func TestHandshakeRequestMarshalPreservesEmptyFeature(t *testing.T) {
	data, err := (HandshakeRequest{Features: []string{""}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x22, 0x00}; !bytes.Equal(data, want) {
		t.Fatalf("wire data = %x, want %x", data, want)
	}
}

func TestParseHandshakeRequestSkipsSupportedUnknownFields(t *testing.T) {
	digest := bytes.Repeat([]byte{0xab}, handshakeDigestSize)
	data := []byte{
		0x08, 0x01,
		0x38, 0x7f,
		0x41, 1, 2, 3, 4, 5, 6, 7, 8,
		0x4a, 0x03, 'x', 'y', 'z',
		0x55, 9, 10, 11, 12,
		0x32, 0x20,
	}
	data = append(data, digest...)

	request, err := ParseHandshakeRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if request.Magic != 1 || !bytes.Equal(request.NetworkSecretDigest, digest) {
		t.Fatalf("parsed = %#v", request)
	}
}

func TestParseHandshakeRequestRejectsMalformedVarintsAndLengths(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "truncated key", data: []byte{0x80}},
		{name: "overflowing value", data: []byte{0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}},
		{name: "uint32 overflow", data: []byte{0x08, 0x80, 0x80, 0x80, 0x80, 0x10}},
		{name: "truncated length", data: []byte{0x2a, 0x80}},
		{name: "length exceeds data", data: []byte{0x2a, 0x02, 'x'}},
		{name: "overflowing length", data: []byte{0x2a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseHandshakeRequest(test.data); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseHandshakeRequestValidatesPresentDigestLength(t *testing.T) {
	if _, err := ParseHandshakeRequest([]byte{0x32, 0x01, 0}); err == nil {
		t.Fatal("expected invalid digest length error")
	}
	if _, err := ParseHandshakeRequest(nil); err != nil {
		t.Fatalf("absent digest should parse: %v", err)
	}
}

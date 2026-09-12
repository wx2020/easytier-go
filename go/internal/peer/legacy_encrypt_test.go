// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"bytes"
	"errors"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// The golden vectors below were produced from the reference SipHash-1-3 key
// schedule; the same primitive is already pinned by the digest fixtures under
// go/testdata/compat/digest.
func TestDeriveLegacyKeys(t *testing.T) {
	vectors := []struct {
		secret string
		key128 string
		key256 string
	}{
		{
			secret: "",
			key128: "d1fba762150c532c4cf426633e76377d",
			key256: "a2c096544363634f2b0a4489cb8496d919d9f290fe8349cad32bc1da83778cb1",
		},
		{
			secret: "legacy-secret",
			key128: "693ac82788bf212963ee75968c418ab0",
			key256: "03d434189cd7c8458dbde09ebe25f5b251694ce67a691d0f227061521f787561",
		},
		{
			secret: "mesh-secret",
			key128: "1e63c5a12520488a0d80a74946edc13a",
			key256: "90e3243776927708899aee4e82b1b868a4a8cea2bfd8ac0a3915b6cf81fbce93",
		},
	}
	for _, vector := range vectors {
		key128, key256 := protocol.DeriveLegacyKeys(vector.secret)
		if got := hexString(key128[:]); got != vector.key128 {
			t.Errorf("secret %q key128 = %s, want %s", vector.secret, got, vector.key128)
		}
		if got := hexString(key256[:]); got != vector.key256 {
			t.Errorf("secret %q key256 = %s, want %s", vector.secret, got, vector.key256)
		}
	}
}

func hexString(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

func TestXorLegacyCipherGolden(t *testing.T) {
	key128, _ := protocol.DeriveLegacyKeys("legacy-secret")
	cipher, err := NewXorLegacyCipher(key128[:])
	if err != nil {
		t.Fatal(err)
	}
	plaintext, _ := bytesFromHex("48656c6c6f2c20576f726c6421205468697320697320612074657374206d6573736167652e")
	want, _ := bytesFromHex("215fa44be793017e0c9c19f2ad61ded80049e84efb9f4009178b06e2ac2cefc31a5baf42a6")

	packet := protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: append([]byte(nil), plaintext...),
	}
	if err := cipher.Encrypt(&packet); err != nil {
		t.Fatal(err)
	}
	if !packet.Header.IsEncrypted() {
		t.Fatal("xor encrypt did not set the encrypted flag")
	}
	if !bytes.Equal(packet.Payload, want) {
		t.Fatalf("xor ciphertext = %x, want %x", packet.Payload, want)
	}
	if err := cipher.Decrypt(&packet); err != nil {
		t.Fatal(err)
	}
	if packet.Header.IsEncrypted() {
		t.Fatal("xor decrypt did not clear the encrypted flag")
	}
	if !bytes.Equal(packet.Payload, plaintext) {
		t.Fatalf("xor round trip mismatch: %x", packet.Payload)
	}
}

func TestXorLegacyCipherRejectsEmptyKey(t *testing.T) {
	if _, err := NewXorLegacyCipher(nil); err == nil {
		t.Fatal("empty xor key must be rejected")
	}
}

func TestAeadLegacyCipherTailLayout(t *testing.T) {
	key128, _ := protocol.DeriveLegacyKeys("legacy-secret")
	cipher, err := NewAesGcmLegacyCipher(key128)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("secret-payload")
	nonce := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	packet := protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: append([]byte(nil), plaintext...),
	}
	if err := cipher.encryptWithNonce(&packet, nonce); err != nil {
		t.Fatal(err)
	}
	if !packet.Header.IsEncrypted() {
		t.Fatal("aead encrypt did not set the encrypted flag")
	}
	if len(packet.Payload) != len(plaintext)+StandardAeadTailSize {
		t.Fatalf("aead payload = %d, want plaintext + %d tail bytes", len(packet.Payload), StandardAeadTailSize)
	}
	if !bytes.Equal(packet.Payload[len(packet.Payload)-12:], nonce[:]) {
		t.Fatal("aead tail must end with the 12-byte nonce")
	}
	if err := cipher.Decrypt(&packet); err != nil {
		t.Fatal(err)
	}
	if packet.Header.IsEncrypted() {
		t.Fatal("aead decrypt did not clear the encrypted flag")
	}
	if !bytes.Equal(packet.Payload, plaintext) {
		t.Fatalf("aead round trip mismatch: %x", packet.Payload)
	}

	// Tampering with the tag must fail decryption.
	packet.Payload = append([]byte(nil), plaintext...)
	if err := cipher.encryptWithNonce(&packet, nonce); err != nil {
		t.Fatal(err)
	}
	packet.Payload[0] ^= 0xff
	if err := cipher.Decrypt(&packet); err != ErrLegacyDecryptionFailed {
		t.Fatalf("tampered aead packet error = %v, want ErrLegacyDecryptionFailed", err)
	}
}

func TestAeadLegacyCipherShortPayload(t *testing.T) {
	_, key256 := protocol.DeriveLegacyKeys("legacy-secret")
	cipher, err := NewChaCha20LegacyCipher(key256)
	if err != nil {
		t.Fatal(err)
	}
	packet := protocol.Packet{Payload: make([]byte, StandardAeadTailSize-1)}
	packet.Header.SetEncrypted(true)
	if err := cipher.Decrypt(&packet); err != ErrLegacyPacketTooShort {
		t.Fatalf("short payload error = %v, want ErrLegacyPacketTooShort", err)
	}
}

func TestAeadLegacyCipherRoundTrips(t *testing.T) {
	key128, key256 := protocol.DeriveLegacyKeys("mesh-secret")
	plaintext := []byte("round-trip-payload")
	builders := map[string]func() (LegacyCipher, error){
		"aes-gcm":      func() (LegacyCipher, error) { return NewAesGcmLegacyCipher(key128) },
		"aes-256-gcm":  func() (LegacyCipher, error) { return NewAes256GcmLegacyCipher(key256) },
		"chacha20":     func() (LegacyCipher, error) { return NewChaCha20LegacyCipher(key256) },
		"unknown-name": func() (LegacyCipher, error) { return NewLegacyCipher("unknown-name", key128, key256) },
	}
	for name, build := range builders {
		cipher, err := build()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		packet := protocol.Packet{Payload: append([]byte(nil), plaintext...)}
		if err := cipher.Encrypt(&packet); err != nil {
			t.Fatalf("%s encrypt: %v", name, err)
		}
		if len(packet.Payload) <= len(plaintext) {
			t.Fatalf("%s did not extend the payload", name)
		}
		if err := cipher.Decrypt(&packet); err != nil {
			t.Fatalf("%s decrypt: %v", name, err)
		}
		if !bytes.Equal(packet.Payload, plaintext) {
			t.Fatalf("%s round trip mismatch", name)
		}
	}
}

// The fallback for unknown algorithm names must agree with the reference
// default (aes-gcm) byte-for-byte for a fixed nonce.
func TestNewLegacyCipherUnknownFallsBackToAesGcm(t *testing.T) {
	key128, key256 := protocol.DeriveLegacyKeys("mesh-secret")
	fallback, err := NewLegacyCipher("bogus", key128, key256)
	if err != nil {
		t.Fatal(err)
	}
	defaultCipher, err := NewAesGcmLegacyCipher(key128)
	if err != nil {
		t.Fatal(err)
	}
	nonce := [12]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0}
	plaintext := []byte("fallback-check")
	sealed := protocol.Packet{Payload: append([]byte(nil), plaintext...)}
	if err := fallback.(*AeadLegacyCipher).encryptWithNonce(&sealed, nonce); err != nil {
		t.Fatal(err)
	}
	expected := protocol.Packet{Payload: append([]byte(nil), plaintext...)}
	if err := defaultCipher.encryptWithNonce(&expected, nonce); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sealed.Payload, expected.Payload) {
		t.Fatal("unknown algorithm fallback does not match aes-gcm")
	}
}

func TestNullLegacyCipher(t *testing.T) {
	var cipher NullLegacyCipher
	packet := protocol.Packet{Payload: []byte("plain")}
	if err := cipher.Encrypt(&packet); err != nil {
		t.Fatal(err)
	}
	if err := cipher.Decrypt(&packet); err != nil {
		t.Fatal(err)
	}
	packet.Header.SetEncrypted(true)
	if err := cipher.Decrypt(&packet); err != ErrLegacyDecryptionFailed {
		t.Fatalf("null decrypt of encrypted packet = %v, want ErrLegacyDecryptionFailed", err)
	}
}

func bytesFromHex(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		high, err := hexDigit(s[2*i])
		if err != nil {
			return nil, err
		}
		low, err := hexDigit(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = high<<4 | low
	}
	return out, nil
}

func hexDigit(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, errors.New("invalid hex digit")
	}
}

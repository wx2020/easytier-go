// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package wgtest provides a minimal stock-format WireGuard initiator for
// tests. It implements the initiator half of the Noise_IKpsk2 handshake
// (mirroring boringtun format/receive response) so responder code
// (wginterop, vpnportal) can be exercised without a live peer. Test-only.
package wgtest

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/blake2s"
)

const (
	msgInit = 1
	msgResp = 2
	msgData = 4

	initSize = 148
	respSize = 92
)

// Initiator runs one stock handshake and session.
type Initiator struct {
	myPriv       [32]byte
	myPub        [32]byte
	peerPub      [32]byte
	staticShared [32]byte
	mac1Key      [32]byte

	ePriv       [32]byte
	ePub        [32]byte
	chainingKey [32]byte
	hash        [32]byte
	localIndex  uint32

	sendKey     [32]byte
	recvKey     [32]byte
	peerIndex   uint32
	sendCounter uint64
	ready       bool
}

func hash2(a, b []byte) [32]byte {
	h, _ := blake2s.New256(nil)
	h.Write(a)
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func mustECDH(priv, pub [32]byte) [32]byte {
	p, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		panic(err)
	}
	q, err := ecdh.X25519().NewPublicKey(pub[:])
	if err != nil {
		panic(err)
	}
	shared, err := p.ECDH(q)
	if err != nil {
		panic(err)
	}
	var out [32]byte
	copy(out[:], shared)
	return out
}

// New creates an initiator with static identity myPriv talking to peerPub.
func New(myPriv, peerPub [32]byte) (*Initiator, error) {
	pub, err := ecdh.X25519().NewPrivateKey(myPriv[:])
	if err != nil {
		return nil, err
	}
	var myPub [32]byte
	copy(myPub[:], pub.PublicKey().Bytes())
	return &Initiator{
		myPriv:       myPriv,
		myPub:        myPub,
		peerPub:      peerPub,
		staticShared: mustECDH(myPriv, peerPub),
		mac1Key:      hash2([]byte("mac1----"), peerPub[:]),
	}, nil
}

func hmacBLAKE(key, data []byte) [32]byte {
	h := newHMAC(key)
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// BuildInit returns one 148-byte initiation.
func (in *Initiator) BuildInit() ([]byte, error) {
	curve := ecdh.X25519()
	eKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	copy(in.ePriv[:], eKey.Bytes())
	copy(in.ePub[:], eKey.PublicKey().Bytes())
	var idx [4]byte
	if _, err := rand.Read(idx[:]); err != nil {
		return nil, err
	}
	in.localIndex = binary.LittleEndian.Uint32(idx[:]) | 0x02000000

	out := make([]byte, initSize)
	binary.LittleEndian.PutUint32(out[0:4], msgInit)
	binary.LittleEndian.PutUint32(out[4:8], in.localIndex)
	copy(out[8:40], in.ePub[:])

	ck := initialChainKey()
	h := initialChainHash()
	h = hash2(h[:], in.peerPub[:])
	h = hash2(h[:], in.ePub[:])
	shared := mustECDH(in.ePriv, in.peerPub)
	inner := hmacBLAKE(ck[:], in.ePub[:])
	temp := hmacBLAKE(inner[:], []byte{0x01})
	ck = temp
	temp = hmacBLAKE(ck[:], shared[:])
	ck = hmacBLAKE(temp[:], []byte{0x01})
	key := hmac2BLAKE(temp[:], ck[:], []byte{0x02})
	copy(out[40:88], sealCounter(key[:], 0, in.myPub[:], h[:]))
	h = hash2(h[:], out[40:88])
	temp = hmacBLAKE(ck[:], in.staticShared[:])
	ck = hmacBLAKE(temp[:], []byte{0x01})
	key = hmac2BLAKE(temp[:], ck[:], []byte{0x02})
	stamp := tai64Now()
	copy(out[88:116], sealCounter(key[:], 0, stamp[:], h[:]))
	h = hash2(h[:], out[88:116])
	in.chainingKey = ck
	in.hash = h
	m1 := keyedMAC16(in.mac1Key[:], out[:116])
	copy(out[116:132], m1[:])
	return out, nil
}

// OpenResponse processes the 92-byte response, completing the handshake.
func (in *Initiator) OpenResponse(resp []byte) error {
	if len(resp) != respSize || binary.LittleEndian.Uint32(resp[0:4]) != msgResp {
		return fmt.Errorf("wgtest: bad response")
	}
	if got := binary.LittleEndian.Uint32(resp[8:12]); got != in.localIndex {
		return fmt.Errorf("wgtest: receiver index mismatch")
	}
	in.peerIndex = binary.LittleEndian.Uint32(resp[4:8])
	var rEPub [32]byte
	copy(rEPub[:], resp[12:44])
	h := hash2(in.hash[:], rEPub[:])
	temp := hmacBLAKE(in.chainingKey[:], rEPub[:])
	ck := hmacBLAKE(temp[:], []byte{0x01})
	shared := mustECDH(in.ePriv, rEPub)
	temp = hmacBLAKE(ck[:], shared[:])
	ck = hmacBLAKE(temp[:], []byte{0x01})
	shared2 := mustECDH(in.myPriv, rEPub)
	temp = hmacBLAKE(ck[:], shared2[:])
	ck = hmacBLAKE(temp[:], []byte{0x01})
	var zeroPSK [32]byte
	temp = hmacBLAKE(ck[:], zeroPSK[:])
	ck = hmacBLAKE(temp[:], []byte{0x01})
	temp2 := hmac2BLAKE(temp[:], ck[:], []byte{0x02})
	key := hmac2BLAKE(temp[:], temp2[:], []byte{0x03})
	h = hash2(h[:], temp2[:])
	if _, err := openCounter(key[:], 0, resp[44:60], h[:]); err != nil {
		return fmt.Errorf("wgtest: response auth: %w", err)
	}
	t1 := hmacBLAKE(ck[:], nil)
	in.sendKey = hmacBLAKE(t1[:], []byte{0x01})
	in.recvKey = hmac2BLAKE(t1[:], in.sendKey[:], []byte{0x02})
	in.ready = true
	return nil
}

// Seal encrypts one transport data packet.
func (in *Initiator) Seal(plaintext []byte) []byte {
	if !in.ready {
		panic("wgtest: handshake not complete")
	}
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], msgData)
	binary.LittleEndian.PutUint32(out[4:8], in.peerIndex)
	binary.LittleEndian.PutUint64(out[8:16], in.sendCounter)
	sealed := sealCounter(in.sendKey[:], in.sendCounter, plaintext, nil)
	in.sendCounter++
	return append(out, sealed...)
}

// Open decrypts one responder data packet.
func (in *Initiator) Open(datagram []byte) ([]byte, error) {
	if len(datagram) < 16 || binary.LittleEndian.Uint32(datagram[0:4]) != msgData {
		return nil, fmt.Errorf("wgtest: bad data packet")
	}
	counter := binary.LittleEndian.Uint64(datagram[8:16])
	return openCounter(in.recvKey[:], counter, datagram[16:], nil)
}

// PeerIndex returns the responder session index (data receiver index).
func (in *Initiator) PeerIndex() uint32 { return in.peerIndex }

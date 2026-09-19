// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package wginterop

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"sync"
)

// Field offsets inside a 148-byte initiation, matching boringtun parse.
const (
	initSenderIdxOff = 4
	initEPubOff      = 8
	initStaticOff    = 40
	initStaticSize   = 48
	initTsOff        = 88
	initTsSize       = 28
	initMac1Off      = 116
	initMac2Off      = 132
)

// initiation is a parsed handshake initiation.
type initiation struct {
	senderIdx uint32
	ePub      [32]byte
	encStatic []byte
	encTs     []byte
	mac1      []byte
	mac2      []byte
	rawNoMACs []byte
}

func parseInitiation(datagram []byte) (initiation, error) {
	if len(datagram) != HandshakeInitSize || binary.LittleEndian.Uint32(datagram[0:4]) != MsgTypeHandshakeInit {
		return initiation{}, ErrInvalidPacket
	}
	var init initiation
	init.senderIdx = binary.LittleEndian.Uint32(datagram[initSenderIdxOff : initSenderIdxOff+4])
	copy(init.ePub[:], datagram[initEPubOff:initEPubOff+32])
	init.encStatic = datagram[initStaticOff : initStaticOff+initStaticSize]
	init.encTs = datagram[initTsOff : initTsOff+initTsSize]
	init.mac1 = datagram[initMac1Off : initMac1Off+MacSize]
	init.mac2 = datagram[initMac2Off : initMac2Off+MacSize]
	init.rawNoMACs = datagram[:initMac1Off]
	return init, nil
}

// timestampReplay remembers the newest accepted handshake timestamp,
// mirroring boringtun Handshake::last_handshake_timestamp.
type timestampReplay struct {
	mu   sync.Mutex
	last [12]byte
}

func (t *timestampReplay) accept(stamp [12]byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !tai64After(stamp, t.last) {
		return false
	}
	t.last = stamp
	return true
}

// Responder answers stock handshake initiations for one static identity.
type Responder struct {
	staticPriv   [32]byte
	staticPub    [32]byte
	peerPub      [32]byte
	staticShared [32]byte
	mac1Key      [32]byte

	mu        sync.Mutex
	nextIndex uint32
	stamps    timestampReplay
}

// NewResponder creates a responder for staticPriv talking to peerPub.
func NewResponder(staticPriv, peerPub [32]byte) (*Responder, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(staticPriv[:])
	if err != nil {
		return nil, err
	}
	pub, err := curve.NewPublicKey(peerPub[:])
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	var ss [32]byte
	copy(ss[:], shared)
	myPub, err := PublicKey(staticPriv)
	if err != nil {
		return nil, err
	}
	var start [4]byte
	if _, err := rand.Read(start[:]); err != nil {
		return nil, err
	}
	return &Responder{
		staticPriv:   staticPriv,
		staticPub:    myPub,
		peerPub:      peerPub,
		staticShared: ss,
		mac1Key:      hash2([]byte(labelMAC1), peerPub[:]),
		nextIndex:    binary.LittleEndian.Uint32(start[:]) | 0x01000000,
	}, nil
}

// allocation indexes like boringtun inc_index: low 8 bits cycle.
func (r *Responder) allocIndex() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := r.nextIndex
	r.nextIndex = (index & ^uint32(0xff)) | uint32(uint8(index)+1)
	return index
}

// Respond authenticates init (MAC1 verified by the caller/rate limiter;
// static identity, timestamp and replay checked here) and builds the
// 92-byte response plus the responder session keys. It mirrors boringtun
// receive_handshake_initialization + format_handshake_response. The
// returned local index is the response sender index: sessions must be
// stored under it.
func (r *Responder) Respond(init initiation) (response []byte, localIndex uint32, receivingKey, sendingKey [32]byte, err error) {
	chainingKey := initialChainKey
	hash := initialChainHash
	hash = hash2(hash[:], r.staticPub[:])
	hash = hash2(hash[:], init.ePub[:])

	inner := hmac1(chainingKey[:], init.ePub[:])
	temp := hmac1(inner[:], []byte{0x01})
	chainingKey = temp
	ephemeralShared, err := ecdhShared(r.staticPriv, init.ePub)
	if err != nil {
		return nil, 0, receivingKey, sendingKey, err
	}
	temp = hmac1(chainingKey[:], ephemeralShared[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	key := hmac2(temp[:], chainingKey[:], []byte{0x02})

	peerStatic, err := openAEAD(key[:], 0, init.encStatic, hash[:])
	if err != nil || len(peerStatic) != 32 {
		return nil, 0, receivingKey, sendingKey, ErrWrongKey
	}
	var initiatorPub [32]byte
	copy(initiatorPub[:], peerStatic)
	if initiatorPub != r.peerPub {
		return nil, 0, receivingKey, sendingKey, ErrWrongKey
	}

	hash = hash2(hash[:], init.encStatic)
	temp = hmac1(chainingKey[:], r.staticShared[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	key = hmac2(temp[:], chainingKey[:], []byte{0x02})
	tsRaw, err := openAEAD(key[:], 0, init.encTs, hash[:])
	if err != nil || len(tsRaw) != TimestampSize {
		return nil, 0, receivingKey, sendingKey, ErrInvalidTag
	}
	var stamp [12]byte
	copy(stamp[:], tsRaw)
	if !r.stamps.accept(stamp) {
		return nil, 0, receivingKey, sendingKey, ErrStaleTimestamp
	}
	hash = hash2(hash[:], init.encTs)

	ePriv, ePub, err := generateX25519()
	if err != nil {
		return nil, 0, receivingKey, sendingKey, err
	}
	localIndex = r.allocIndex()

	response = make([]byte, HandshakeRespSize)
	binary.LittleEndian.PutUint32(response[0:4], MsgTypeHandshakeResponse)
	binary.LittleEndian.PutUint32(response[4:8], localIndex)
	binary.LittleEndian.PutUint32(response[8:12], init.senderIdx)
	copy(response[12:44], ePub[:])

	hash = hash2(hash[:], ePub[:])
	temp = hmac1(chainingKey[:], ePub[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	dhEE, err := ecdhShared(ePriv, init.ePub)
	if err != nil {
		return nil, 0, receivingKey, sendingKey, err
	}
	temp = hmac1(chainingKey[:], dhEE[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	dhES, err := ecdhShared(ePriv, initiatorPub)
	if err != nil {
		return nil, 0, receivingKey, sendingKey, err
	}
	temp = hmac1(chainingKey[:], dhES[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	var zeroPSK [32]byte
	temp = hmac1(chainingKey[:], zeroPSK[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	temp2 := hmac2(temp[:], chainingKey[:], []byte{0x02})
	key = hmac2(temp[:], temp2[:], []byte{0x03})
	hash = hash2(hash[:], temp2[:])
	sealedNothing := sealAEAD(nil, key[:], 0, nil, hash[:])
	copy(response[44:60], sealedNothing)

	temp1 := hmac1(chainingKey[:], nil)
	k2 := hmac1(temp1[:], []byte{0x01})
	k3 := hmac2(temp1[:], k2[:], []byte{0x02})
	// Responder: receiving = temp2-equivalent? No: Session::new(local,
	// peer, temp2, temp3) with (receiving, sending) order.
	receivingKey = k2
	sendingKey = k3

	appendMACs(response, r.mac1Key, nil)
	return response, localIndex, receivingKey, sendingKey, nil
}

// appendMACs fills mac1 (always) and mac2 (under cookie) like boringtun
// append_mac1_and_mac2. cookie nil => zero mac2.
func appendMACs(message []byte, mac1Key [32]byte, cookie []byte) {
	mac1Off := len(message) - 32
	mac2Off := len(message) - 16
	m1 := mac16(mac1Key[:], message[:mac1Off])
	copy(message[mac1Off:mac2Off], m1[:])
	if cookie == nil {
		for i := mac2Off; i < len(message); i++ {
			message[i] = 0
		}
		return
	}
	m2 := mac16(cookie, message[:mac2Off])
	copy(message[mac2Off:], m2[:])
}

// verifyMAC1 checks the initiation MAC1 with the responder key.
func verifyMAC1(mac1Key [32]byte, datagram []byte) bool {
	if len(datagram) < 32 {
		return false
	}
	mac1Off := len(datagram) - 32
	m1 := mac16(mac1Key[:], datagram[:mac1Off])
	var a, b [16]byte
	copy(a[:], m1[:])
	copy(b[:], datagram[mac1Off:mac1Off+16])
	return verifyEqual(a[:], b[:])
}

// mac1KeyFor derives HASH("mac1----" || responderPub) for verifying an
// initiation addressed to us.
func mac1KeyFor(responderPub [32]byte) [32]byte {
	return hash2([]byte(labelMAC1), responderPub[:])
}

func ecdhShared(priv, pub [32]byte) ([32]byte, error) {
	curve := ecdh.X25519()
	privateKey, err := curve.NewPrivateKey(priv[:])
	if err != nil {
		return [32]byte{}, err
	}
	publicKey, err := curve.NewPublicKey(pub[:])
	if err != nil {
		return [32]byte{}, err
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], shared)
	return out, nil
}

// PublicKey derives the X25519 public key for priv. Used by callers that
// hold a raw static private and need its public half (e.g. WG interop
// against a peer that derives its key from the network identity).
func PublicKey(priv [32]byte) ([32]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], key.PublicKey().Bytes())
	return out, nil
}

func generateX25519() (priv, pub [32]byte, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return priv, pub, err
	}
	copy(priv[:], key.Bytes())
	copy(pub[:], key.PublicKey().Bytes())
	return priv, pub, nil
}

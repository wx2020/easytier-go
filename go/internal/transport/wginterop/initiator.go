// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package wginterop

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
)

// Initiator builds and sends standard WireGuard handshakes (boringtun-
// compatible Noise IK), completing the client half of the wg:// tunnel.
// The responder half lives in handshake.go; both share the same crypto
// primitives and wire sizes.
type Initiator struct {
	staticPriv   [32]byte
	staticPub    [32]byte
	peerPub      [32]byte
	staticShared [32]byte
	mac1Key      [32]byte

	mu                sync.Mutex
	nextIndex         uint32
	lastInitEPriv     [32]byte
	lastInitEpub      [32]byte
	lastInitHash      [32]byte
	lastInitChain     [32]byte
	lastInitEncStatic [32]byte
	lastInitSenderIdx uint32
	lastInitSharedEE  [32]byte
	stamp             [12]byte
}

// NewInitiator creates a client for staticPriv talking to peerPub.
func NewInitiator(staticPriv, peerPub [32]byte) (*Initiator, error) {
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
	myPub, err := x25519Public(staticPriv)
	if err != nil {
		return nil, err
	}
	var start [4]byte
	if _, err := rand.Read(start[:]); err != nil {
		return nil, err
	}
	return &Initiator{
		staticPriv:   staticPriv,
		staticPub:    myPub,
		peerPub:      peerPub,
		staticShared: ss,
		mac1Key:      hash2([]byte(labelMAC1), peerPub[:]),
		nextIndex:    binary.LittleEndian.Uint32(start[:]) | 0x01000000,
	}, nil
}

func (i *Initiator) allocIndex() uint32 {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.allocIndexLocked()
}

// allocIndexLocked is the unsynchronized core; callers holding i.mu use
// this directly (Go mutexes are not reentrant).
func (i *Initiator) allocIndexLocked() uint32 {
	index := i.nextIndex
	i.nextIndex = (index & ^uint32(0xff)) | uint32(uint8(index)+1)
	return index
}

// FormatHandshakeInitiation builds the 148-byte initiation, mirroring
// boringtun format_handshake_initiation. It stores the handshake state so
// ConsumeHandshakeResponse can complete the exchange.
func (i *Initiator) FormatHandshakeInitiation() ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	chainingKey := initialChainKey
	hash := initialChainHash
	hash = hash2(hash[:], i.peerPub[:])

	ePriv, ePub, err := generateX25519()
	if err != nil {
		return nil, err
	}
	hash = hash2(hash[:], ePub[:])
	inner := hmac1(chainingKey[:], ePub[:])
	temp := hmac1(inner[:], []byte{0x01})
	chainingKey = temp
	// The static key is sealed under the EPHEMERAL-STATIC secret
	// (initiator ephemeral x responder static), matching boringtun and
	// the responder's open step; the static-static secret comes later.
	sharedES, err := ecdhShared(ePriv, i.peerPub)
	if err != nil {
		return nil, err
	}
	temp = hmac1(chainingKey[:], sharedES[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	key := hmac2(temp[:], chainingKey[:], []byte{0x02})
	encStatic := sealAEAD(nil, key[:], 0, i.staticPub[:], hash[:])
	if len(encStatic) != initStaticSize {
		return nil, errors.New("wginterop: static seal size mismatch")
	}
	hash = hash2(hash[:], encStatic)

	// TAI64N timestamp, monotonically advancing across handshakes.
	stamp := tai64Now()
	if stampAfter(stamp, i.stamp) {
		i.stamp = stamp
	}
	var ts [12]byte
	copy(ts[:], i.stamp[:])
	temp = hmac1(chainingKey[:], i.staticShared[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	key = hmac2(temp[:], chainingKey[:], []byte{0x02})
	encTs := sealAEAD(nil, key[:], 0, ts[:], hash[:])
	if len(encTs) != initTsSize {
		return nil, errors.New("wginterop: timestamp seal size mismatch")
	}
	hash = hash2(hash[:], encTs)

	senderIdx := i.allocIndexLocked()
	init := make([]byte, HandshakeInitSize)
	binary.LittleEndian.PutUint32(init[0:4], MsgTypeHandshakeInit)
	binary.LittleEndian.PutUint32(init[initSenderIdxOff:initSenderIdxOff+4], senderIdx)
	copy(init[initEPubOff:initEPubOff+32], ePub[:])
	copy(init[initStaticOff:initStaticOff+initStaticSize], encStatic)
	copy(init[initTsOff:initTsOff+initTsSize], encTs)
	appendMACs(init, i.mac1Key, nil)

	// Preserve the handshake state for the response.
	i.lastInitEPriv = ePriv
	i.lastInitEpub = ePub
	i.lastInitHash = hash
	i.lastInitChain = chainingKey
	copy(i.lastInitEncStatic[:], encStatic)
	i.lastInitSenderIdx = senderIdx
	dhEES, err := ecdhShared(ePriv, i.peerPub)
	if err != nil {
		return nil, err
	}
	i.lastInitSharedEE = dhEES
	return init, nil
}

// ConsumeHandshakeResponse authenticates the 92-byte response and derives
// the transport session keys, mirroring boringtun
// receive_handshake_response + Session::new. The returned session has
// receiving/sending oriented for the initiator: we receive under the
// responder's temp2 chain, send under temp3.
func (i *Initiator) ConsumeHandshakeResponse(datagram []byte) (*Session, error) {
	if len(datagram) != HandshakeRespSize || binary.LittleEndian.Uint32(datagram[0:4]) != MsgTypeHandshakeResponse {
		return nil, ErrInvalidPacket
	}
	i.mu.Lock()
	defer i.mu.Unlock()

	senderIdx := binary.LittleEndian.Uint32(datagram[4:8])
	ourIdx := binary.LittleEndian.Uint32(datagram[8:12])
	if ourIdx != i.lastInitSenderIdx {
		return nil, ErrWrongIndex
	}
	var rEpub [32]byte
	copy(rEpub[:], datagram[12:44])

	chainingKey := i.lastInitChain
	hash := i.lastInitHash
	hash = hash2(hash[:], rEpub[:])
	temp := hmac1(chainingKey[:], rEpub[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	temp = hmac1(chainingKey[:], i.lastInitSharedEE[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	// Initiator's static x responder ephemeral: the mirror of the
	// responder's ES step.
	dhSE, err := ecdhShared(i.staticPriv, rEpub)
	if err != nil {
		return nil, err
	}
	temp = hmac1(chainingKey[:], dhSE[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	var zeroPSK [32]byte
	temp = hmac1(chainingKey[:], zeroPSK[:])
	chainingKey = hmac1(temp[:], []byte{0x01})
	temp2 := hmac2(temp[:], chainingKey[:], []byte{0x02})
	key := hmac2(temp[:], temp2[:], []byte{0x03})
	hash = hash2(hash[:], temp2[:])

	// Verify the responder's empty AEAD tag.
	if _, err := openAEAD(key[:], 0, datagram[44:60], hash[:]); err != nil {
		return nil, ErrInvalidTag
	}

	temp1 := hmac1(chainingKey[:], nil)
	k2 := hmac1(temp1[:], []byte{0x01})
	k3 := hmac2(temp1[:], k2[:], []byte{0x02})
	// Initiator session: we send under temp3 (k3) and receive under temp2
	// (k2); the responder built the mirror. Session stores (receiving,
	// sending) and its own send/receive indexes: we receive on the
	// responder's sender index, and send with our receiver index as the
	// responder-side receiving hint is irrelevant for data (data packets
	// carry the receiver's local index, i.e. the responder's localIndex).
	session := NewSession(senderIdx, ourIdx, k2, k3)
	return session, nil
}

func stampAfter(a, b [12]byte) bool {
	return tai64After(a, b)
}

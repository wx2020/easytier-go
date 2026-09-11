// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package wginterop

import (
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// Receiving bitmap constants, matching boringtun noise/session.rs.
const (
	replayWordSize = 64
	replayNWords   = 16
	replayNBits    = replayWordSize * replayNWords // 1024 packets of reorder window
)

// Session is one established transport session, mirroring boringtun
// noise/session.rs Session: dual AEAD keys, atomic-style send counter,
// bitmap replay validator.
type Session struct {
	receivingIndex uint32
	sendingIndex   uint32
	receiver       []byte
	sender         []byte

	mu       sync.Mutex
	sendNext uint64
	recvNext uint64
	recvCnt  uint64
	bitmap   [replayNWords]uint64

	lastUsedUnix int64
}

// NewSession creates a session. receivingKey decrypts inbound packets
// addressed to localIndex; sendingKey encrypts towards peerIndex.
func NewSession(localIndex, peerIndex uint32, receivingKey, sendingKey [32]byte) *Session {
	return &Session{
		receivingIndex: localIndex,
		sendingIndex:   peerIndex,
		receiver:       append([]byte(nil), receivingKey[:]...),
		sender:         append([]byte(nil), sendingKey[:]...),
	}
}

func (s *Session) setBit(idx uint64) {
	bit := idx % replayNBits
	s.bitmap[(bit / replayWordSize)] |= 1 << (bit % replayWordSize)
}

func (s *Session) clearBit(idx uint64) {
	bit := idx % replayNBits
	s.bitmap[(bit / replayWordSize)] &= ^(uint64(1) << (bit % replayWordSize))
}

func (s *Session) clearWord(idx uint64) {
	bit := idx % replayNBits
	s.bitmap[bit/replayWordSize] = 0
}

func (s *Session) checkBit(idx uint64) bool {
	bit := idx % replayNBits
	return (s.bitmap[bit/replayWordSize]>>(bit%replayWordSize))&1 == 1
}

// willAccept mirrors ReceivingKeyCounterValidator::will_accept.
func (s *Session) willAccept(counter uint64) error {
	if counter >= s.recvNext {
		return nil
	}
	if counter+replayNBits < s.recvNext {
		return ErrInvalidCounter
	}
	if !s.checkBit(counter) {
		return nil
	}
	return ErrDuplicateCounter
}

// markReceived mirrors ReceivingKeyCounterValidator::mark_did_receive.
func (s *Session) markReceived(counter uint64) error {
	if counter+replayNBits < s.recvNext {
		return ErrInvalidCounter
	}
	if counter == s.recvNext {
		s.setBit(counter)
		s.recvNext++
		return nil
	}
	if counter < s.recvNext {
		if s.checkBit(counter) {
			return ErrInvalidCounter
		}
		s.setBit(counter)
		return nil
	}
	if counter-s.recvNext >= replayNBits {
		for i := range s.bitmap {
			s.bitmap[i] = 0
		}
	} else {
		i := s.recvNext
		for i%replayWordSize != 0 && i < counter {
			s.clearBit(i)
			i++
		}
		for i+replayWordSize < counter {
			s.clearWord(i)
			i = (i + replayWordSize) & ^uint64(replayWordSize-1)
		}
		for i < counter {
			s.clearBit(i)
			i++
		}
	}
	s.setBit(counter)
	s.recvNext = counter + 1
	return nil
}

// SealData formats one transport data packet (boringtun format_packet_data).
func (s *Session) SealData(plaintext []byte) []byte {
	s.mu.Lock()
	counter := s.sendNext
	s.sendNext++
	s.mu.Unlock()

	out := make([]byte, DataHeaderSize, DataHeaderSize+len(plaintext)+16)
	binary.LittleEndian.PutUint32(out[0:4], MsgTypeData)
	binary.LittleEndian.PutUint32(out[4:8], s.sendingIndex)
	binary.LittleEndian.PutUint64(out[8:16], counter)
	aead, err := chacha20poly1305.New(s.sender)
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	sealed := aead.Seal(nil, nonce[:], plaintext, nil)
	return append(out, sealed...)
}

// dataPacket is a parsed transport data message.
type dataPacket struct {
	receiverIndex uint32
	counter       uint64
	ciphertext    []byte
}

func parseData(datagram []byte) (dataPacket, error) {
	if len(datagram) < DataHeaderSize || binary.LittleEndian.Uint32(datagram[0:4]) != MsgTypeData {
		return dataPacket{}, ErrInvalidPacket
	}
	return dataPacket{
		receiverIndex: binary.LittleEndian.Uint32(datagram[4:8]),
		counter:       binary.LittleEndian.Uint64(datagram[8:16]),
		ciphertext:    datagram[DataHeaderSize:],
	}, nil
}

// OpenData authenticates and decrypts one data packet
// (boringtun receive_packet_data: index check, quick counter check,
// decrypt, mark).
func (s *Session) OpenData(datagram []byte) ([]byte, error) {
	packet, err := parseData(datagram)
	if err != nil {
		return nil, err
	}
	if packet.receiverIndex != s.receivingIndex {
		return nil, ErrWrongIndex
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.willAccept(packet.counter); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(s.receiver)
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], packet.counter)
	plaintext, err := aead.Open(nil, nonce[:], packet.ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidTag
	}
	if err := s.markReceived(packet.counter); err != nil {
		return nil, err
	}
	s.recvCnt++
	return plaintext, nil
}

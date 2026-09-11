// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package stun

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	messageHeaderSize = 20
	maxMessageSize    = 576
	magicCookie       = 0x2112A442

	bindingRequest   = 0x0001
	bindingSuccess   = 0x0101
	xorMappedAddress = 0x0020
)

var errNoXORMappedAddress = errors.New("STUN binding response has no XOR-MAPPED-ADDRESS")

// Bind sends an RFC 5389 Binding Request to server and returns its mapped address.
func Bind(ctx context.Context, server string) (netip.AddrPort, error) {
	if ctx == nil {
		return netip.AddrPort{}, errors.New("STUN context is nil")
	}
	if err := ctx.Err(); err != nil {
		return netip.AddrPort{}, err
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", server)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("dial STUN server %q: %w", server, err)
	}
	defer conn.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return netip.AddrPort{}, fmt.Errorf("set STUN deadline: %w", err)
		}
	}

	request, transactionID, err := bindingRequestMessage()
	if err != nil {
		return netip.AddrPort{}, err
	}
	if _, err := conn.Write(request); err != nil {
		if ctx.Err() != nil {
			return netip.AddrPort{}, ctx.Err()
		}
		return netip.AddrPort{}, fmt.Errorf("send STUN binding request: %w", err)
	}

	var buffer [maxMessageSize + 1]byte
	for {
		n, err := conn.Read(buffer[:])
		if err != nil {
			if contextErr := stunContextError(ctx); contextErr != nil {
				return netip.AddrPort{}, contextErr
			}
			return netip.AddrPort{}, fmt.Errorf("read STUN binding response: %w", err)
		}
		if n > maxMessageSize {
			return netip.AddrPort{}, fmt.Errorf("STUN response exceeds %d bytes", maxMessageSize)
		}

		responseTransactionID, err := responseTransactionID(buffer[:n])
		if err != nil {
			return netip.AddrPort{}, err
		}
		if responseTransactionID != transactionID {
			continue
		}
		mapped, err := parseBindingResponse(buffer[:n], transactionID)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return mapped, nil
	}
}

func stunContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func bindingRequestMessage() ([]byte, [12]byte, error) {
	var transactionID [12]byte
	if _, err := cryptorand.Read(transactionID[:]); err != nil {
		return nil, transactionID, fmt.Errorf("generate STUN transaction ID: %w", err)
	}
	copy(transactionID[:4], []byte{0xde, 0xad, 0xbe, 0xef})

	message := make([]byte, messageHeaderSize)
	binary.BigEndian.PutUint16(message[:2], bindingRequest)
	binary.BigEndian.PutUint32(message[4:8], magicCookie)
	copy(message[8:], transactionID[:])
	return message, transactionID, nil
}

func responseTransactionID(message []byte) ([12]byte, error) {
	var transactionID [12]byte
	if len(message) < messageHeaderSize {
		return transactionID, errors.New("STUN response is shorter than its header")
	}
	if binary.BigEndian.Uint32(message[4:8]) != magicCookie {
		return transactionID, errors.New("STUN response has an invalid magic cookie")
	}
	copy(transactionID[:], message[8:20])
	return transactionID, nil
}

func parseBindingResponse(message []byte, transactionID [12]byte) (netip.AddrPort, error) {
	if len(message) < messageHeaderSize {
		return netip.AddrPort{}, errors.New("STUN response is shorter than its header")
	}
	if binary.BigEndian.Uint16(message[:2]) != bindingSuccess {
		return netip.AddrPort{}, errors.New("STUN response is not a Binding Success Response")
	}
	length := int(binary.BigEndian.Uint16(message[2:4]))
	if length%4 != 0 || length != len(message)-messageHeaderSize {
		return netip.AddrPort{}, errors.New("STUN response has an invalid message length")
	}
	if binary.BigEndian.Uint32(message[4:8]) != magicCookie {
		return netip.AddrPort{}, errors.New("STUN response has an invalid magic cookie")
	}
	if got := message[8:20]; !bytes.Equal(got, transactionID[:]) {
		return netip.AddrPort{}, errors.New("STUN response has an unexpected transaction ID")
	}

	var mapped netip.AddrPort
	foundMapped := false
	for offset := messageHeaderSize; offset < len(message); {
		if len(message)-offset < 4 {
			return netip.AddrPort{}, errors.New("STUN response has a truncated attribute header")
		}
		attributeType := binary.BigEndian.Uint16(message[offset : offset+2])
		attributeLength := int(binary.BigEndian.Uint16(message[offset+2 : offset+4]))
		offset += 4
		paddedLength := (attributeLength + 3) &^ 3
		if paddedLength > len(message)-offset {
			return netip.AddrPort{}, errors.New("STUN response has a truncated attribute")
		}
		for _, padding := range message[offset+attributeLength : offset+paddedLength] {
			if padding != 0 {
				return netip.AddrPort{}, errors.New("STUN response has non-zero attribute padding")
			}
		}
		if attributeType == xorMappedAddress {
			if foundMapped {
				return netip.AddrPort{}, errors.New("STUN response has multiple XOR-MAPPED-ADDRESS attributes")
			}
			var err error
			mapped, err = parseXORMappedAddress(message[offset:offset+attributeLength], transactionID)
			if err != nil {
				return netip.AddrPort{}, err
			}
			foundMapped = true
		}
		offset += paddedLength
	}
	if !foundMapped {
		return netip.AddrPort{}, errNoXORMappedAddress
	}
	return mapped, nil
}

func parseXORMappedAddress(value []byte, transactionID [12]byte) (netip.AddrPort, error) {
	if len(value) < 4 || value[0] != 0 {
		return netip.AddrPort{}, errors.New("STUN XOR-MAPPED-ADDRESS has an invalid value")
	}
	port := binary.BigEndian.Uint16(value[2:4]) ^ uint16(magicCookie>>16)
	switch value[1] {
	case 0x01:
		if len(value) != 8 {
			return netip.AddrPort{}, errors.New("STUN IPv4 XOR-MAPPED-ADDRESS has an invalid length")
		}
		var address [4]byte
		cookie := [4]byte{}
		binary.BigEndian.PutUint32(cookie[:], magicCookie)
		for i := range address {
			address[i] = value[4+i] ^ cookie[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom4(address), port), nil
	case 0x02:
		if len(value) != 20 {
			return netip.AddrPort{}, errors.New("STUN IPv6 XOR-MAPPED-ADDRESS has an invalid length")
		}
		var address [16]byte
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[:4], magicCookie)
		copy(mask[4:], transactionID[:])
		for i := range address {
			address[i] = value[4+i] ^ mask[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom16(address), port), nil
	default:
		return netip.AddrPort{}, errors.New("STUN XOR-MAPPED-ADDRESS has an unknown address family")
	}
}

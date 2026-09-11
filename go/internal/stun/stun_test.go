// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package stun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestBindIPv4(t *testing.T) {
	want := netip.MustParseAddrPort("203.0.113.9:54321")
	server := newFakeServer(t, func(request []byte) []byte {
		if len(request) != messageHeaderSize || binary.BigEndian.Uint16(request[:2]) != bindingRequest || binary.BigEndian.Uint16(request[2:4]) != 0 || binary.BigEndian.Uint32(request[4:8]) != magicCookie {
			t.Errorf("invalid Binding Request: %x", request)
		}
		if got := request[8:12]; string(got) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Errorf("transaction ID prefix = %x, want deadbeef", got)
		}
		return bindingResponse(request[8:20], xorMappedAttribute(want, request[8:20]))
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := Bind(ctx, server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Bind() = %v, want %v", got, want)
	}
}

func TestParseBindingResponseIPv6(t *testing.T) {
	transactionID := [12]byte{0xde, 0xad, 0xbe, 0xef, 4, 5, 6, 7, 8, 9, 10, 11}
	want := netip.MustParseAddrPort("[2001:db8::1]:3478")
	got, err := parseBindingResponse(bindingResponse(transactionID[:], xorMappedAttribute(want, transactionID[:])), transactionID)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("parseBindingResponse() = %v, want %v", got, want)
	}
}

func TestBindIPv6MappedAddress(t *testing.T) {
	want := netip.MustParseAddrPort("[2001:db8::1]:3478")
	server := newFakeServer(t, func(request []byte) []byte {
		return bindingResponse(request[8:20], xorMappedAttribute(want, request[8:20]))
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := Bind(ctx, server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Bind() = %v, want %v", got, want)
	}
}

func TestBindRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "cookie",
			mutate: func(response []byte) []byte {
				response[4] ^= 1
				return response
			},
		},
		{
			name: "message length",
			mutate: func(response []byte) []byte {
				response[2], response[3] = 0, 0
				return response
			},
		},
		{
			name: "transaction ID",
			mutate: func(response []byte) []byte {
				response[8] ^= 1
				return response
			},
		},
		{
			name: "attribute length",
			mutate: func(response []byte) []byte {
				response[22], response[23] = 0, 20
				return response
			},
		},
		{
			name: "xor mapped address length",
			mutate: func(response []byte) []byte {
				response[22], response[23] = 0, 7
				return response
			},
		},
		{
			name: "attribute padding",
			mutate: func(response []byte) []byte {
				response = append(response, 0, 1, 0, 1, 0, 1, 0, 0)
				binary.BigEndian.PutUint16(response[2:4], uint16(len(response)-messageHeaderSize))
				return response
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newFakeServer(t, func(request []byte) []byte {
				response := bindingResponse(request[8:20], xorMappedAttribute(netip.MustParseAddrPort("192.0.2.1:1"), request[8:20]))
				return test.mutate(response)
			})
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := Bind(ctx, server.LocalAddr().String()); err == nil {
				t.Fatal("Bind accepted malformed response")
			}
		})
	}
}

func TestBindHonorsContextDeadline(t *testing.T) {
	server := newFakeServer(t, func([]byte) []byte { return nil })
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := Bind(ctx, server.LocalAddr().String()); err != context.DeadlineExceeded {
		t.Fatalf("Bind() error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func newFakeServer(t *testing.T, reply func([]byte) []byte) *net.UDPConn {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buffer := make([]byte, maxMessageSize)
		n, client, err := server.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if response := reply(buffer[:n]); response != nil {
			_, _ = server.WriteToUDP(response, client)
		}
	}()
	return server
}

func bindingResponse(transactionID []byte, attribute []byte) []byte {
	response := make([]byte, messageHeaderSize+len(attribute))
	binary.BigEndian.PutUint16(response[:2], bindingSuccess)
	binary.BigEndian.PutUint16(response[2:4], uint16(len(attribute)))
	binary.BigEndian.PutUint32(response[4:8], magicCookie)
	copy(response[8:20], transactionID)
	copy(response[20:], attribute)
	return response
}

func xorMappedAttribute(address netip.AddrPort, transactionID []byte) []byte {
	if address.Addr().Is4() {
		attribute := make([]byte, 12)
		binary.BigEndian.PutUint16(attribute[:2], xorMappedAddress)
		binary.BigEndian.PutUint16(attribute[2:4], 8)
		attribute[5] = 0x01
		binary.BigEndian.PutUint16(attribute[6:8], address.Port()^uint16(magicCookie>>16))
		cookie := [4]byte{}
		binary.BigEndian.PutUint32(cookie[:], magicCookie)
		for i, octet := range address.Addr().As4() {
			attribute[8+i] = octet ^ cookie[i]
		}
		return attribute
	}
	attribute := make([]byte, 24)
	binary.BigEndian.PutUint16(attribute[:2], xorMappedAddress)
	binary.BigEndian.PutUint16(attribute[2:4], 20)
	attribute[5] = 0x02
	binary.BigEndian.PutUint16(attribute[6:8], address.Port()^uint16(magicCookie>>16))
	mask := make([]byte, 16)
	binary.BigEndian.PutUint32(mask[:4], magicCookie)
	copy(mask[4:], transactionID)
	for i, octet := range address.Addr().As16() {
		attribute[8+i] = octet ^ mask[i]
	}
	return attribute
}

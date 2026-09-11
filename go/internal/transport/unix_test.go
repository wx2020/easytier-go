// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestUnixPacketChannelRoundTripAndCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "easytier.sock")
	listener, err := ListenUnix(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	accepted := make(chan *UnixPacketChannel, 1)
	go func() {
		channel, err := listener.Accept(context.Background())
		if err == nil {
			accepted <- channel
		}
	}()

	client, err := DialUnix(context.Background(), path, 0)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	packet := protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData},
		Payload: []byte("unix packet"),
	}
	if err := client.Send(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	got, err := server.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Header != (protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData, Length: 11}) || string(got.Payload) != "unix packet" {
		t.Fatalf("packet = %#v", got)
	}

	reply := protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 1, PacketType: protocol.PacketTypePong},
		Payload: []byte("unix reply"),
	}
	if err := server.Send(context.Background(), reply); err != nil {
		t.Fatal(err)
	}
	got, err = client.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Header != (protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 1, PacketType: protocol.PacketTypePong, Length: 10}) || string(got.Payload) != "unix reply" {
		t.Fatalf("reverse packet = %#v", got)
	}

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket path still exists, stat error = %v", err)
	}
}

func TestUnixPacketChannelRejectsOversizedSend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "easytier.sock")
	listener, err := ListenUnix(path, protocol.PeerManagerHeaderSize)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan *UnixPacketChannel, 1)
	go func() {
		channel, err := listener.Accept(context.Background())
		if err == nil {
			accepted <- channel
		}
	}()
	client, err := DialUnix(context.Background(), path, protocol.PeerManagerHeaderSize)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if err := client.Send(context.Background(), protocol.Packet{}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Receive(context.Background()); err != nil {
		t.Fatalf("maximum-sized frame: %v", err)
	}
	err = client.Send(context.Background(), protocol.Packet{Payload: []byte("x")})
	if err == nil {
		t.Fatal("expected oversized frame error")
	}
}

func TestUnixPacketChannelRejectsMalformedLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "easytier.sock")
	listener, err := ListenUnix(path, protocol.PeerManagerHeaderSize)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	raw, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	server, err := listener.Accept(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], protocol.PeerManagerHeaderSize+1)
	if _, err := raw.Write(length[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Receive(context.Background()); err == nil {
		t.Fatal("expected malformed length error")
	}
}

func TestUnixPacketChannelReceiveHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "easytier.sock")
	listener, err := ListenUnix(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan *UnixPacketChannel, 1)
	go func() {
		channel, err := listener.Accept(context.Background())
		if err == nil {
			accepted <- channel
		}
	}()
	client, err := DialUnix(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := server.Receive(ctx)
		result <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive error = %v, want context canceled", err)
	}
}

func TestUnixListenerAcceptHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "easytier.sock")
	listener, err := ListenUnix(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := listener.Accept(ctx)
		result <- err
	}()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept error = %v, want context canceled", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("listener was closed by an accept cancellation: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket path was not removed on listener close, stat error = %v", err)
	}
}

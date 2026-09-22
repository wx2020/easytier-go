// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestQUICWireHandshakeAndStreaming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve UDP addr: %v", err)
	}

	serverEp, err := ListenEndpoint(serverAddr)
	if err != nil {
		t.Fatalf("ListenEndpoint: %v", err)
	}
	defer serverEp.Close()

	boundServerAddr := serverEp.socket.LocalAddr().(*net.UDPAddr)

	clientEp, err := NewClientEndpoint(nil)
	if err != nil {
		t.Fatalf("NewClientEndpoint: %v", err)
	}
	defer clientEp.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	// Server goroutine
	go func() {
		defer wg.Done()
		serverConn, err := serverEp.Accept(ctx)
		if err != nil {
			t.Errorf("server Accept failed: %v", err)
			return
		}
		defer serverConn.Close()

		// Echo server: read 16 bytes then write response
		buf := make([]byte, 16)
		n, err := io.ReadFull(serverConn, buf)
		if err != nil {
			t.Errorf("server ReadFull failed: %v", err)
			return
		}
		if string(buf[:n]) != "hello quic world" {
			t.Errorf("server received unexpected data: %q", string(buf[:n]))
			return
		}

		if _, err := serverConn.Write([]byte("reply quic world")); err != nil {
			t.Errorf("server Write failed: %v", err)
			return
		}
	}()

	// Client
	clientConn, err := clientEp.Dial(ctx, boundServerAddr)
	if err != nil {
		t.Fatalf("client Dial failed: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("hello quic world")); err != nil {
		t.Fatalf("client Write failed: %v", err)
	}

	resp := make([]byte, 16)
	n, err := io.ReadFull(clientConn, resp)
	if err != nil {
		t.Fatalf("client ReadFull failed: %v", err)
	}
	if string(resp[:n]) != "reply quic world" {
		t.Fatalf("client received unexpected response: %q", string(resp[:n]))
	}

	wg.Wait()
}

func TestQUICWireBulkDataTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	serverEp, err := ListenEndpoint(serverAddr)
	if err != nil {
		t.Fatalf("ListenEndpoint: %v", err)
	}
	defer serverEp.Close()

	clientEp, err := NewClientEndpoint(nil)
	if err != nil {
		t.Fatalf("NewClientEndpoint: %v", err)
	}
	defer clientEp.Close()

	// 50KB data transfer
	payload := bytes.Repeat([]byte("0123456789abcdef"), 3125) // 50,000 bytes

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		serverConn, err := serverEp.Accept(ctx)
		if err != nil {
			t.Errorf("server Accept: %v", err)
			return
		}
		defer serverConn.Close()

		recvBuf := make([]byte, len(payload))
		_, err = io.ReadFull(serverConn, recvBuf)
		if err != nil {
			t.Errorf("server ReadFull: %v", err)
			return
		}
		if !bytes.Equal(recvBuf, payload) {
			t.Errorf("data mismatch on server")
		}
	}()

	clientConn, err := clientEp.Dial(ctx, serverEp.socket.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("client Dial: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write(payload); err != nil {
		t.Fatalf("client Write: %v", err)
	}

	wg.Wait()
}

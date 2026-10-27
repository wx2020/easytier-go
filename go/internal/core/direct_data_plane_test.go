// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/tun"
)

// icmpEcho builds a minimal ICMPv4 echo request with the given payload.
func icmpEcho(payload []byte) []byte {
	buf := make([]byte, 20+len(payload)+8)
	buf[0] = 0x45 // IPv4, IHL 5
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64 // TTL
	buf[9] = 1  // ICMP
	// src 10.64.0.1 dst 10.64.0.2
	copy(buf[12:16], []byte{10, 64, 0, 1})
	copy(buf[16:20], []byte{10, 64, 0, 2})
	icmp := buf[20:]
	icmp[0] = 8 // echo request
	copy(icmp[8:], payload)
	return buf
}

// TestDirectSessionCarriesTUNDataPins the direct data plane end to end: two
// nodes in one OSPF mesh, node B connected through a direct TCP session, and
// node A writing an ICMP frame into its TUN. The frame must arrive on node
// B's TUN with the Noise-encrypted direct session carrying it — the plane
// the OSPF hop-cost switch was waiting for.
func TestDirectSessionCarriesTUNData(t *testing.T) {
	identityA := testIdentity(22, "direct-data", 0x88)
	identityB := testIdentity(11, "direct-data", 0x88)

	// B's TUN receives what A sends; the memory pair links them for the
	// return direction, which this test does not exercise.
	tunA, tunB, err := tun.NewMemoryDevicePair(16)
	if err != nil {
		t.Fatal(err)
	}
	nodeA, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identityA.PeerID, LegacyIdentity: identityA},
		PacketHandler: func(_ context.Context, _ protocol.Packet) error {
			return nil
		},
		EnableOSPF:   true,
		RouteRefresh: 100 * time.Millisecond,
		TUN:          tunA,
		TUNMTU:       1500,
		IPv4:         "10.64.0.1/24",
		Hostname:     "node-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Node B's TUN is paired with A's for the return direction, but the
	// authoritative arrival signal is B's packet pipeline: packetLoop sees
	// the decrypted Data packet before it is handed to the TUN writer.
	// Capturing it there avoids the memory-pair echo (B's egress writes
	// received frames back toward A, so tunB.ReadPacket never sees them).
	gotB := make(chan protocol.Packet, 4)
	nodeB, err := ListenWithOptions(NodeOptions{
		Address:     "127.0.0.1:0",
		PeerManager: peer.PeerConnectionManagerConfig{LocalPeerID: identityB.PeerID, LegacyIdentity: identityB},
		PacketHandler: func(_ context.Context, packet protocol.Packet) error {
			if packet.Header.PacketType == protocol.PacketTypeData {
				select {
				case gotB <- packet:
				default:
				}
			}
			return nil
		},
		EnableOSPF:   true,
		RouteRefresh: 100 * time.Millisecond,
		TUN:          tunB,
		TUNMTU:       1500,
		IPv4:         "10.64.0.2/24",
		Hostname:     "node-b",
		Peers:        []string{"tcp://" + nodeA.Address().String()},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveA := make(chan error, 1)
	go func() { serveA <- nodeA.Serve(ctx) }()
	serveB := make(chan error, 1)
	go func() { serveB <- nodeB.Serve(ctx) }()

	// Wait for OSPF convergence on A (route to B's peer id).
	deadline := time.Now().Add(10 * time.Second)
	for {
		if nodeA.runtime.manager.Router.Routes()[identityB.PeerID] == identityB.PeerID {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("OSPF did not converge, routes = %v", nodeA.runtime.manager.Router.Routes())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The direct session must exist on A (B dialed A, A accepted).
	deadline = time.Now().Add(5 * time.Second)
	for {
		if _, ok := nodeA.runtime.manager.Peers()[identityB.PeerID]; ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("direct session not established")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Write an ICMP echo into A's TUN destined to B's overlay IP.
	frame := icmpEcho([]byte("direct-data-plane-probe"))
	if err := tunA.WritePacket(context.Background(), frame); err != nil {
		t.Fatalf("write TUN: %v", err)
	}

	readCtx, readCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readCancel()
	// The memory pair loops A's frame back into B's own TUN ingress (dst is
	// B's own address), so discard locally sourced echoes and wait for the
	// frame that crossed the direct session (from = A's peer id).
	for {
		select {
		case packet := <-gotB:
			if packet.Header.FromPeerID != identityA.PeerID {
				continue
			}
			if !bytes.Contains(packet.Payload, []byte("direct-data-plane-probe")) {
				t.Fatalf("payload corrupted: %x", packet.Payload)
			}
			return
		case <-readCtx.Done():
			t.Fatalf("direct data plane delivered nothing")
		}
	}
}

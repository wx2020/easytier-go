// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

func TestLegacyHandshakeRoundTrip(t *testing.T) {
	client, server := newPacketPair()
	clientIdentity := testIdentity(11, "mesh", 0x11)
	serverIdentity := testIdentity(22, "mesh", 0x11)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	responseResult := make(chan error, 1)
	go func() {
		packet, err := server.Receive(ctx)
		if err != nil {
			responseResult <- err
			return
		}
		request, err := RespondLegacyHandshake(ctx, server, serverIdentity, packet)
		if err == nil && request.MyPeerID != clientIdentity.PeerID {
			err = errors.New("responder received wrong peer ID")
		}
		responseResult <- err
	}()

	response, err := InitiateLegacyHandshake(ctx, client, clientIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if response.MyPeerID != serverIdentity.PeerID || response.NetworkName != "mesh" {
		t.Fatalf("response = %#v", response)
	}
	if err := <-responseResult; err != nil {
		t.Fatal(err)
	}
}

func TestLegacyHandshakeRejectsMismatchedIdentity(t *testing.T) {
	local := testIdentity(1, "mesh", 1)
	bad := testIdentity(2, "other", 2)
	payload, err := (protocol.HandshakeRequest{
		Magic:               protocol.HandshakeMagic,
		MyPeerID:            bad.PeerID,
		Version:             protocol.HandshakeVersion,
		NetworkName:         bad.NetworkName,
		NetworkSecretDigest: bad.NetworkSecretDigest[:],
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	channel := &packetQueue{}
	_, err = RespondLegacyHandshake(context.Background(), channel, local, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: bad.PeerID, PacketType: protocol.PacketTypeHandshake},
		Payload: payload,
	})
	if err == nil {
		t.Fatal("expected identity mismatch")
	}
}

func TestLegacyHandshakeAcceptsZeroDestinationResponse(t *testing.T) {
	client, server := newPacketPair()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		packet, err := server.Receive(ctx)
		if err != nil {
			return
		}
		_ = packet
		response, _ := handshakeRequest(testIdentity(22, "mesh", 0x55))
		payload, _ := response.Marshal()
		_ = server.Send(ctx, protocol.Packet{
			Header:  protocol.PeerManagerHeader{FromPeerID: 22, PacketType: protocol.PacketTypeHandshake},
			Payload: payload,
		})
	}()
	response, err := InitiateLegacyHandshake(ctx, client, testIdentity(11, "mesh", 0x55))
	if err != nil {
		t.Fatal(err)
	}
	if response.MyPeerID != 22 {
		t.Fatalf("response peer ID = %d", response.MyPeerID)
	}
}

func testIdentity(peerID uint32, name string, digestByte byte) LegacyIdentity {
	identity := LegacyIdentity{PeerID: peerID, NetworkName: name}
	for i := range identity.NetworkSecretDigest {
		identity.NetworkSecretDigest[i] = digestByte
	}
	return identity
}

type packetQueue struct {
	mu      sync.Mutex
	packets []protocol.Packet
	peer    *packetQueue
	ready   chan struct{}
}

func newPacketPair() (*packetQueue, *packetQueue) {
	client := &packetQueue{ready: make(chan struct{}, 8)}
	server := &packetQueue{ready: make(chan struct{}, 8)}
	client.peer = server
	server.peer = client
	return client, server
}

func (q *packetQueue) Send(_ context.Context, packet protocol.Packet) error {
	q.peer.mu.Lock()
	q.peer.packets = append(q.peer.packets, packet)
	q.peer.mu.Unlock()
	q.peer.ready <- struct{}{}
	return nil
}

func (q *packetQueue) Receive(ctx context.Context) (protocol.Packet, error) {
	select {
	case <-ctx.Done():
		return protocol.Packet{}, ctx.Err()
	case <-q.ready:
		q.mu.Lock()
		defer q.mu.Unlock()
		packet := q.packets[0]
		q.packets = q.packets[1:]
		return packet, nil
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

func TestDirectPeerHandshakeRoundTrip(t *testing.T) {
	client, server := newPacketPair()
	clientConfig, serverConfig := testDirectHandshakeConfigs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	serverResult := make(chan handshakeResult, 1)
	go func() {
		session, level, identity, err := RespondDirectPeerHandshake(ctx, server, serverConfig)
		serverResult <- handshakeResult{session: session, level: level, identity: identity, err: err}
	}()
	clientSession, clientLevel, _, err := InitiateDirectPeerHandshake(ctx, client, clientConfig)
	if err != nil {
		select {
		case serverErr := <-serverResult:
			t.Fatalf("%v; responder=%v", err, serverErr.err)
		default:
			t.Fatal(err)
		}
	}
	serverHandshake := <-serverResult
	if serverHandshake.err != nil {
		t.Fatal(serverHandshake.err)
	}
	if clientLevel != AuthenticationLevelNetworkSecret || serverHandshake.level != AuthenticationLevelNetworkSecret {
		t.Fatalf("authentication levels = %d, %d", clientLevel, serverHandshake.level)
	}
	assertSessionRoundTrip(t, clientSession, serverHandshake.session, []byte("client to server"))
	assertSessionRoundTrip(t, serverHandshake.session, clientSession, []byte("server to client"))
}

func TestDirectPeerHandshakeRejectsWrongDigestProof(t *testing.T) {
	client, server := newPacketPair()
	clientConfig, serverConfig := testDirectHandshakeConfigs(t)
	serverConfig.NetworkSecret = "wrong-secret"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, _, err := RespondDirectPeerHandshake(ctx, server, serverConfig)
		result <- err
	}()
	if _, _, _, err := InitiateDirectPeerHandshake(ctx, client, clientConfig); err == nil {
		t.Fatal("expected responder proof rejection")
	}
	if err := <-result; err == nil {
		t.Fatal("expected network proof rejection")
	}
}

func TestDirectPeerHandshakeRejectsWrongConnectionEcho(t *testing.T) {
	client, server := newPacketPair()
	clientConfig, serverConfig := testDirectHandshakeConfigs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- sendWrongConnectionEcho(ctx, server, serverConfig)
	}()
	if _, _, _, err := InitiateDirectPeerHandshake(ctx, client, clientConfig); err == nil {
		t.Fatal("expected connection echo rejection")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestDirectPeerHandshakeRejectsPinnedStaticMismatch(t *testing.T) {
	client, server := newPacketPair()
	clientConfig, serverConfig := testDirectHandshakeConfigs(t)
	other, err := GenerateDirectPeerStaticKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.PinnedRemoteStatic = other.Public
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _, _, _, _ = RespondDirectPeerHandshake(ctx, server, serverConfig) }()
	if _, _, _, err := InitiateDirectPeerHandshake(ctx, client, clientConfig); err == nil {
		t.Fatal("expected pinned static rejection")
	}
}

func TestDirectPeerHandshakeRejectsTamperedNoisePacket(t *testing.T) {
	client, server := newPacketPair()
	clientConfig, serverConfig := testDirectHandshakeConfigs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	result := make(chan error, 1)
	go func() {
		_, _, _, err := RespondDirectPeerHandshake(ctx, tamperingPacketChannel{PacketChannel: server, packetType: protocol.PacketTypeNoiseHandshakeMsg2}, serverConfig)
		result <- err
	}()
	if _, _, _, err := InitiateDirectPeerHandshake(ctx, client, clientConfig); err == nil {
		t.Fatal("expected tampered Noise packet rejection")
	}
	cancel()
	if err := <-result; err == nil {
		t.Fatal("expected responder cancellation after tampered Noise packet")
	}
}

func TestDirectPeerHandshakeOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientConfig, serverConfig := testDirectHandshakeConfigs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverResult := make(chan handshakeResult, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- handshakeResult{err: err}
			return
		}
		channel, err := transport.NewTCPPacketChannel(connection, 0)
		if err != nil {
			serverResult <- handshakeResult{err: err}
			return
		}
		defer channel.Close()
		session, level, identity, err := RespondDirectPeerHandshake(ctx, channel, serverConfig)
		serverResult <- handshakeResult{session: session, level: level, identity: identity, err: err}
	}()
	channel, err := transport.DialTCP(ctx, listener.Addr().String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	clientSession, _, _, err := InitiateDirectPeerHandshake(ctx, channel, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	serverHandshake := <-serverResult
	if serverHandshake.err != nil {
		t.Fatal(serverHandshake.err)
	}
	assertSessionRoundTrip(t, clientSession, serverHandshake.session, []byte("secure TCP payload"))
}

func TestDirectPeerHandshakeOverUDP(t *testing.T) {
	service, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	serveCtx, stopServe := context.WithCancel(context.Background())
	defer stopServe()
	serveResult := make(chan error, 1)
	go func() { serveResult <- service.Serve(serveCtx) }()

	clientConfig, serverConfig := testDirectHandshakeConfigs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientChannel, err := transport.DialUDP(ctx, service.Address().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientChannel.Close()
	serverChannel, err := service.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer serverChannel.Close()

	serverResult := make(chan handshakeResult, 1)
	go func() {
		session, level, identity, err := RespondDirectPeerHandshake(ctx, serverChannel, serverConfig)
		serverResult <- handshakeResult{session: session, level: level, identity: identity, err: err}
	}()
	clientSession, _, _, err := InitiateDirectPeerHandshake(ctx, clientChannel, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	serverHandshake := <-serverResult
	if serverHandshake.err != nil {
		t.Fatal(serverHandshake.err)
	}
	assertSessionRoundTrip(t, clientSession, serverHandshake.session, []byte("secure UDP payload"))
	stopServe()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

type handshakeResult struct {
	session  *SecureDatagramSession
	level    AuthenticationLevel
	identity PeerIdentity
	err      error
}

func testDirectHandshakeConfigs(t *testing.T) (DirectPeerHandshakeConfig, DirectPeerHandshakeConfig) {
	t.Helper()
	clientStatic, err := GenerateDirectPeerStaticKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverStatic, err := GenerateDirectPeerStaticKeypair()
	if err != nil {
		t.Fatal(err)
	}
	client := DirectPeerHandshakeConfig{LocalPeerID: 11, NetworkName: "mesh", NetworkSecret: "test-secret", StaticKeypair: clientStatic, PinnedRemoteStatic: serverStatic.Public, CipherSuite: CipherSuiteChaCha20Poly1305}
	server := DirectPeerHandshakeConfig{LocalPeerID: 22, NetworkName: "mesh", NetworkSecret: "test-secret", StaticKeypair: serverStatic, PinnedRemoteStatic: clientStatic.Public, CipherSuite: CipherSuiteChaCha20Poly1305}
	for i := range client.NetworkSecretDigest {
		client.NetworkSecretDigest[i] = byte(i + 1)
		server.NetworkSecretDigest[i] = byte(i + 1)
	}
	return client, server
}

func assertSessionRoundTrip(t *testing.T, sender, receiver *SecureDatagramSession, plaintext []byte) {
	t.Helper()
	ciphertext, err := sender.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := receiver.Open(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
}

func sendWrongConnectionEcho(ctx context.Context, channel PacketChannel, config DirectPeerHandshakeConfig) error {
	handshake, err := newDirectNoiseHandshake(config, false)
	if err != nil {
		return err
	}
	packet, err := receiveDirectNoisePacket(ctx, channel, protocol.PacketTypeNoiseHandshakeMsg1)
	if err != nil {
		return err
	}
	message1, _, _, err := handshake.ReadMessage(nil, packet.Payload)
	if err != nil {
		return err
	}
	initiatorID, suite, err := parseDirectMsg1(message1, config.NetworkName)
	if err != nil {
		return err
	}
	var responderID [directConnectionIDSize]byte
	var wrongInitiatorID [directConnectionIDSize]byte
	var rootKey [directRootKeySize]byte
	responderID[0], wrongInitiatorID[0], rootKey[0] = 1, initiatorID[0]^1, 1
	message2, _, _, err := handshake.WriteMessage(nil, marshalDirectMsg2(config.NetworkName, responderID, wrongInitiatorID, rootKey, 0, networkProof(config.NetworkSecret, handshake.ChannelBinding())))
	if err != nil {
		return err
	}
	if suite != config.CipherSuite {
		return errors.New("unexpected cipher suite")
	}
	return sendDirectNoisePacket(ctx, channel, config.LocalPeerID, packet.Header.FromPeerID, protocol.PacketTypeNoiseHandshakeMsg2, message2)
}

type tamperingPacketChannel struct {
	PacketChannel
	packetType uint8
}

func (c tamperingPacketChannel) Send(ctx context.Context, packet protocol.Packet) error {
	if packet.Header.PacketType == c.packetType && len(packet.Payload) > 0 {
		packet.Payload = append([]byte(nil), packet.Payload...)
		packet.Payload[len(packet.Payload)-1] ^= 1
	}
	return c.PacketChannel.Send(ctx, packet)
}

// A credential client authenticates with its own static key: the admin
// responder classifies it as a credential peer when the key is in the
// configured trust list, while the client cannot confirm the admin.
func TestDirectPeerHandshakeClassifiesCredentialPeer(t *testing.T) {
	client, server := newPacketPair()
	clientStatic, err := GenerateDirectPeerStaticKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverStatic, err := GenerateDirectPeerStaticKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := DirectPeerHandshakeConfig{
		LocalPeerID: 11, NetworkName: "mesh", NetworkSecretDigest: [NetworkSecretDigestSize]byte{7},
		StaticKeypair: clientStatic, CipherSuite: CipherSuiteChaCha20Poly1305,
	}
	serverConfig := DirectPeerHandshakeConfig{
		LocalPeerID: 22, NetworkName: "mesh", NetworkSecret: "test-secret",
		StaticKeypair: serverStatic, CipherSuite: CipherSuiteChaCha20Poly1305,
		TrustedCredentialPubkeys: [][]byte{clientStatic.Public[:]},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	serverResult := make(chan handshakeResult, 1)
	go func() {
		session, level, identity, err := RespondDirectPeerHandshake(ctx, server, serverConfig)
		serverResult <- handshakeResult{session: session, level: level, identity: identity, err: err}
	}()
	clientSession, _, _, err := InitiateDirectPeerHandshake(ctx, client, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	_ = clientSession
	responder := <-serverResult
	if responder.err != nil {
		t.Fatal(responder.err)
	}
	if responder.session == nil {
		t.Fatal("responder session is nil")
	}
	// The admin responder classifies the credential client.
	if responder.identity != PeerIdentityCredential {
		t.Fatalf("responder sees client identity = %v, want credential", responder.identity)
	}
}

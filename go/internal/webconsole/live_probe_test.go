// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webconsole

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	webpb "github.com/EasyTier/EasyTier/go/internal/proto/web"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"google.golang.org/protobuf/proto"
)

// loggedChannel reports every packet the probe receives so a silent client is
// distinguishable from a dispatch failure.
type loggedChannel struct {
	inner transport.PacketChannel
	t     *testing.T
}

func (l *loggedChannel) Send(ctx context.Context, packet protocol.Packet) error {
	l.t.Logf("tx type=%d payload=%d bytes", packet.Header.PacketType, len(packet.Payload))
	return l.inner.Send(ctx, packet)
}

func (l *loggedChannel) Receive(ctx context.Context) (protocol.Packet, error) {
	packet, err := l.inner.Receive(ctx)
	if err != nil {
		l.t.Logf("rx error: %v", err)
		return packet, err
	}
	l.t.Logf("rx type=%d payload=%d bytes", packet.Header.PacketType, len(packet.Payload))
	return packet, err
}

func (l *loggedChannel) Close() error {
	if closer, ok := l.inner.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// captureConsole records the first heartbeat the peer sends, so a real client
// (for example the reference binary) can be inspected without the hosted
// console.
type captureConsole struct {
	features   int
	machineID  string
	hostname   string
	version    string
	token      string
	heartbeats int
	instances  int
	ready      chan struct{}
	logf       func(string, ...any)
}

func (c *captureConsole) ServiceName() string { return ServiceWebServer }

func (c *captureConsole) HandleMethod(methodIndex uint32, _ context.Context, _ uint32, body []byte) ([]byte, error) {
	if c.logf != nil {
		c.logf("service call method=%d body=%d bytes", methodIndex, len(body))
	}
	switch methodIndex {
	case MethodGetFeature:
		c.features++
		// Advertise no encryption so the client keeps the plaintext tunnel
		// and the capture stays readable.
		return proto.Marshal(&webpb.GetFeatureResponse{SupportEncryption: false})
	case MethodHeartbeat:
		request := &webpb.HeartbeatRequest{}
		if err := proto.Unmarshal(body, request); err != nil {
			return nil, err
		}
		c.heartbeats++
		if c.heartbeats == 1 {
			c.machineID = uuidString(request.GetMachineId())
			c.hostname = request.GetHostname()
			c.version = request.GetEasytierVersion()
			c.token = request.GetUserToken()
			c.instances = len(request.GetRunningNetworkInstances())
			close(c.ready)
		}
		return proto.Marshal(&webpb.HeartbeatResponse{})
	default:
		return nil, nil
	}
}

// TestCaptureRealClientHeartbeat is a manual interoperability probe: it listens
// on the address in ET_CONSOLE_PROBE_ADDR and prints the first heartbeat a real
// client sends. It is skipped unless that variable is set.
//
//	ET_CONSOLE_PROBE_ADDR=0.0.0.0:24555 go test ./internal/webconsole -run TestCaptureRealClientHeartbeat -v
//
// Run the reference client against it with:
//
//	easytier-core -w udp://<this-host>:24555/wx2020 --machine-id f50 --hostname f50
func TestCaptureRealClientHeartbeat(t *testing.T) {
	address := os.Getenv("ET_CONSOLE_PROBE_ADDR")
	if strings.TrimSpace(address) == "" {
		t.Skip("set ET_CONSOLE_PROBE_ADDR to listen for a real client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	listener, err := transport.ListenUDP(address)
	if err != nil {
		t.Fatalf("listen %s: %v", address, err)
	}
	defer func() { _ = listener.Close() }()
	go func() { _ = listener.Serve(ctx) }()

	channel, err := listener.Accept(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Logf("accepted tunnel session from the real client")
	session, err := newSession(ctx, &loggedChannel{inner: channel, t: t})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer func() { _ = session.Close() }()

	console := &captureConsole{ready: make(chan struct{}), logf: t.Logf}
	if err := session.Register(console); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Logf("session registered, waiting for the first RPC")
	select {
	case <-console.ready:
	case <-ctx.Done():
		t.Fatalf("no heartbeat received before timeout (features=%d)", console.features)
	}
	t.Logf("client machine_id=%s hostname=%q version=%q token=%q running_instances=%d",
		console.machineID, console.hostname, console.version, console.token, console.instances)
	if console.features == 0 {
		t.Error("client never asked for GetFeature")
	}
	if console.machineID == "00000000-0000-0000-0000-000000000000" {
		t.Error("client sent a zero machine id")
	}
}

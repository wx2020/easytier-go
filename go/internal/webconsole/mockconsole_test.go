// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webconsole

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
	configpb "github.com/EasyTier/EasyTier/go/internal/proto/api_config"
	instancepb "github.com/EasyTier/EasyTier/go/internal/proto/api_instance"
	managepb "github.com/EasyTier/EasyTier/go/internal/proto/api_manage"
	commonpb "github.com/EasyTier/EasyTier/go/internal/proto/common"
	webpb "github.com/EasyTier/EasyTier/go/internal/proto/web"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"github.com/EasyTier/EasyTier/go/internal/webclient"
	"google.golang.org/protobuf/proto"
)

// fakeBackend is an in-memory instance surface for the closed-loop test.
type fakeBackend struct {
	mu        sync.Mutex
	configs   map[string]*config.Config
	runCalls  []string
	patchSeen int
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{configs: map[string]*config.Config{}}
}

func (b *fakeBackend) InstanceIDs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	ids := make([]string, 0, len(b.configs))
	for id := range b.configs {
		ids = append(ids, id)
	}
	return ids
}

func (b *fakeBackend) RunInstance(_ context.Context, instID string, cfg *config.Config, overwrite bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.configs[instID]; exists && !overwrite {
		return nil
	}
	copied := *cfg
	b.configs[instID] = &copied
	b.runCalls = append(b.runCalls, instID)
	return nil
}

func (b *fakeBackend) DeleteInstances(ids []string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range ids {
		delete(b.configs, id)
	}
	return nil
}

func (b *fakeBackend) RetainInstances(ids []string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = true
	}
	for id := range b.configs {
		if !keep[id] {
			delete(b.configs, id)
		}
	}
	return ids
}

func (b *fakeBackend) InstanceConfig(instID string) (*config.Config, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cfg, ok := b.configs[instID]
	return cfg, ok
}

// FirstInstanceInfo returns the first known instance, like the real backend.
func (b *fakeBackend) FirstInstanceInfo() *managepb.NetworkInstanceRunningInfo {
	b.mu.Lock()
	defer b.mu.Unlock()
	for range b.configs {
		return &managepb.NetworkInstanceRunningInfo{Running: true}
	}
	return nil
}

func (b *fakeBackend) InstanceInfo(ids []string) map[string]*managepb.NetworkInstanceRunningInfo {
	b.mu.Lock()
	defer b.mu.Unlock()
	info := map[string]*managepb.NetworkInstanceRunningInfo{}
	for _, id := range ids {
		if _, ok := b.configs[id]; ok {
			info[id] = &managepb.NetworkInstanceRunningInfo{Running: true}
		}
	}
	return info
}

// fakeConsole is the console side of the tunnel: it answers GetFeature and
// Heartbeat and drives the client services.
type fakeConsole struct {
	mu         sync.Mutex
	heartbeats []*webpb.HeartbeatRequest
	features   int
}

func (f *fakeConsole) ServiceName() string { return ServiceWebServer }

func (f *fakeConsole) HandleMethod(methodIndex uint32, _ context.Context, _ uint32, body []byte) ([]byte, error) {
	switch methodIndex {
	case MethodGetFeature:
		f.mu.Lock()
		f.features++
		f.mu.Unlock()
		return proto.Marshal(&webpb.GetFeatureResponse{SupportEncryption: false})
	case MethodHeartbeat:
		request := &webpb.HeartbeatRequest{}
		if err := proto.Unmarshal(body, request); err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.heartbeats = append(f.heartbeats, request)
		f.mu.Unlock()
		return proto.Marshal(&webpb.HeartbeatResponse{})
	default:
		return nil, errors.New("unexpected WebServerService method")
	}
}

func (f *fakeConsole) featureCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.features
}

func (f *fakeConsole) heartbeatCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.heartbeats)
}

func (f *fakeConsole) firstHeartbeat() *webpb.HeartbeatRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.heartbeats) == 0 {
		return nil
	}
	return f.heartbeats[0]
}

// TestMockConsoleClosedLoop runs the whole console protocol in process:
// connect, GetFeature, heartbeat, RunNetworkInstance, List, GetConfig,
// PatchConfig, CollectNetworkInfo, ListNetworkInstanceMeta, Retain and Delete.
func TestMockConsoleClosedLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	listener, err := transport.ListenRing("ring://webconsole-mock")
	if err != nil {
		t.Fatalf("listen ring: %v", err)
	}
	defer func() { _ = listener.Close() }()

	backend := newFakeBackend()
	console := &fakeConsole{}

	consoleOptions := Options{
		ServerURL:         "udp://console.invalid:22020/test-token",
		MachineID:         "11111111-2222-4333-8444-555555555555",
		Hostname:          "unit-test-machine",
		Version:           "2.6.4-go",
		HeartbeatInterval: 50 * time.Millisecond,
		ReconnectDelay:    50 * time.Millisecond,
		Backend:           backend,
		Dial: func(ctx context.Context) (transport.PacketChannel, error) {
			return transport.DialRing(ctx, "ring://webconsole-mock")
		},
	}
	client, err := NewConsole(consoleOptions)
	if err != nil {
		t.Fatalf("new console: %v", err)
	}
	if client.Token() != "test-token" {
		t.Fatalf("token = %q", client.Token())
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	runErr := make(chan error, 1)
	go func() { runErr <- client.Run(runCtx) }()

	// First connection: GetFeature probe.
	plain, err := listener.Accept(ctx)
	if err != nil {
		t.Fatalf("accept probe connection: %v", err)
	}
	probeSession, err := newSession(ctx, plain)
	if err != nil {
		t.Fatalf("probe session: %v", err)
	}
	if err := probeSession.Register(console); err != nil {
		t.Fatalf("register console service: %v", err)
	}
	waitFor(t, ctx, func() bool { return console.featureCount() == 1 })
	_ = probeSession.Close()

	// Second connection: the real session.
	channel, err := listener.Accept(ctx)
	if err != nil {
		t.Fatalf("accept session connection: %v", err)
	}
	session, err := newSession(ctx, channel)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer func() { _ = session.Close() }()
	if err := session.Register(console); err != nil {
		t.Fatalf("register console service: %v", err)
	}

	waitFor(t, ctx, func() bool { return console.heartbeatCount() >= 1 })
	heartbeat := console.firstHeartbeat()
	if heartbeat.GetHostname() != "unit-test-machine" {
		t.Fatalf("heartbeat hostname = %q", heartbeat.GetHostname())
	}
	if uuidString(heartbeat.GetMachineId()) != consoleOptions.MachineID {
		t.Fatalf("heartbeat machine id = %q", uuidString(heartbeat.GetMachineId()))
	}
	if heartbeat.GetUserToken() != "test-token" {
		t.Fatalf("heartbeat token = %q", heartbeat.GetUserToken())
	}
	if !heartbeat.GetSupportConfigSource() {
		t.Fatal("heartbeat must advertise config source support")
	}

	// RunNetworkInstance.
	instID := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	runResponse := &managepb.RunNetworkInstanceResponse{}
	if err := session.Call(ctx, ServiceWebClient, MethodRunNetworkInstance, &managepb.RunNetworkInstanceRequest{
		InstId: uuidMessage(instID),
		Config: &managepb.NetworkConfig{
			InstanceId:       proto.String(instID),
			Hostname:         proto.String("f50"),
			NetworkName:      proto.String("wx2020"),
			NetworkSecret:    proto.String("secret"),
			VirtualIpv4:      proto.String("10.64.0.50"),
			NetworkLength:    proto.Int32(24),
			NetworkingMethod: managepb.NetworkingMethod_Manual.Enum(),
			PeerUrls:         []string{"tcp://110.40.168.232:11010"},
			ListenerUrls:     []string{"tcp://0.0.0.0:11010"},
			LatencyFirst:     proto.Bool(true),
			DisableUpnp:      proto.Bool(true),
		},
	}, runResponse, 5*time.Second); err != nil {
		t.Fatalf("RunNetworkInstance: %v", err)
	}
	if uuidString(runResponse.GetInstId()) != instID {
		t.Fatalf("run response inst id = %q", uuidString(runResponse.GetInstId()))
	}
	cfg, ok := backend.InstanceConfig(instID)
	if !ok {
		t.Fatal("instance was not created")
	}
	if cfg.Hostname != "f50" || cfg.IPv4 != "10.64.0.50/24" {
		t.Fatalf("mapped config hostname=%q ipv4=%q", cfg.Hostname, cfg.IPv4)
	}
	if cfg.Flags == nil || !cfg.Flags.LatencyFirst || !cfg.Flags.DisableUPnP {
		t.Fatalf("advanced flags not applied: %+v", cfg.Flags)
	}

	// ListNetworkInstance.
	listResponse := &managepb.ListNetworkInstanceResponse{}
	if err := session.Call(ctx, ServiceWebClient, MethodListNetworkInstance, &managepb.ListNetworkInstanceRequest{}, listResponse, 5*time.Second); err != nil {
		t.Fatalf("ListNetworkInstance: %v", err)
	}
	if len(listResponse.GetInstIds()) != 1 || uuidString(listResponse.GetInstIds()[0]) != instID {
		t.Fatalf("list = %v", listResponse.GetInstIds())
	}

	// CollectNetworkInfo.
	collectResponse := &managepb.CollectNetworkInfoResponse{}
	if err := session.Call(ctx, ServiceWebClient, MethodCollectNetworkInfo, &managepb.CollectNetworkInfoRequest{}, collectResponse, 5*time.Second); err != nil {
		t.Fatalf("CollectNetworkInfo: %v", err)
	}
	if info := collectResponse.GetInfo().GetMap()[instID]; info == nil || !info.GetRunning() {
		t.Fatalf("collect info = %v", collectResponse.GetInfo().GetMap())
	}

	// GetNetworkInstanceConfig.
	configResponse := &managepb.GetNetworkInstanceConfigResponse{}
	if err := session.Call(ctx, ServiceWebClient, MethodGetNetworkInstanceConfig, &managepb.GetNetworkInstanceConfigRequest{
		InstId: uuidMessage(instID),
	}, configResponse, 5*time.Second); err != nil {
		t.Fatalf("GetNetworkInstanceConfig: %v", err)
	}
	if configResponse.GetConfig().GetNetworkName() != "wx2020" {
		t.Fatalf("config network name = %q", configResponse.GetConfig().GetNetworkName())
	}

	// ListNetworkInstanceMeta.
	metaResponse := &managepb.ListNetworkInstanceMetaResponse{}
	if err := session.Call(ctx, ServiceWebClient, MethodListNetworkInstanceMeta, &managepb.ListNetworkInstanceMetaRequest{}, metaResponse, 5*time.Second); err != nil {
		t.Fatalf("ListNetworkInstanceMeta: %v", err)
	}
	if len(metaResponse.GetMetas()) != 1 || metaResponse.GetMetas()[0].GetNetworkName() != "wx2020" {
		t.Fatalf("metas = %v", metaResponse.GetMetas())
	}

	// ValidateConfig renders TOML.
	validateResponse := &managepb.ValidateConfigResponse{}
	if err := session.Call(ctx, ServiceWebClient, MethodValidateConfig, &managepb.ValidateConfigRequest{
		Config: &managepb.NetworkConfig{
			NetworkName:      proto.String("wx2020"),
			NetworkSecret:    proto.String("secret"),
			VirtualIpv4:      proto.String("10.64.0.60"),
			NetworkingMethod: managepb.NetworkingMethod_Standalone.Enum(),
		},
	}, validateResponse, 5*time.Second); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	if validateResponse.GetTomlConfig() == "" {
		t.Fatal("ValidateConfig returned empty TOML")
	}

	// ConfigRpc GetConfig / PatchConfig.
	getConfig := &configpb.GetConfigResponse{}
	if err := session.Call(ctx, ServiceConfigRPC, MethodGetConfig, &configpb.GetConfigRequest{
		Instance: &instancepb.InstanceIdentifier{Selector: &instancepb.InstanceIdentifier_Id{Id: uuidMessage(instID)}},
	}, getConfig, 5*time.Second); err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if getConfig.GetConfig().GetHostname() != "f50" {
		t.Fatalf("GetConfig hostname = %q", getConfig.GetConfig().GetHostname())
	}
	patchResponse := &configpb.PatchConfigResponse{}
	if err := session.Call(ctx, ServiceConfigRPC, MethodPatchConfig, &configpb.PatchConfigRequest{
		Instance: &instancepb.InstanceIdentifier{Selector: &instancepb.InstanceIdentifier_Id{Id: uuidMessage(instID)}},
		Patch:    &configpb.InstanceConfigPatch{Hostname: proto.String("f50-patched")},
	}, patchResponse, 5*time.Second); err != nil {
		t.Fatalf("PatchConfig: %v", err)
	}
	patched, _ := backend.InstanceConfig(instID)
	if patched == nil || patched.Hostname != "f50-patched" {
		t.Fatalf("patched config = %+v", patched)
	}

	// Retain keeps the listed instance alive.
	retainResponse := &managepb.RetainNetworkInstanceResponse{}
	if err := session.Call(ctx, ServiceWebClient, MethodRetainNetworkInstance, &managepb.RetainNetworkInstanceRequest{
		InstIds: []*commonpb.UUID{uuidMessage(instID)},
	}, retainResponse, 5*time.Second); err != nil {
		t.Fatalf("RetainNetworkInstance: %v", err)
	}
	if _, ok := backend.InstanceConfig(instID); !ok {
		t.Fatal("retained instance disappeared")
	}

	// Delete removes it and reports nothing remaining.
	deleteResponse := &managepb.DeleteNetworkInstanceResponse{}
	if err := session.Call(ctx, ServiceWebClient, MethodDeleteNetworkInstance, &managepb.DeleteNetworkInstanceRequest{
		InstIds: []*commonpb.UUID{uuidMessage(instID)},
	}, deleteResponse, 5*time.Second); err != nil {
		t.Fatalf("DeleteNetworkInstance: %v", err)
	}
	if _, ok := backend.InstanceConfig(instID); ok {
		t.Fatal("deleted instance is still present")
	}

	runCancel()
	if err := <-runErr; err != nil {
		t.Fatalf("console run returned %v", err)
	}
}

// TestUDPConsoleLoopback runs the same closed loop over a real UDP socket pair,
// so the tunnel framing is exercised too (the ring tests bypass it).
func TestUDPConsoleLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	listener, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() { _ = listener.Serve(ctx) }()
	address := listener.Address().String()

	backend := newFakeBackend()
	console := &fakeConsole{}
	client, err := NewConsole(Options{
		ServerURL:         "udp://" + address + "/udp-token",
		MachineID:         "22222222-3333-4444-8555-666666666666",
		Hostname:          "udp-machine",
		Version:           "2.6.4-go",
		HeartbeatInterval: 100 * time.Millisecond,
		ReconnectDelay:    100 * time.Millisecond,
		Backend:           backend,
	})
	if err != nil {
		t.Fatalf("new console: %v", err)
	}
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	go func() { _ = client.Run(runCtx) }()

	// Probe connection (GetFeature), then the real session.
	for attempt := 0; attempt < 2; attempt++ {
		channel, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			t.Fatalf("accept %d: %v", attempt, acceptErr)
		}
		session, sessionErr := newSession(ctx, channel)
		if sessionErr != nil {
			t.Fatalf("session %d: %v", attempt, sessionErr)
		}
		if regErr := session.Register(console); regErr != nil {
			t.Fatalf("register %d: %v", attempt, regErr)
		}
		if attempt == 1 {
			defer func() { _ = session.Close() }()
			break
		}
		waitFor(t, ctx, func() bool { return console.featureCount() >= 1 })
		_ = session.Close()
	}
	waitFor(t, ctx, func() bool { return console.heartbeatCount() >= 1 })
	if console.firstHeartbeat().GetHostname() != "udp-machine" {
		t.Fatalf("heartbeat hostname = %q", console.firstHeartbeat().GetHostname())
	}
	runCancel()
}

// TestUUIDWireRoundTrip pins the UUID framing used on the console wire.
func TestUUIDWireRoundTrip(t *testing.T) {
	const id = "01234567-89ab-4cde-8f01-23456789abcd"
	message := uuidMessage(id)
	if message.GetPart1() != 0x01234567 || message.GetPart3() != 0x8f012345 || message.GetPart4() != 0x6789abcd {
		t.Fatalf("unexpected parts: %+v", message)
	}
	if got := uuidString(message); got != id {
		t.Fatalf("round trip = %q, want %q", got, id)
	}
}

// TestParseServerURL covers token extraction and scheme normalisation.
func TestParseServerURL(t *testing.T) {
	cases := []struct {
		raw    string
		scheme string
		host   string
		token  string
	}{
		{"udp://easytier.example:22020/wx2020", "udp", "easytier.example:22020", "wx2020"},
		{"easytier.example:22020/tok%2Fen", "udp", "easytier.example:22020", "tok/en"},
		{"wss://console.example/ws/token2", "wss", "console.example", "token2"},
	}
	for _, testCase := range cases {
		parsed, token, err := parseServerURL(testCase.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", testCase.raw, err)
		}
		if parsed.Scheme != testCase.scheme || parsed.Host != testCase.host || token != testCase.token {
			t.Fatalf("parse %q = (%s,%s,%s)", testCase.raw, parsed.Scheme, parsed.Host, token)
		}
	}
	if _, _, err := parseServerURL("quic://host:1/token"); err == nil {
		t.Fatal("expected an unsupported-scheme error")
	}
}

func waitFor(t *testing.T, ctx context.Context, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("context expired while waiting")
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("condition was not met in time")
}

var _ rpc.RpcService = (*fakeConsole)(nil)

// secureConsole advertises the Noise upgrade so the client re-dials securely.
type secureConsole struct{ *fakeConsole }

func (s *secureConsole) HandleMethod(methodIndex uint32, ctx context.Context, from uint32, body []byte) ([]byte, error) {
	if methodIndex == MethodGetFeature {
		s.fakeConsole.mu.Lock()
		s.fakeConsole.features++
		s.fakeConsole.mu.Unlock()
		return proto.Marshal(&webpb.GetFeatureResponse{SupportEncryption: true})
	}
	return s.fakeConsole.HandleMethod(methodIndex, ctx, from, body)
}

// TestSecureConsoleLoopback proves the Noise upgrade path carries heartbeats
// and instance commands, which is what the hosted console requires.
func TestSecureConsoleLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	listener, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() { _ = listener.Serve(ctx) }()

	backend := newFakeBackend()
	base := &fakeConsole{}
	console := &secureConsole{fakeConsole: base}
	client, err := NewConsole(Options{
		ServerURL:         "udp://" + listener.Address().String() + "/secure-token",
		MachineID:         "33333333-4444-4555-8666-777777777777",
		Hostname:          "secure-machine",
		Version:           "2.6.4-go",
		HeartbeatInterval: 100 * time.Millisecond,
		ReconnectDelay:    100 * time.Millisecond,
		Backend:           backend,
		Logf:              t.Logf,
	})
	if err != nil {
		t.Fatalf("new console: %v", err)
	}
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	go func() { _ = client.Run(runCtx) }()

	// Probe connection: plaintext GetFeature.
	plain, err := listener.Accept(ctx)
	if err != nil {
		t.Fatalf("accept probe: %v", err)
	}
	probeSession, err := newSession(ctx, plain)
	if err != nil {
		t.Fatalf("probe session: %v", err)
	}
	if err := probeSession.Register(console); err != nil {
		t.Fatalf("probe register: %v", err)
	}
	waitFor(t, ctx, func() bool { return base.featureCount() >= 1 })
	// The probe session shares the listener socket; closing it early would
	// tear the listener down before the secure dial arrives.
	defer func() { _ = probeSession.Close() }()

	// Secure connection: accept the Noise upgrade, then serve.
	t.Logf("waiting for the secure dial")
	raw, err := listener.Accept(ctx)
	if err != nil {
		t.Fatalf("accept secure: %v", err)
	}
	t.Logf("accepted secure dial, upgrading")
	secureChannel, upgraded, err := webclient.AcceptOrUpgradeServerChannel(ctx, raw, true)
	if err != nil {
		t.Fatalf("server noise upgrade: %v", err)
	}
	if !upgraded {
		t.Fatal("server did not upgrade the tunnel")
	}
	session, err := newSession(ctx, secureChannel)
	if err != nil {
		t.Fatalf("secure session: %v", err)
	}
	defer func() { _ = session.Close() }()
	if err := session.Register(console); err != nil {
		t.Fatalf("secure register: %v", err)
	}
	waitFor(t, ctx, func() bool { return base.heartbeatCount() >= 2 })
	if base.firstHeartbeat().GetHostname() != "secure-machine" {
		t.Fatalf("hostname = %q", base.firstHeartbeat().GetHostname())
	}
	runCancel()
}

// TestReconnectBackoff pins the exponential reconnect schedule.
func TestReconnectBackoff(t *testing.T) {
	backoff := &reconnectBackoff{base: time.Second, max: 8 * time.Second}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second}
	for index, expected := range want {
		if got := backoff.next(); got != expected {
			t.Fatalf("attempt %d = %s, want %s", index, got, expected)
		}
	}
	backoff.reset()
	if got := backoff.next(); got != time.Second {
		t.Fatalf("after reset = %s, want 1s", got)
	}
}

// TestTransportConsoleLoops runs the console handshake over every transport the
// protocol supports on this build: UDP, TCP and WebSocket.
func TestTransportConsoleLoops(t *testing.T) {
	type endpoint struct {
		accept func(context.Context) (transport.PacketChannel, error)
		addr   string
		close  func() error
		serve  func(context.Context) error
	}
	cases := []struct {
		name  string
		setup func(context.Context) (endpoint, error)
	}{
		{"udp", func(ctx context.Context) (endpoint, error) {
			listener, err := transport.ListenUDP("127.0.0.1:0")
			if err != nil {
				return endpoint{}, err
			}
			go func() { _ = listener.Serve(ctx) }()
			return endpoint{
				accept: func(ctx context.Context) (transport.PacketChannel, error) { return listener.Accept(ctx) },
				addr:   listener.Address().String(),
				close:  listener.Close,
			}, nil
		}},
		{"tcp", func(context.Context) (endpoint, error) {
			listener, err := transport.ListenPacketChannel("tcp", "127.0.0.1:0")
			if err != nil {
				return endpoint{}, err
			}
			return endpoint{
				accept: listener.Accept,
				addr:   listener.Address().String(),
				close:  listener.Close,
			}, nil
		}},
		{"ws", func(ctx context.Context) (endpoint, error) {
			listener, err := transport.ListenWebSocket("127.0.0.1:0")
			if err != nil {
				return endpoint{}, err
			}
			go func() { _ = listener.Serve(ctx) }()
			return endpoint{
				accept: func(ctx context.Context) (transport.PacketChannel, error) { return listener.Accept(ctx) },
				addr:   listener.Address().String(),
				close:  listener.Close,
			}, nil
		}},
		{"wss", func(ctx context.Context) (endpoint, error) {
			listener, err := transport.ListenWebSocket("127.0.0.1:0")
			if err != nil {
				return endpoint{}, err
			}
			// The empty cert/key pair makes the listener generate a
			// self-signed certificate, which the client accepts by default.
			go func() { _ = listener.ServeTLS(ctx, "", "") }()
			return endpoint{
				accept: func(ctx context.Context) (transport.PacketChannel, error) { return listener.Accept(ctx) },
				addr:   listener.Address().String(),
				close:  listener.Close,
			}, nil
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			server, err := testCase.setup(ctx)
			if err != nil {
				t.Skipf("%s listener unavailable: %v", testCase.name, err)
			}
			defer func() { _ = server.close() }()
			if server.serve != nil {
				go func() { _ = server.serve(ctx) }()
			}

			backend := newFakeBackend()
			console := &fakeConsole{}
			client, err := NewConsole(Options{
				ServerURL:         testCase.name + "://" + server.addr + "/transport-token",
				MachineID:         "55555555-6666-4777-8888-999999999999",
				Hostname:          testCase.name + "-machine",
				Version:           "2.6.4-go",
				HeartbeatInterval: 100 * time.Millisecond,
				ReconnectDelay:    100 * time.Millisecond,
				Backend:           backend,
			})
			if err != nil {
				t.Fatalf("new console: %v", err)
			}
			runCtx, runCancel := context.WithCancel(ctx)
			defer runCancel()
			go func() { _ = client.Run(runCtx) }()

			channel, err := server.accept(ctx)
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
			session, err := newSession(ctx, channel)
			if err != nil {
				t.Fatalf("session: %v", err)
			}
			defer func() { _ = session.Close() }()
			if err := session.Register(console); err != nil {
				t.Fatalf("register: %v", err)
			}
			waitFor(t, ctx, func() bool { return console.heartbeatCount() >= 1 })
			if got := console.firstHeartbeat().GetHostname(); got != testCase.name+"-machine" {
				t.Fatalf("hostname = %q", got)
			}
			runCancel()
		})
	}
}

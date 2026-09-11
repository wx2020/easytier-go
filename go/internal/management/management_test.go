// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package management

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/acl"
	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/credential"
	"github.com/EasyTier/EasyTier/go/internal/dns"
	"github.com/EasyTier/EasyTier/go/internal/forward"
	"github.com/EasyTier/EasyTier/go/internal/instance"
	"github.com/EasyTier/EasyTier/go/internal/logging"
	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/route"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/stats"
	"github.com/EasyTier/EasyTier/go/internal/webclient"
)

func TestHandlerMethods(t *testing.T) {
	counters := stats.New()
	counters.Add("easytier_packets_total", 3)
	instances := instance.NewInstanceManager()
	if err := instances.Add(testInstance{id: "2", name: "beta"}); err != nil {
		t.Fatal(err)
	}
	if err := instances.Add(testInstance{id: "1", name: "alpha"}); err != nil {
		t.Fatal(err)
	}
	service := NewService(NodeInfo{ID: "node-1", Name: "test", Version: "v1"}, counters, instances)

	response := callHandler(t, service, methodNodeInfo, `{}`)
	if got := string(response.Body); got != `{"node":{"id":"node-1","name":"test","version":"v1"}}` {
		t.Fatalf("node.info response = %s", got)
	}

	response = callHandler(t, service, methodStatsPrometheus, `{}`)
	var prometheus prometheusResponse
	if err := json.Unmarshal(response.Body, &prometheus); err != nil {
		t.Fatal(err)
	}
	if want := "easytier_packets_total 3\n"; !containsLine(prometheus.Text, want) {
		t.Fatalf("stats.prometheus response = %q, want line %q", prometheus.Text, want)
	}

	response = callHandler(t, service, methodLoggerGet, `{}`)
	if got := string(response.Body); got != `{"level":"info"}` {
		t.Fatalf("logger.get response = %s", got)
	}
	response = callHandler(t, service, methodLoggerSet, `{"level":"debug"}`)
	if got := string(response.Body); got != `{"level":"debug"}` {
		t.Fatalf("logger.set response = %s", got)
	}

	response = callHandler(t, service, methodInstanceList, `{}`)
	if got := string(response.Body); got != `{"instances":[{"id":"1","name":"alpha"},{"id":"2","name":"beta"}]}` {
		t.Fatalf("instance.list response = %s", got)
	}
}

func TestHandlerRejectsInvalidRequest(t *testing.T) {
	service := NewService(NodeInfo{}, nil, nil)
	for _, request := range []rpc.RpcPacket{
		{IsRequest: true},
		{IsRequest: true, Descriptor: &rpc.RpcDescriptor{ServiceName: "wrong"}, Body: []byte(`{}`)},
		{IsRequest: true, Descriptor: &rpc.RpcDescriptor{ServiceName: ServiceName, MethodIndex: 5}, Body: []byte(`{}`)},
		{IsRequest: true, Descriptor: &rpc.RpcDescriptor{ServiceName: ServiceName}, Body: []byte(`{"unknown":true}`)},
		{IsRequest: true, Descriptor: &rpc.RpcDescriptor{ServiceName: ServiceName, MethodIndex: methodLoggerSet}, Body: []byte(`{"level":"verbose"}`)},
	} {
		if _, err := service.Handler(context.Background(), request); err == nil {
			t.Fatalf("Handler(%#v) succeeded", request)
		}
	}
}

func TestClientLoopback(t *testing.T) {
	counters := stats.New()
	counters.Add("easytier_packets_total", 7)
	instances := instance.NewInstanceManager()
	if err := instances.Add(testInstance{id: "node-a", name: "alpha"}); err != nil {
		t.Fatal(err)
	}
	service := NewService(NodeInfo{ID: "node-1", Name: "test", Version: "v1"}, counters, instances)
	prefix := netip.MustParsePrefix("127.0.0.0/8")
	server, err := rpc.NewServer([]netip.Prefix{prefix}, service.Handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		if err := server.Serve(context.Background()); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()

	client := NewClient(server.Addr().String(), 1, 2)
	info, err := client.NodeInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := (NodeInfo{ID: "node-1", Name: "test", Version: "v1"}); info != want {
		t.Fatalf("NodeInfo = %#v, want %#v", info, want)
	}
	level, err := client.LoggerSet(context.Background(), LoggerLevelWarn)
	if err != nil {
		t.Fatal(err)
	}
	if level != LoggerLevelWarn {
		t.Fatalf("LoggerSet = %q, want %q", level, LoggerLevelWarn)
	}
	level, err = client.LoggerGet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if level != LoggerLevelWarn {
		t.Fatalf("LoggerGet = %q, want %q", level, LoggerLevelWarn)
	}
	text, err := client.StatsPrometheus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !containsLine(text, "easytier_packets_total 7\n") {
		t.Fatalf("StatsPrometheus = %q", text)
	}
	listed, err := client.InstanceList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []InstanceInfo{{ID: "node-a", Name: "alpha"}}; !reflect.DeepEqual(listed, want) {
		t.Fatalf("InstanceList = %#v, want %#v", listed, want)
	}
	if _, err := client.ConfigGet(context.Background()); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unsupported ConfigGet error = %v", err)
	}
}

func TestClientLoopbackCoversConfiguredManagementServices(t *testing.T) {
	counters := stats.New()
	counters.Add("requests_total", 4)
	instances := instance.NewInstanceManager()
	if err := instances.Add(testInstance{id: "one", name: "one"}); err != nil {
		t.Fatal(err)
	}
	identity := peer.LegacyIdentity{PeerID: 1, NetworkName: "mesh"}
	peers, err := peer.NewPeerConnectionManager(peer.PeerConnectionManagerConfig{LocalPeerID: 1, LegacyIdentity: identity})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peers.Close() })
	routes := route.NewEngine(1)
	routes.AddLink(1, 2, 5)
	policy, err := acl.NewPolicy(acl.ActionDrop, []acl.Rule{{Name: "allow", Direction: acl.DirectionInbound, Protocol: acl.ProtocolTCP, Action: acl.ActionAllow}})
	if err != nil {
		t.Fatal(err)
	}
	forwards := forward.NewManager(context.Background())
	t.Cleanup(func() { _ = forwards.Close() })
	dnsServer, err := dns.NewServer(dns.Config{Address: "127.0.0.1:0", Zone: "mesh"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dnsServer.Close() })
	webServer, err := webclient.NewServer(webclient.ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var logOutput strings.Builder
	logger := logging.New(&logOutput, logging.LevelInfo)
	cfg := config.Config{NetworkIdentity: config.NetworkIdentity{NetworkName: "mesh"}, InstanceName: "one"}
	service := NewServiceWithOptions(ServiceOptions{
		NodeInfo: NodeInfo{ID: "node-1", Name: "mesh", Version: "test"}, Counters: counters,
		Instances: instances, Logger: logger, Config: &cfg,
		UpdateConfig: func(context.Context, config.Config) error { return nil },
		Peers:        peers, Routes: routes, Connectors: []ConnectorInfo{{URL: "tcp://127.0.0.1:11010", Status: "configured"}},
		Forwards: forwards, ACL: policy, Credentials: &credential.Manager{}, DNS: dnsServer, WebClient: webServer,
	})
	server := newLoopbackManagementServer(t, service)
	client := NewClient(server.Addr().String(), 10, 20)
	ctx := context.Background()
	if _, err := client.NodeInfo(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.StatsPrometheus(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.StatsSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.LoggerSet(ctx, LoggerLevelDebug); err != nil {
		t.Fatal(err)
	}
	if got, err := client.LoggerGet(ctx); err != nil || got != LoggerLevelDebug {
		t.Fatalf("logger = %q, %v", got, err)
	}
	if _, err := client.InstanceList(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.InstanceStatusList(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.InstanceStart(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	if err := client.InstanceStop(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	statuses, err := client.InstanceStatusList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].State != "stopped" || statuses[0].Running {
		t.Fatalf("stopped instance status = %#v", statuses)
	}
	if _, err := client.InstanceStart(ctx, "one"); err != nil {
		t.Fatal(err)
	}
	configInfo, err := client.ConfigGet(ctx)
	if err != nil || configInfo.ReadOnly {
		t.Fatalf("config get = %#v, %v", configInfo, err)
	}
	if _, err := client.ConfigSetTOML(ctx, "[network_identity]\nnetwork_name = \"updated\"\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PeerList(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RouteList(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ConnectorList(ctx); err != nil {
		t.Fatal(err)
	}
	bind := freeForwardAddress(t)
	rule := forward.Rule{Bind: bind, Destination: "127.0.0.1:1"}
	if _, err := client.ForwardAdd(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ForwardList(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.ForwardRemove(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ACLGet(ctx); err != nil {
		t.Fatal(err)
	}
	aclStats, err := client.ACLStats(ctx)
	if err != nil || aclStats.Evaluations != 0 {
		t.Fatalf("ACL stats = %#v, %v", aclStats, err)
	}
	generated, err := client.CredentialGenerate(ctx, CredentialGenerateRequest{TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CredentialList(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.CredentialRevoke(ctx, generated.CredentialID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.DNSList(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DNSSet(ctx, "node.mesh", []string{"10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := client.DNSDelete(ctx, "node.mesh"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WebSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.VPNPortal(ctx); err != nil {
		t.Fatalf("VPNPortal error = %v", err)
	}
	if _, err := client.Proxy(ctx); err != nil {
		t.Fatalf("Proxy error = %v", err)
	}
	if _, err := client.PeerCenter(ctx); err != nil {
		t.Fatalf("PeerCenter error = %v", err)
	}
}

func TestManagementRuntimeComponents(t *testing.T) {
	cfg := config.Config{NetworkIdentity: config.NetworkIdentity{NetworkName: "test"}, InstanceName: "one"}
	updated := make(chan config.Config, 1)
	routes := route.NewEngine(1)
	routes.AddLink(1, 2, 3)
	aclPolicy, err := acl.NewPolicy(acl.ActionDrop, []acl.Rule{{Name: "allow", Priority: 1, Direction: acl.DirectionInbound, Protocol: acl.ProtocolTCP, Action: acl.ActionAllow}})
	if err != nil {
		t.Fatal(err)
	}
	dnsServer, err := dns.NewServer(dns.Config{Address: "127.0.0.1:0", Zone: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dnsServer.Close() })
	forwardManager := forward.NewManager(context.Background())
	t.Cleanup(func() { _ = forwardManager.Close() })
	service := NewServiceWithOptions(ServiceOptions{
		NodeInfo: NodeInfo{ID: "node"}, Counters: stats.New(), Config: &cfg,
		UpdateConfig: func(_ context.Context, value config.Config) error { updated <- value; return nil },
		Routes:       routes, Connectors: []ConnectorInfo{{URL: "tcp://127.0.0.1:1", Status: "configured"}},
		Forwards: forwardManager, ACL: aclPolicy,
		Credentials: &credential.Manager{}, DNS: dnsServer,
	})
	service.counters.Add("test_total", 4)
	gotRoutes, err := service.RouteList()
	if err != nil || !reflect.DeepEqual(gotRoutes, []route.Route{{Destination: 2, NextHop: 2, Cost: 3}}) {
		t.Fatalf("routes = %#v", gotRoutes)
	}
	if _, err := service.ConfigSet(context.Background(), "", &config.Config{NetworkIdentity: config.NetworkIdentity{NetworkName: "changed"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-updated:
		if value.NetworkIdentity.NetworkName != "changed" {
			t.Fatalf("updated config = %#v", value)
		}
	case <-time.After(time.Second):
		t.Fatal("configuration callback was not called")
	}
	generated, err := service.CredentialGenerate(CredentialGenerateRequest{TTLSeconds: 60})
	if err != nil || generated.CredentialID == "" || generated.CredentialSecret == "" {
		t.Fatalf("credential generate = %#v, %v", generated, err)
	}
	if err := service.DNSSet("node.test", []string{"10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	gotRecords, err := service.DNSList()
	if err != nil || !reflect.DeepEqual(gotRecords, []DNSRecordInfo{{Name: "node.test", Addresses: []string{"10.0.0.1"}}}) {
		t.Fatalf("DNS records = %#v", gotRecords)
	}
	response := callHandler(t, service, methodCredentialList, `{}`)
	if !strings.Contains(string(response.Body), generated.CredentialID) {
		t.Fatalf("credential list response = %s", response.Body)
	}
}

func TestConfigSnapshotsAreIndependentAndReadOnlyIsEnforced(t *testing.T) {
	cfg := config.Config{
		NetworkIdentity: config.NetworkIdentity{NetworkName: "mesh"},
		Peers:           []config.Peer{{URI: "tcp://127.0.0.1:11010"}},
	}
	called := false
	service := NewServiceWithOptions(ServiceOptions{
		Config:         &cfg,
		ConfigReadOnly: true,
		UpdateConfig: func(context.Context, config.Config) error {
			called = true
			return nil
		},
	})
	info, err := service.ConfigGet()
	if err != nil {
		t.Fatal(err)
	}
	info.Config.Peers[0].URI = "tcp://mutated:1"
	again, err := service.ConfigGet()
	if err != nil {
		t.Fatal(err)
	}
	if again.Config.Peers[0].URI != "tcp://127.0.0.1:11010" {
		t.Fatalf("configuration snapshot was mutable: %#v", again.Config)
	}
	if _, err := service.ConfigSet(context.Background(), "[network_identity]\nnetwork_name = \"new\"\n", nil); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only ConfigSet error = %v", err)
	}
	if called {
		t.Fatal("read-only ConfigSet invoked update callback")
	}
}

func TestVPNPortalDeterministicWireGuardConfig(t *testing.T) {
	cfg := config.Config{
		NetworkIdentity: config.NetworkIdentity{NetworkName: "testnet", NetworkSecret: "secret123"},
		VPNPortalConfig: &config.VPNPortalConfig{ClientCIDR: "10.14.14.0/24", WireGuardListen: "0.0.0.0:11013"},
		IPv4:            "10.10.0.1/24",
		ProxyNetworks:   []config.ProxyNetwork{{CIDR: "10.20.0.0/24"}},
	}
	service := NewServiceWithOptions(ServiceOptions{Config: &cfg, UpdateConfig: func(context.Context, config.Config) error { return nil }})
	info, err := service.VPNPortalInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.VPNType != "wireguard" {
		t.Fatalf("vpn_type = %q", info.VPNType)
	}
	// Deterministic keys via GenerateDigestFromStrings
	keySeed := "testnetsecret123"
	clientDigest := protocol.GenerateDigestFromStrings("client", keySeed)
	serverDigest := protocol.GenerateDigestFromStrings("server", keySeed)
	expectedPriv := base64.StdEncoding.EncodeToString(clientDigest[:])
	serverPub, err := deriveX25519PublicKey(serverDigest)
	if err != nil {
		t.Fatal(err)
	}
	expectedPub := base64.StdEncoding.EncodeToString(serverPub[:])
	if !strings.Contains(info.ClientConfig, expectedPriv) {
		t.Fatalf("client config missing expected private key %q: %q", expectedPriv, info.ClientConfig)
	}
	if !strings.Contains(info.ClientConfig, expectedPub) {
		t.Fatalf("client config missing expected public key %q: %q", expectedPub, info.ClientConfig)
	}
	if !strings.Contains(info.ClientConfig, "10.14.14.0/32") {
		t.Fatalf("client config missing expected address: %q", info.ClientConfig)
	}
	if !strings.Contains(info.ClientConfig, "AllowedIPs = 10.20.0.0/24,10.10.0.1/24,10.14.14.0/24") {
		t.Fatalf("client config missing expected AllowedIPs: %q", info.ClientConfig)
	}
	// Without VPN config, should return error string but still success
	empty := NewService(NodeInfo{}, nil, nil)
	emptyInfo, err := empty.VPNPortalInfo()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(emptyInfo.ClientConfig, "ERROR: Wireguard VPN Portal Not Started") {
		t.Fatalf("empty portal info = %#v", emptyInfo)
	}
	// Proxy and peer center should return empty structures, not ErrUnsupported
	proxyInfo, err := empty.ProxyList()
	if err != nil || proxyInfo.Entries == nil {
		t.Fatalf("proxy list = %#v, %v", proxyInfo, err)
	}
	peerInfo, err := empty.PeerCenterInfo()
	if err != nil || peerInfo.GlobalPeerMap == nil {
		t.Fatalf("peer center = %#v, %v", peerInfo, err)
	}
}

func callHandler(t *testing.T, service *Service, method uint32, body string) rpc.RpcPacket {
	t.Helper()
	response, err := service.Handler(context.Background(), rpc.RpcPacket{
		Descriptor: &rpc.RpcDescriptor{ServiceName: ServiceName, MethodIndex: method},
		Body:       []byte(body),
		IsRequest:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func newLoopbackManagementServer(t *testing.T, service *Service) *rpc.Server {
	t.Helper()
	server, err := rpc.NewServer([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, service.Handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(context.Background()) }()
	return server
}

func freeForwardAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func containsLine(text, line string) bool {
	for _, current := range splitLines(text) {
		if current+"\n" == line {
			return true
		}
	}
	return false
}

func splitLines(text string) []string {
	var lines []string
	start := 0
	for i := range text {
		if text[i] == '\n' {
			lines = append(lines, text[start:i])
			start = i + 1
		}
	}
	return lines
}

type testInstance struct {
	id   string
	name string
}

func (i testInstance) ID() string                { return i.id }
func (i testInstance) Name() string              { return i.name }
func (testInstance) Start(context.Context) error { return nil }
func (testInstance) Close() error                { return nil }

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webconsole

import (
	"reflect"
	"strings"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/config"
	managepb "github.com/EasyTier/EasyTier/go/internal/proto/api_manage"
	commonpb "github.com/EasyTier/EasyTier/go/internal/proto/common"
	gproto "google.golang.org/protobuf/proto"
)

// cmFullNetworkConfig builds a console NetworkConfig that sets every switch the
// console form exposes.
func cmFullNetworkConfig() *managepb.NetworkConfig {
	manual := managepb.NetworkingMethod_Manual
	zstd := commonpb.CompressionAlgoPb_Zstd
	return &managepb.NetworkConfig{
		InstanceId:                  gproto.String("inst-full"),
		Dhcp:                        gproto.Bool(false),
		VirtualIpv4:                 gproto.String("10.144.7.9"),
		NetworkLength:               gproto.Int32(24),
		Hostname:                    gproto.String("node-full"),
		NetworkName:                 gproto.String("net-full"),
		NetworkSecret:               gproto.String("secret-full"),
		NetworkingMethod:            &manual,
		PeerUrls:                    []string{"tcp://public.easytier.cn:11010", "udp://peer.example.org:11010"},
		ProxyCidrs:                  []string{"192.168.50.0/24"},
		EnableVpnPortal:             gproto.Bool(true),
		VpnPortalListenPort:         gproto.Int32(51821),
		VpnPortalClientNetworkAddr:  gproto.String("10.14.14.0"),
		VpnPortalClientNetworkLen:   gproto.Int32(24),
		ListenerUrls:                []string{"tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"},
		LatencyFirst:                gproto.Bool(true),
		DevName:                     gproto.String("utun9"),
		UseSmoltcp:                  gproto.Bool(true),
		DisableIpv6:                 gproto.Bool(true),
		EnableKcpProxy:              gproto.Bool(true),
		DisableKcpInput:             gproto.Bool(true),
		EnableQuicProxy:             gproto.Bool(true),
		DisableQuicInput:            gproto.Bool(true),
		DisableP2P:                  gproto.Bool(true),
		P2POnly:                     gproto.Bool(true),
		LazyP2P:                     gproto.Bool(true),
		NeedP2P:                     gproto.Bool(true),
		BindDevice:                  gproto.Bool(false),
		NoTun:                       gproto.Bool(true),
		EnableExitNode:              gproto.Bool(true),
		RelayAllPeerRpc:             gproto.Bool(true),
		MultiThread:                 gproto.Bool(false),
		ProxyForwardBySystem:        gproto.Bool(true),
		DisableEncryption:           gproto.Bool(true),
		EnableRelayNetworkWhitelist: gproto.Bool(true),
		RelayNetworkWhitelist:       []string{"net-full", "net-*"},
		EnableManualRoutes:          gproto.Bool(true),
		Routes:                      []string{"172.16.0.0/16", "10.10.0.0/16"},
		ExitNodes:                   []string{"10.144.7.1"},
		EnableSocks5:                gproto.Bool(true),
		Socks5Port:                  gproto.Int32(1080),
		DisableUdpHolePunching:      gproto.Bool(true),
		DisableTcpHolePunching:      gproto.Bool(true),
		Mtu:                         gproto.Int32(1300),
		MappedListeners:             []string{"tcp://1.2.3.4:11010"},
		EnableMagicDns:              gproto.Bool(true),
		EnablePrivateMode:           gproto.Bool(true),
		DisableSymHolePunching:      gproto.Bool(true),
		DataCompressAlgo:            &zstd,
		EncryptionAlgorithm:         gproto.String("chacha20-poly1305"),
		DisableUpnp:                 gproto.Bool(true),
		DisableRelayData:            gproto.Bool(true),
		EnableUdpBroadcastRelay:     gproto.Bool(true),
		InstanceRecvBpsLimit:        gproto.Uint64(1048576),
		Ipv6PublicAddrProvider:      gproto.Bool(true),
		Ipv6PublicAddrAuto:          gproto.Bool(false),
		Ipv6PublicAddrPrefix:        gproto.String("2001:db8::/64"),
		CredentialFile:              gproto.String("/etc/easytier/credential.json"),
		PortForwards: []*managepb.PortForwardConfig{
			{BindIp: "0.0.0.0", BindPort: 8080, DstIp: "10.144.7.2", DstPort: 80, Proto: "tcp"},
			{BindIp: "::1", BindPort: 8443, DstIp: "10.144.7.3", DstPort: 443, Proto: "udp"},
			{BindIp: "", BindPort: 9000, DstIp: "10.144.7.4", DstPort: 9000, Proto: "tcp"},
		},
	}
}

func TestNetworkConfigToConfigAppliesEveryFlag(t *testing.T) {
	cfg, err := NetworkConfigToConfig(cmFullNetworkConfig())
	if err != nil {
		t.Fatalf("NetworkConfigToConfig: %v", err)
	}
	if cfg.Flags == nil {
		t.Fatal("Flags must always be non-nil")
	}

	expected := config.DefaultFlags()
	expected.LatencyFirst = true
	expected.DevName = "utun9"
	expected.UseSmoltcp = true
	expected.EnableIPv6 = false
	expected.EnableKCPProxy = true
	expected.DisableKCPInput = true
	expected.EnableQUICProxy = true
	expected.DisableQUICInput = true
	expected.DisableP2P = true
	expected.P2POnly = true
	expected.LazyP2P = true
	expected.NeedP2P = true
	expected.BindDevice = false
	expected.NoTUN = true
	expected.EnableExitNode = true
	expected.RelayAllPeerRPC = true
	expected.MultiThread = false
	expected.ProxyForwardBySystem = true
	expected.EnableEncryption = false
	expected.RelayNetworkWhitelist = "net-full net-*"
	expected.DisableTCPHolePunching = true
	expected.DisableUDPHolePunching = true
	expected.DisableUPnP = true
	expected.DisableRelayData = true
	expected.EnableUDPBroadcastRelay = true
	expected.DisableSymHolePunching = true
	expected.AcceptDNS = true
	expected.PrivateMode = true
	expected.MTU = 1300
	expected.InstanceRecvBPSLimit = 1048576
	expected.EncryptionAlgorithm = "chacha20-poly1305"
	expected.DataCompressAlgo = "zstd"

	if !reflect.DeepEqual(*cfg.Flags, expected) {
		t.Fatalf("flags mismatch:\n got %+v\nwant %+v", *cfg.Flags, expected)
	}

	if cfg.InstanceID != "inst-full" || cfg.Hostname != "node-full" {
		t.Fatalf("identity not mapped: %+v", cfg)
	}
	if cfg.InstanceName != "net-full" || cfg.NetworkIdentity.NetworkName != "net-full" ||
		cfg.NetworkIdentity.NetworkSecret != "secret-full" {
		t.Fatalf("network identity not mapped: %+v", cfg.NetworkIdentity)
	}
	if cfg.IPv4 != "10.144.7.9/24" {
		t.Fatalf("ipv4 = %q, want 10.144.7.9/24", cfg.IPv4)
	}
	if len(cfg.Peers) != 2 || cfg.Peers[0].URI != "tcp://public.easytier.cn:11010" {
		t.Fatalf("peers = %+v", cfg.Peers)
	}
	if len(cfg.Listeners) != 2 || cfg.Listeners[1] != "udp://0.0.0.0:11010" {
		t.Fatalf("listeners = %+v", cfg.Listeners)
	}
	if len(cfg.ProxyNetworks) != 1 || cfg.ProxyNetworks[0].CIDR != "192.168.50.0/24" {
		t.Fatalf("proxy networks = %+v", cfg.ProxyNetworks)
	}
	if len(cfg.PortForwards) != 2 {
		t.Fatalf("port forwards = %+v", cfg.PortForwards)
	}
	if cfg.PortForwards[0].BindAddr != "0.0.0.0:8080" || cfg.PortForwards[0].DstAddr != "10.144.7.2:80" {
		t.Fatalf("port forward 0 = %+v", cfg.PortForwards[0])
	}
	if cfg.PortForwards[1].BindAddr != "[::1]:8443" {
		t.Fatalf("ipv6 port forward not bracketed: %+v", cfg.PortForwards[1])
	}
	if cfg.VPNPortalConfig == nil || cfg.VPNPortalConfig.ClientCIDR != "10.14.14.0/24" ||
		cfg.VPNPortalConfig.WireGuardListen != "0.0.0.0:51821" {
		t.Fatalf("vpn portal = %+v", cfg.VPNPortalConfig)
	}
	if len(cfg.Routes) != 2 || cfg.ExitNodes[0] != "10.144.7.1" {
		t.Fatalf("routes/exit nodes = %+v / %+v", cfg.Routes, cfg.ExitNodes)
	}
	if cfg.Socks5Proxy != "socks5://0.0.0.0:1080" {
		t.Fatalf("socks5 proxy = %q", cfg.Socks5Proxy)
	}
	if len(cfg.MappedListeners) != 1 || cfg.CredentialFile != "/etc/easytier/credential.json" {
		t.Fatalf("mapped listeners/credential file = %+v / %q", cfg.MappedListeners, cfg.CredentialFile)
	}
	if !cfg.IPv6PublicAddrProvider || cfg.IPv6PublicAddrAuto || cfg.IPv6PublicAddrPrefix != "2001:db8::/64" {
		t.Fatalf("ipv6 public address mapping = %+v", cfg)
	}
	if cfg.SecureMode != nil {
		t.Fatalf("secure mode should be unset when the console sends none: %+v", cfg.SecureMode)
	}
}

func TestNetworkConfigToConfigNetworkingMethods(t *testing.T) {
	publicServer := managepb.NetworkingMethod_PublicServer
	manual := managepb.NetworkingMethod_Manual
	standalone := managepb.NetworkingMethod_Standalone

	tests := []struct {
		name      string
		config    *managepb.NetworkConfig
		wantDHCP  bool
		wantIPv4  string
		wantPeers []string
		wantName  string
	}{
		{
			name: "unset method behaves like public server",
			config: &managepb.NetworkConfig{
				NetworkName:     gproto.String("net-a"),
				PublicServerUrl: gproto.String("tcp://public.easytier.cn:11010"),
				VirtualIpv4:     gproto.String("10.1.2.3"),
			},
			wantIPv4:  "10.1.2.3/24",
			wantPeers: []string{"tcp://public.easytier.cn:11010"},
			wantName:  "net-a",
		},
		{
			name: "public server with explicit length",
			config: &managepb.NetworkConfig{
				NetworkName:      gproto.String("net-b"),
				NetworkingMethod: &publicServer,
				PublicServerUrl:  gproto.String("udp://public.easytier.cn:11010"),
				VirtualIpv4:      gproto.String("10.2.0.9"),
				NetworkLength:    gproto.Int32(16),
			},
			wantIPv4:  "10.2.0.9/16",
			wantPeers: []string{"udp://public.easytier.cn:11010"},
			wantName:  "net-b",
		},
		{
			name: "manual peers skip blank entries",
			config: &managepb.NetworkConfig{
				NetworkName:      gproto.String("net-c"),
				NetworkingMethod: &manual,
				PeerUrls:         []string{"tcp://a.example.org:11010", "", "ws://b.example.org:11011"},
				Dhcp:             gproto.Bool(true),
				VirtualIpv4:      gproto.String("10.3.3.3"),
			},
			wantDHCP:  true,
			wantPeers: []string{"tcp://a.example.org:11010", "ws://b.example.org:11011"},
			wantName:  "net-c",
		},
		{
			name: "standalone has no peers",
			config: &managepb.NetworkConfig{
				NetworkName:      gproto.String("net-d"),
				NetworkingMethod: &standalone,
			},
			wantName: "net-d",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := NetworkConfigToConfig(test.config)
			if err != nil {
				t.Fatalf("NetworkConfigToConfig: %v", err)
			}
			if cfg.DHCP != test.wantDHCP {
				t.Errorf("dhcp = %v, want %v", cfg.DHCP, test.wantDHCP)
			}
			if cfg.IPv4 != test.wantIPv4 {
				t.Errorf("ipv4 = %q, want %q", cfg.IPv4, test.wantIPv4)
			}
			var got []string
			for _, peer := range cfg.Peers {
				got = append(got, peer.URI)
			}
			if !reflect.DeepEqual(got, test.wantPeers) {
				t.Errorf("peers = %v, want %v", got, test.wantPeers)
			}
			if cfg.NetworkIdentity.NetworkName != test.wantName {
				t.Errorf("network name = %q, want %q", cfg.NetworkIdentity.NetworkName, test.wantName)
			}
			if cfg.InstanceID == "" {
				t.Error("instance id must be generated when the console does not send one")
			}
			if cfg.Flags == nil {
				t.Error("flags must always be set")
			}
		})
	}
}

func TestNetworkConfigToConfigCredentialMode(t *testing.T) {
	standalone := managepb.NetworkingMethod_Standalone
	cfg, err := NetworkConfigToConfig(&managepb.NetworkConfig{
		NetworkName:      gproto.String("net-cred"),
		NetworkingMethod: &standalone,
		SecureMode: &commonpb.SecureModeConfig{
			Enabled:         false,
			LocalPrivateKey: gproto.String("cHJpdmF0ZQ=="),
		},
	})
	if err != nil {
		t.Fatalf("NetworkConfigToConfig: %v", err)
	}
	if cfg.NetworkIdentity.NetworkSecret != "" {
		t.Errorf("network secret = %q, want empty in credential mode", cfg.NetworkIdentity.NetworkSecret)
	}
	if cfg.SecureMode == nil || !cfg.SecureMode.Enabled ||
		cfg.SecureMode.LocalPrivateKey != "cHJpdmF0ZQ==" {
		t.Fatalf("secure mode = %+v", cfg.SecureMode)
	}

	// With a network secret the console secure mode is passed through as-is.
	cfg, err = NetworkConfigToConfig(&managepb.NetworkConfig{
		NetworkName:      gproto.String("net-plain"),
		NetworkingMethod: &standalone,
		NetworkSecret:    gproto.String("secret"),
		SecureMode: &commonpb.SecureModeConfig{
			Enabled:         true,
			LocalPrivateKey: gproto.String("a2V5"),
			LocalPublicKey:  gproto.String("cHVi"),
		},
	})
	if err != nil {
		t.Fatalf("NetworkConfigToConfig: %v", err)
	}
	if cfg.SecureMode == nil || !cfg.SecureMode.Enabled || cfg.SecureMode.LocalPublicKey != "cHVi" {
		t.Fatalf("secure mode = %+v", cfg.SecureMode)
	}
}

func TestNetworkConfigToConfigRejectsInvalidInput(t *testing.T) {
	manual := managepb.NetworkingMethod_Manual
	tests := []struct {
		name   string
		config *managepb.NetworkConfig
		want   string
	}{
		{
			name:   "nil config",
			config: nil,
			want:   "nil",
		},
		{
			name: "bad proxy cidr",
			config: &managepb.NetworkConfig{
				NetworkName:     gproto.String("net"),
				PublicServerUrl: gproto.String("tcp://public.easytier.cn:11010"),
				ProxyCidrs:      []string{"192.168.1.0/33"},
			},
			want: "proxy_cidrs",
		},
		{
			name: "bad peer uri",
			config: &managepb.NetworkConfig{
				NetworkName:      gproto.String("net"),
				NetworkingMethod: &manual,
				PeerUrls:         []string{"not-a-url"},
			},
			want: "peer uri",
		},
		{
			name: "empty public server url",
			config: &managepb.NetworkConfig{
				NetworkName: gproto.String("net"),
			},
			want: "public_server_url",
		},
		{
			name: "bad exit node",
			config: &managepb.NetworkConfig{
				NetworkName:     gproto.String("net"),
				PublicServerUrl: gproto.String("tcp://public.easytier.cn:11010"),
				ExitNodes:       []string{"10.0.0.300"},
			},
			want: "exit_nodes",
		},
		{
			name: "bad route",
			config: &managepb.NetworkConfig{
				NetworkName:        gproto.String("net"),
				PublicServerUrl:    gproto.String("tcp://public.easytier.cn:11010"),
				EnableManualRoutes: gproto.Bool(true),
				Routes:             []string{"172.16.0.0/40"},
			},
			want: "routes",
		},
		{
			name: "bad virtual ipv4",
			config: &managepb.NetworkConfig{
				NetworkName:     gproto.String("net"),
				PublicServerUrl: gproto.String("tcp://public.easytier.cn:11010"),
				VirtualIpv4:     gproto.String("10.0.0.999"),
			},
			want: "virtual_ipv4",
		},
		{
			name: "bad vpn portal cidr",
			config: &managepb.NetworkConfig{
				NetworkName:                gproto.String("net"),
				PublicServerUrl:            gproto.String("tcp://public.easytier.cn:11010"),
				EnableVpnPortal:            gproto.Bool(true),
				VpnPortalClientNetworkAddr: gproto.String("10.0.0.0/40"),
			},
			want: "vpn_portal_client_network_addr",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NetworkConfigToConfig(test.config)
			if err == nil {
				t.Fatalf("expected an error mentioning %q", test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error %q does not mention %q", err, test.want)
			}
		})
	}
}

func TestNetworkConfigRoundTripIsStable(t *testing.T) {
	first, err := NetworkConfigToConfig(cmFullNetworkConfig())
	if err != nil {
		t.Fatalf("NetworkConfigToConfig: %v", err)
	}
	roundTripped, err := NetworkConfigToConfig(ConfigToNetworkConfig("inst-full", first))
	if err != nil {
		t.Fatalf("NetworkConfigToConfig after inverse: %v", err)
	}

	if roundTripped.InstanceID != first.InstanceID ||
		roundTripped.Hostname != first.Hostname ||
		roundTripped.InstanceName != first.InstanceName ||
		roundTripped.IPv4 != first.IPv4 ||
		roundTripped.DHCP != first.DHCP ||
		roundTripped.NetworkIdentity != first.NetworkIdentity ||
		roundTripped.Socks5Proxy != first.Socks5Proxy ||
		roundTripped.CredentialFile != first.CredentialFile {
		t.Fatalf("identity drifted:\n got %+v\nwant %+v", roundTripped, first)
	}
	if !reflect.DeepEqual(roundTripped.Listeners, first.Listeners) {
		t.Errorf("listeners drifted: %v vs %v", roundTripped.Listeners, first.Listeners)
	}
	if !reflect.DeepEqual(roundTripped.Peers, first.Peers) {
		t.Errorf("peers drifted: %v vs %v", roundTripped.Peers, first.Peers)
	}
	if !reflect.DeepEqual(roundTripped.ProxyNetworks, first.ProxyNetworks) {
		t.Errorf("proxy networks drifted: %v vs %v", roundTripped.ProxyNetworks, first.ProxyNetworks)
	}
	if !reflect.DeepEqual(roundTripped.PortForwards, first.PortForwards) {
		t.Errorf("port forwards drifted: %v vs %v", roundTripped.PortForwards, first.PortForwards)
	}
	if !reflect.DeepEqual(roundTripped.Routes, first.Routes) {
		t.Errorf("routes drifted: %v vs %v", roundTripped.Routes, first.Routes)
	}
	if !reflect.DeepEqual(roundTripped.ExitNodes, first.ExitNodes) {
		t.Errorf("exit nodes drifted: %v vs %v", roundTripped.ExitNodes, first.ExitNodes)
	}
	if !reflect.DeepEqual(roundTripped.MappedListeners, first.MappedListeners) {
		t.Errorf("mapped listeners drifted: %v vs %v", roundTripped.MappedListeners, first.MappedListeners)
	}
	if !reflect.DeepEqual(roundTripped.VPNPortalConfig, first.VPNPortalConfig) {
		t.Errorf("vpn portal drifted: %v vs %v", roundTripped.VPNPortalConfig, first.VPNPortalConfig)
	}
	if !reflect.DeepEqual(roundTripped.Flags, first.Flags) {
		t.Errorf("flags drifted:\n got %+v\nwant %+v", roundTripped.Flags, first.Flags)
	}
}

func TestConfigToNetworkConfigMapsFlagsAndPorts(t *testing.T) {
	flags := config.DefaultFlags()
	flags.EnableIPv6 = false
	flags.EnableEncryption = false
	flags.LatencyFirst = true
	flags.DevName = "tun7"
	flags.UseSmoltcp = true
	flags.MTU = 1400
	flags.InstanceRecvBPSLimit = 4096
	flags.DataCompressAlgo = "zstd"
	flags.EncryptionAlgorithm = "aes-256-gcm"
	flags.PrivateMode = true
	flags.AcceptDNS = true

	nc := ConfigToNetworkConfig("inst-map", &config.Config{
		Hostname:        "node-map",
		DHCP:            false,
		IPv4:            "10.9.9.9/22",
		InstanceName:    "net-map",
		NetworkIdentity: config.NetworkIdentity{NetworkName: "net-map", NetworkSecret: "s3cr3t"},
		Peers:           []config.Peer{{URI: "tcp://peer.example.org:11010"}},
		Listeners:       []string{"tcp://0.0.0.0:11010"},
		ProxyNetworks:   []config.ProxyNetwork{{CIDR: "192.168.9.0/24"}},
		PortForwards: []config.PortForward{
			{BindAddr: "0.0.0.0:8080", DstAddr: "[::1]:80", Proto: "tcp"},
			{BindAddr: "broken", DstAddr: "10.0.0.1:80", Proto: "tcp"},
		},
		VPNPortalConfig: &config.VPNPortalConfig{ClientCIDR: "10.14.0.0/24", WireGuardListen: "0.0.0.0:51820"},
		Routes:          []string{"172.16.0.0/16"},
		ExitNodes:       []string{"10.9.9.1"},
		MappedListeners: []string{"tcp://1.2.3.4:11010"},
		Socks5Proxy:     "socks5://0.0.0.0:1080",
		CredentialFile:  "/tmp/credential.json",
		Flags:           &flags,
	})

	if nc.GetInstanceId() != "inst-map" || nc.GetHostname() != "node-map" || nc.GetNetworkName() != "net-map" {
		t.Fatalf("basic fields = %v", nc)
	}
	if nc.GetNetworkSecret() != "s3cr3t" || nc.GetDhcp() {
		t.Fatalf("secret/dhcp = %q/%v", nc.GetNetworkSecret(), nc.GetDhcp())
	}
	if nc.GetVirtualIpv4() != "10.9.9.9" || nc.GetNetworkLength() != 22 {
		t.Fatalf("ipv4 = %q/%d", nc.GetVirtualIpv4(), nc.GetNetworkLength())
	}
	if nc.GetNetworkingMethod() != managepb.NetworkingMethod_Manual || len(nc.GetPeerUrls()) != 1 {
		t.Fatalf("networking method = %v peers %v", nc.GetNetworkingMethod(), nc.GetPeerUrls())
	}
	if !nc.GetEnableVpnPortal() || nc.GetVpnPortalListenPort() != 51820 ||
		nc.GetVpnPortalClientNetworkAddr() != "10.14.0.0" || nc.GetVpnPortalClientNetworkLen() != 24 {
		t.Fatalf("vpn portal = %v", nc.GetVpnPortalClientNetworkAddr())
	}
	if !nc.GetEnableSocks5() || nc.GetSocks5Port() != 1080 {
		t.Fatalf("socks5 = %v/%d", nc.GetEnableSocks5(), nc.GetSocks5Port())
	}
	if !nc.GetEnableManualRoutes() || len(nc.GetRoutes()) != 1 {
		t.Fatalf("routes = %v", nc.GetRoutes())
	}
	if len(nc.GetPortForwards()) != 1 {
		t.Fatalf("malformed port forwards must be dropped: %v", nc.GetPortForwards())
	}
	if forward := nc.GetPortForwards()[0]; forward.GetDstIp() != "::1" || forward.GetDstPort() != 80 {
		t.Fatalf("port forward = %v", forward)
	}
	if !nc.GetDisableIpv6() || !nc.GetDisableEncryption() {
		t.Fatalf("inverted flags not mapped: ipv6=%v encryption=%v", nc.GetDisableIpv6(), nc.GetDisableEncryption())
	}
	if !nc.GetLatencyFirst() || nc.GetDevName() != "tun7" || !nc.GetUseSmoltcp() {
		t.Fatalf("latency/dev/smoltcp not mapped")
	}
	if nc.GetMtu() != 1400 || nc.GetInstanceRecvBpsLimit() != 4096 {
		t.Fatalf("mtu/bps = %d/%d", nc.GetMtu(), nc.GetInstanceRecvBpsLimit())
	}
	if nc.GetDataCompressAlgo() != commonpb.CompressionAlgoPb_Zstd {
		t.Fatalf("compression = %v", nc.GetDataCompressAlgo())
	}
	if nc.GetEncryptionAlgorithm() != "aes-256-gcm" || !nc.GetEnablePrivateMode() || !nc.GetEnableMagicDns() {
		t.Fatalf("algorithm/private/dns not mapped")
	}
	if !nc.GetBindDevice() || !nc.GetMultiThread() {
		t.Fatalf("default-true flags must be preserved: bind=%v multi=%v", nc.GetBindDevice(), nc.GetMultiThread())
	}

	// Standalone when the local config has no peers.
	standalone := ConfigToNetworkConfig("inst-alone", &config.Config{
		NetworkIdentity: config.NetworkIdentity{NetworkName: "net-alone"},
	})
	if standalone.GetNetworkingMethod() != managepb.NetworkingMethod_Standalone {
		t.Fatalf("networking method = %v, want standalone", standalone.GetNetworkingMethod())
	}
}

func TestValidateNetworkConfigReturnsParseableTOML(t *testing.T) {
	text, err := ValidateNetworkConfig(cmFullNetworkConfig())
	if err != nil {
		t.Fatalf("ValidateNetworkConfig: %v", err)
	}
	for _, want := range []string{
		`instance_id = 'inst-full'`,
		`network_name = 'net-full'`,
		`ipv4 = '10.144.7.9/24'`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered TOML is missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "advanced_settings") {
		t.Fatalf("ui-only fields must not leak into the TOML:\n%s", text)
	}

	parsed, err := config.ParseTOML([]byte(text))
	if err != nil {
		t.Fatalf("rendered TOML does not parse: %v\n%s", err, text)
	}
	if parsed.InstanceID != "inst-full" {
		t.Fatalf("instance id = %q, want inst-full", parsed.InstanceID)
	}
	if parsed.Flags == nil || parsed.Flags.DataCompressAlgo != "zstd" || parsed.Flags.MTU != 1300 {
		t.Fatalf("flags did not survive the round trip: %+v", parsed.Flags)
	}

	if _, err := ValidateNetworkConfig(nil); err == nil {
		t.Fatal("ValidateNetworkConfig must reject a nil config")
	}
}

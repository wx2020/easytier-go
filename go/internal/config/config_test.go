// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestLoadExpandsEnvironmentAndMarksConfigReadOnly(t *testing.T) {
	t.Setenv("ET_NETWORK", "test-network")
	path := writeConfig(t, ""+
		"ipv4 = \"10.144.144.1\"\n"+
		"[network_identity]\n"+
		"network_name = \"${ET_NETWORK}\"\n"+
		"network_secret = \"${MISSING_SECRET:-fallback}\"\n")

	cfg, readOnly, err := Load(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if !readOnly {
		t.Fatal("expanded config must be read-only")
	}
	if cfg.NetworkIdentity.NetworkName != "test-network" || cfg.NetworkIdentity.NetworkSecret != "fallback" {
		t.Fatalf("identity = %#v", cfg.NetworkIdentity)
	}
	prefix, ok, err := cfg.IPv4Prefix()
	if err != nil || !ok || prefix.String() != "10.144.144.1/24" {
		t.Fatalf("prefix = %v, %t, %v", prefix, ok, err)
	}
}

func TestLoadCanDisableEnvironmentExpansion(t *testing.T) {
	path := writeConfig(t, ""+
		"[network_identity]\n"+
		"network_name = \"${ET_NETWORK:-literal}\"\n")
	cfg, readOnly, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if readOnly || cfg.NetworkIdentity.NetworkName != "${ET_NETWORK:-literal}" {
		t.Fatalf("got readOnly=%t config=%#v", readOnly, cfg)
	}
}

func TestLoadEnvironmentMissingAndEmptyDefault(t *testing.T) {
	t.Setenv("ET_EMPTY", "")
	if expanded, changed := expandEnvironment("${ET_EMPTY:-fallback}"); expanded != "fallback" || !changed {
		t.Fatalf("empty default expansion = %q, %t", expanded, changed)
	}
	path := writeConfig(t, ""+
		"hostname = \"${ET_EMPTY:-fallback}\"\n"+
		"[network_identity]\n"+
		"network_name = \"test\"\n"+
		"network_secret = \"${ET_MISSING}\"\n")

	cfg, readOnly, err := Load(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if readOnly || cfg.NetworkIdentity.NetworkSecret != "${ET_MISSING}" || cfg.Hostname != "${ET_EMPTY:-fallback}" {
		t.Fatalf("missing/default expansion = readOnly=%t config=%#v", readOnly, cfg)
	}
}

func TestLoadReadsStdinAsStaticConfig(t *testing.T) {
	stdin, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() {
		os.Stdin = original
		_ = stdin.Close()
	})
	if _, err := writer.WriteString("[network_identity]\nnetwork_name = \"stdin\"\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, readOnly, err := Load("-", false)
	if err != nil {
		t.Fatal(err)
	}
	if !readOnly || cfg.NetworkIdentity.NetworkName != "stdin" {
		t.Fatalf("stdin config = readOnly=%t config=%#v", readOnly, cfg)
	}
}

func TestLoadSourcesSelectsExplicitAndDirectoryTOMLFiles(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "b.toml")
	second := filepath.Join(directory, "a.toml")
	ignored := filepath.Join(directory, "ignored.txt")
	for path, network := range map[string]string{
		first:   "directory-b",
		second:  "directory-a",
		ignored: "ignored",
	} {
		if err := os.WriteFile(path, []byte("[network_identity]\nnetwork_name = \""+network+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	explicit := writeConfig(t, "[network_identity]\nnetwork_name = \"explicit\"\n")

	loaded, err := LoadSources([]string{explicit}, directory, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 3 {
		t.Fatalf("loaded %d configs, want 3", len(loaded))
	}
	got := []string{
		loaded[0].Config.NetworkIdentity.NetworkName,
		loaded[1].Config.NetworkIdentity.NetworkName,
		loaded[2].Config.NetworkIdentity.NetworkName,
	}
	if want := []string{"explicit", "directory-a", "directory-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("config selection = %#v, want %#v", got, want)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, cfg := range []Config{
		{},
		{NetworkIdentity: NetworkIdentity{NetworkName: "test"}, IPv4: "not-an-ip"},
		{NetworkIdentity: NetworkIdentity{NetworkName: "test"}, IPv6: "not-an-ip"},
		{NetworkIdentity: NetworkIdentity{NetworkName: "test"}, Listeners: []string{"invalid://listener"}},
		{NetworkIdentity: NetworkIdentity{NetworkName: "test"}, Routes: []string{"not-a-cidr"}},
		{NetworkIdentity: NetworkIdentity{NetworkName: "test"}, Peers: []Peer{{}}},
	} {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate(%#v) succeeded", cfg)
		}
	}
}

func TestConfigRejectsUnsupportedCompression(t *testing.T) {
	cfg := Config{
		NetworkIdentity: NetworkIdentity{NetworkName: "test"},
		Flags:           &Flags{DataCompressAlgo: "brotli"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsupported compression algorithm succeeded")
	}
}

func TestConfigAcceptsIPv6RoutesAndProxyNetworks(t *testing.T) {
	cfg := Config{
		NetworkIdentity: NetworkIdentity{NetworkName: "mesh"},
		Routes:          []string{"2001:db8:10::/48"},
		ProxyNetworks: []ProxyNetwork{{
			CIDR:       "2001:db8:20::/48",
			MappedCIDR: "2001:db8:30::/48",
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestReferenceStyleConfigParsingAndSerialization(t *testing.T) {
	path := writeConfig(t, `
hostname = "edge-1"
instance_name = "reference"
ipv4 = "10.144.144.10/24"
ipv6 = "fd00:144:144::10/64"
ipv6_public_addr_provider = true
ipv6_public_addr_auto = true
ipv6_public_addr_prefix = "2001:db8:144::/64"
listeners = ["tcp://0.0.0.0:11010", "udp://[::]:11010"]
mapped_listeners = ["tcp://203.0.113.10:11010"]
exit_nodes = ["10.144.144.1", "fd00:144:144::1"]
routes = ["192.168.0.0/16", "10.0.0.0/8"]
socks5_proxy = "socks5://0.0.0.0:1080"
tcp_whitelist = ["10.0.0.0/8"]
udp_whitelist = ["fd00::/8"]
stun_servers = ["stun.example.test:3478"]
stun_servers_v6 = ["[2001:db8::1]:3478"]

[network_identity]
network_name = "reference-network"
network_secret = "secret"

[[peer]]
uri = "tcp://relay.example.test:11010"
peer_public_key = "peer-key"

[[proxy_network]]
cidr = "192.168.50.0/24"
mapped_cidr = "10.50.0.0/24"
allow = ["tcp", "udp"]

[vpn_portal_config]
client_cidr = "10.144.200.0/24"
wireguard_listen = "0.0.0.0:51820"

[[port_forward]]
bind_addr = "0.0.0.0:8080"
dst_addr = "10.144.144.20:80"
proto = "tcp"

[secure_mode]
enabled = true
local_private_key = "private-key"
local_public_key = "public-key"

[flags]
enable_ipv6 = true
enable_exit_node = true
relay_network_whitelist = "reference-*"
disable_upnp = true

[acl.acl_v1.group]
members = ["operators"]

[[acl.acl_v1.group.declares]]
group_name = "operators"
group_secret = "group-secret"

[[acl.acl_v1.chains]]
name = "inbound"
chain_type = 1
enabled = true
default_action = 2

[[acl.acl_v1.chains.rules]]
name = "allow-ssh"
priority = 100
enabled = true
protocol = 1
ports = ["22"]
source_ips = ["10.0.0.0/8"]
action = 1
stateful = true
`)

	cfg, readOnly, err := Load(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if readOnly {
		t.Fatal("config without environment references must be editable")
	}
	if cfg.IPv6 != "fd00:144:144::10/64" || len(cfg.MappedListeners) != 1 || len(cfg.ExitNodes) != 2 {
		t.Fatalf("IPv6/listeners/exit nodes = %#v", cfg)
	}
	if len(cfg.Routes) != 2 || cfg.ProxyNetworks[0].MappedCIDR != "10.50.0.0/24" || cfg.VPNPortalConfig.WireGuardListen != "0.0.0.0:51820" {
		t.Fatalf("routes/proxy/VPN portal = %#v", cfg)
	}
	if cfg.SecureMode == nil || !cfg.SecureMode.Enabled || cfg.Flags == nil || !cfg.Flags.EnableExitNode {
		t.Fatalf("secure mode/flags = %#v", cfg)
	}
	if cfg.ACL == nil || cfg.ACL.ACLV1 == nil || len(cfg.ACL.ACLV1.Chains) != 1 || cfg.ACL.ACLV1.Chains[0].Rules[0].Action != 1 {
		t.Fatalf("ACL = %#v", cfg.ACL)
	}

	encoded, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "[secure_mode]") || !strings.Contains(string(encoded), "[[proxy_network]]") {
		t.Fatalf("serialized TOML missing reference sections:\n%s", encoded)
	}
	var decoded Config
	if err := toml.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("serialized TOML did not parse: %v", err)
	}
	if decoded.NetworkIdentity.NetworkName != cfg.NetworkIdentity.NetworkName || decoded.Socks5Proxy != cfg.Socks5Proxy || decoded.ACL.ACLV1.Chains[0].Rules[0].Name != "allow-ssh" {
		t.Fatalf("round trip config = %#v", decoded)
	}
}

func TestConfigBuildsReferenceCompatibleLegacyIdentity(t *testing.T) {
	cfg := Config{NetworkIdentity: NetworkIdentity{NetworkName: "mesh", NetworkSecret: "secret"}}
	identity, err := cfg.LegacyIdentity(42)
	if err != nil {
		t.Fatal(err)
	}
	if identity.PeerID != 42 || identity.NetworkName != "mesh" {
		t.Fatalf("identity = %#v", identity)
	}
	if got := fmt.Sprintf("%x", identity.NetworkSecretDigest); got != "31107b8e51f0ce46f7b98ceefacfec089fdf3c65e27f8b20fbe21c0ae043c564" {
		t.Fatalf("digest = %s", got)
	}
}

func writeConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

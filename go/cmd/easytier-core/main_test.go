// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/management"
)

func TestParseArgsSupportsCompatibilityFlags(t *testing.T) {
	options, err := parseArgs([]string{
		"-l", "tcp://0.0.0.0:11010,udp://[::]:11010",
		"--listeners", "ws://0.0.0.0:11011",
		"-p", "tcp://peer-1:11010",
		"--peers", "udp://peer-2:11010,ws://peer-3:11010",
		"-i", "10.144.144.2/24",
		"-d",
		"--network-name", "test-network",
		"--network-secret", "secret",
		"-f", "config.toml",
		"--check-config",
		"--disable-env-parsing",
		"-r", "127.0.0.1:15888",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := []string(options.listeners), []string{"tcp://0.0.0.0:11010", "udp://[::]:11010", "ws://0.0.0.0:11011"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listeners = %#v, want %#v", got, want)
	}
	if got, want := []string(options.peers), []string{"tcp://peer-1:11010", "udp://peer-2:11010", "ws://peer-3:11010"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("peers = %#v, want %#v", got, want)
	}
	if options.ipv4 != "10.144.144.2/24" || !options.dhcp || options.networkName != "test-network" || options.networkSecret != "secret" || options.configFile != "config.toml" || !options.checkConfig || !options.disableEnvironmentParsing || options.rpcPortal != "127.0.0.1:15888" || !options.rpcPortalSet {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseArgsKeepsListenAlias(t *testing.T) {
	options, err := parseArgs([]string{"--listen", "127.0.0.1:11010"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := []string(options.listeners), []string{"127.0.0.1:11010"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listeners = %#v, want %#v", got, want)
	}
}

func TestCoreHelpGoldenContract(t *testing.T) {
	help := coreHelp()
	for _, want := range []string{
		"Usage: easytier-core [OPTIONS]",
		"-d\tenable DHCP",
		"-f value",
		"-l value",
		"-p value",
		"-u\tdisable encryption",
		"-n value",
		"-m string",
		"-rpc-portal string",
		"-stun-servers value",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help is missing %q:\n%s", want, help)
		}
	}
}

func TestParseArgsRustAliasesOptionalBooleansAndDelimitedValues(t *testing.T) {
	options, err := parseArgs([]string{
		"-l", "tcp://0.0.0.0:11010,udp://0.0.0.0:11010",
		"-p", "tcp://peer:11010,udp://peer:11011",
		"-i", "10.144.144.2/24",
		"-d=false",
		"-e", "tcp://external:11010",
		"-n", "10.0.0.0/8->192.168.0.0/16",
		"-m", "instance",
		"-u",
		"--disable-ipv6",
		"--exit-nodes", "10.0.0.1,10.0.0.2",
		"--manual-routes", "10.1.0.0/16,10.2.0.0/16",
		"--stun-servers", "stun-a,stun-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.dhcp || !options.disableEncryption || !options.disableIPv6 || options.instanceName != "instance" {
		t.Fatalf("optional booleans or aliases parsed incorrectly: %#v", options)
	}
	if got, want := []string(options.listeners), []string{"tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listeners = %#v, want %#v", got, want)
	}
	if got, want := []string(options.proxyNetworks), []string{"10.0.0.0/8->192.168.0.0/16"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("proxy networks = %#v, want %#v", got, want)
	}
	if !options.boolSet["dhcp"] || !options.boolSet["disable-encryption"] || !options.boolSet["disable-ipv6"] {
		t.Fatalf("optional bool set tracking = %#v", options.boolSet)
	}
}

func TestParseArgsEnvironmentMappingsYieldToCLI(t *testing.T) {
	t.Setenv("ET_NETWORK_NAME", "from-env")
	t.Setenv("ET_NETWORK_SECRET", "env-secret")
	t.Setenv("ET_LISTENERS", "tcp://env:11010,udp://env:11010")
	t.Setenv("ET_DHCP", "false")
	t.Setenv("ET_RPC_PORTAL", "127.0.0.1:25888")

	options, err := parseArgs([]string{"--network-name", "from-cli", "--dhcp"})
	if err != nil {
		t.Fatal(err)
	}
	if options.networkName != "from-cli" || options.networkSecret != "env-secret" || !options.dhcp || options.rpcPortal != "127.0.0.1:25888" || !options.rpcPortalSet {
		t.Fatalf("environment mapping = %#v", options)
	}
	if got, want := []string(options.listeners), []string{"tcp://env:11010", "udp://env:11010"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listeners from environment = %#v, want %#v", got, want)
	}
}

func TestApplyOptionsMapsRepresentableConfigFields(t *testing.T) {
	options, err := parseArgs([]string{
		"--network-name", "mesh",
		"--network-secret", "secret",
		"--mapped-listeners", "tcp://203.0.113.1:11010,udp://203.0.113.1:11010",
		"--proxy-networks", "10.0.0.0/8->192.168.0.0/16",
		"--vpn-portal", "wireguard://127.0.0.1:51820/10.200.0.0/24",
		"--port-forward", "tcp://127.0.0.1:8080/10.0.0.2:80",
		"--compression", "zstd",
		"--disable-encryption=false",
		"--tcp-whitelist", "10.0.0.0/8,192.168.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := applyOptions(&cfg, options); err != nil {
		t.Fatal(err)
	}
	if cfg.NetworkIdentity.NetworkName != "mesh" || cfg.NetworkIdentity.NetworkSecret != "secret" || len(cfg.MappedListeners) != 2 || len(cfg.ProxyNetworks) != 1 {
		t.Fatalf("network config = %#v", cfg)
	}
	if cfg.VPNPortalConfig == nil || cfg.VPNPortalConfig.ClientCIDR != "10.200.0.0/24" || len(cfg.PortForwards) != 1 {
		t.Fatalf("portal/forward config = %#v", cfg)
	}
	if cfg.Flags == nil || cfg.Flags.DataCompressAlgo != "zstd" || !cfg.Flags.EnableEncryption {
		t.Fatalf("flag config = %#v", cfg.Flags)
	}
}

func TestRunChecksConfigWithInternalValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[network_identity]\nnetwork_name = \"test-network\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"--check-config", "--config-file", path}, &stdout, &stderr); status != 0 {
		t.Fatalf("run status = %d, stderr = %s", status, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestParseArgsSupportsConfigDirectoryAndMultipleFiles(t *testing.T) {
	options, err := parseArgs([]string{
		"--config-file", "one.toml,two.toml",
		"--config-file", "-",
		"--config-dir", "/etc/easytier",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := []string(options.configFiles), []string{"one.toml", "two.toml", "-"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("config files = %#v, want %#v", got, want)
	}
	if options.configFile != "one.toml" || options.configDir != "/etc/easytier" {
		t.Fatalf("options = %#v", options)
	}
}

func TestRunChecksConfigDirectory(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"one.toml", "two.toml"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("[network_identity]\nnetwork_name = \""+name+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"--check-config", "--config-dir", directory}, &stdout, &stderr); status != 0 {
		t.Fatalf("run status = %d, stderr = %s", status, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunReportsInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("ipv4 = \"not-an-ip\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	if status := run(context.Background(), []string{"--check-config", "-f", path}, &bytes.Buffer{}, &stderr); status != 2 {
		t.Fatalf("run status = %d, stderr = %s", status, stderr.String())
	}
	if !strings.Contains(stderr.String(), "validate config") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestTCPListenerAddress(t *testing.T) {
	for _, test := range []struct {
		listener string
		want     string
		fails    bool
	}{
		{"127.0.0.1:11010", "127.0.0.1:11010", false},
		{"tcp://[::1]:11010", "[::1]:11010", false},
		{"udp://127.0.0.1:11010", "", true},
	} {
		got, err := tcpListenerAddress(test.listener)
		if test.fails {
			if err == nil {
				t.Fatalf("tcpListenerAddress(%q) succeeded", test.listener)
			}
			continue
		}
		if err != nil || got != test.want {
			t.Fatalf("tcpListenerAddress(%q) = %q, %v", test.listener, got, err)
		}
	}
}

func TestLoopbackWhitelist(t *testing.T) {
	whitelist := loopbackWhitelist()
	if len(whitelist) != 2 || !whitelist[0].Contains(netip.MustParseAddr("127.0.0.1")) || !whitelist[1].Contains(netip.MustParseAddr("::1")) {
		t.Fatalf("whitelist = %#v", whitelist)
	}
}

func TestConfigNetworkIdentityCanStartHandshakeNode(t *testing.T) {
	cfg := config.Config{NetworkIdentity: config.NetworkIdentity{NetworkName: "mesh", NetworkSecret: "secret"}}
	identity, err := cfg.LegacyIdentity(2)
	if err != nil {
		t.Fatal(err)
	}
	node, err := newCoreNode("127.0.0.1:0", &peerIdentity{value: identity})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRunServesManagementPortalAndStopsCleanly(t *testing.T) {
	listenerAddress := freeTCPAddress(t)
	portalAddress := freeTCPAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- run(ctx, []string{
			"--listen", listenerAddress,
			"--rpc-portal", portalAddress,
			"--network-name", "test-network",
			"--network-secret", "test-secret",
		}, &stdout, &stderr)
	}()

	deadline := time.Now().Add(10 * time.Second)
	client := management.NewClient(portalAddress, 1, 2)
	for {
		callCtx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
		info, err := client.NodeInfo(callCtx)
		stop()
		if err == nil {
			if info.Version != version {
				t.Fatalf("node info = %#v", info)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("management portal did not become ready: %v; stderr=%s", err, stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case status := <-result:
		if status != 0 || stderr.Len() != 0 {
			t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
		}
	case <-time.After(time.Second):
		t.Fatal("core did not stop after context cancellation")
	}
}

func TestRunStartsMultipleConfiguredInstancesAndManagesThemByLocalName(t *testing.T) {
	firstAddress := freeTCPAddress(t)
	secondAddress := freeTCPAddress(t)
	portalAddress := freeTCPAddress(t)
	directory := t.TempDir()
	writeRuntimeConfig(t, filepath.Join(directory, "alpha.toml"), "alpha", firstAddress)
	writeRuntimeConfig(t, filepath.Join(directory, "beta.toml"), "beta", secondAddress)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() {
		result <- run(ctx, []string{"--config-dir", directory, "--rpc-portal", portalAddress}, &stdout, &stderr)
	}()

	waitForPorts(t, firstAddress, secondAddress, portalAddress)
	client := management.NewClient(portalAddress, 1, 2)
	items, err := client.InstanceList(context.Background())
	if err != nil || len(items) != 2 || items[0].Name != "alpha" || items[1].Name != "beta" {
		t.Fatalf("instance list = %#v, %v", items, err)
	}
	statuses, err := client.InstanceStatusList(context.Background())
	if err != nil || len(statuses) != 2 || !statuses[0].Running || !statuses[1].Running {
		t.Fatalf("instance statuses = %#v, %v", statuses, err)
	}
	if err := client.InstanceStop(context.Background(), "alpha"); err != nil {
		t.Fatal(err)
	}
	statuses, err = client.InstanceStatusList(context.Background())
	if err != nil || statuses[0].State != "stopped" || statuses[0].Running {
		t.Fatalf("stopped alpha status = %#v, %v", statuses, err)
	}
	if _, err := client.InstanceStart(context.Background(), "alpha"); err != nil {
		t.Fatal(err)
	}
	if canListen(firstAddress) || canListen(secondAddress) {
		t.Fatal("configured instance port was not occupied")
	}

	cancel()
	select {
	case status := <-result:
		if status != 0 || stderr.Len() != 0 {
			t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
		}
	case <-time.After(time.Second):
		t.Fatal("multi-instance core did not stop after context cancellation")
	}
	if !canListen(firstAddress) || !canListen(secondAddress) || !canListen(portalAddress) {
		t.Fatal("a configured listener remained open after context cancellation")
	}
}

func TestRunRollsBackStartedInstancesWhenAConfigCannotStart(t *testing.T) {
	address := freeTCPAddress(t)
	directory := t.TempDir()
	writeRuntimeConfig(t, filepath.Join(directory, "first.toml"), "first", address)
	writeRuntimeConfig(t, filepath.Join(directory, "second.toml"), "second", address)

	var stderr bytes.Buffer
	if status := run(context.Background(), []string{"--config-dir", directory, "--rpc-portal", freeTCPAddress(t)}, &bytes.Buffer{}, &stderr); status != 1 {
		t.Fatalf("run status = %d, stderr=%q", status, stderr.String())
	}
	if !canListen(address) {
		t.Fatal("rollback left the first instance port open")
	}
}

func writeRuntimeConfig(t *testing.T, path, name, address string) {
	t.Helper()
	text := fmt.Sprintf("instance_name = %q\nlisteners = [\"tcp://%s\"]\n[network_identity]\nnetwork_name = %q\nnetwork_secret = \"secret\"\n", name, address, name)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForPorts(t *testing.T, addresses ...string) {
	t.Helper()
	// Generous for loaded race-mode runners.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, address := range addresses {
			if canListen(address) {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("configured listeners did not become ready: %v", addresses)
}

func canListen(address string) bool {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

func freeTCPAddress(t *testing.T) string {
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

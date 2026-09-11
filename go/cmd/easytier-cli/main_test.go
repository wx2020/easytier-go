// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/instance"
	"github.com/EasyTier/EasyTier/go/internal/management"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/stats"
)

func TestParseArgsDefaultsAndOutput(t *testing.T) {
	options, err := parseArgs([]string{"--output=json", "node"})
	if err != nil {
		t.Fatal(err)
	}
	if options.rpcPortal != defaultPortal || options.output != outputJSON || strings.Join(options.command, " ") != "node" {
		t.Fatalf("options = %#v", options)
	}
	if _, err := parseArgs([]string{"--output=yaml", "node"}); err == nil {
		t.Fatal("invalid output was accepted")
	}
	options, err = parseArgs([]string{"peer", "--instance-name", "edge"})
	if err != nil || options.instanceName != "edge" || strings.Join(options.command, " ") != "peer" {
		t.Fatalf("global options after command = %#v, %v", options, err)
	}
	if _, err := parseArgs([]string{"--fan-out", "--instance-id", "edge", "peer"}); err == nil {
		t.Fatal("fan-out and instance selector were accepted together")
	}
}

func TestCLIHelpGoldenContract(t *testing.T) {
	help := cliHelp()
	for _, want := range []string{
		"Usage: easytier-cli [OPTIONS] COMMAND",
		"-p, --rpc-portal <address>",
		"-o, --output <format>",
		"(default 127.0.0.1:15888)",
		"node",
		"stats [show|prometheus]",
		"logger [get|set LEVEL]",
		"instance list",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help is missing %q:\n%s", want, help)
		}
	}
}

func TestParseArgsHelpIsSuccessful(t *testing.T) {
	options, err := parseArgs([]string{"--help"})
	if err != nil || !options.showHelp {
		t.Fatalf("help parse = %#v, %v", options, err)
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"--version"}, &stdout, &stderr, nil); status != 0 || stderr.Len() != 0 {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestCLIReturnsStableHelpAndErrorContracts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"--help"}, &stdout, &stderr, nil); status != 0 || stderr.Len() != 0 || !strings.HasPrefix(stdout.String(), "Usage: easytier-cli") {
		t.Fatalf("help status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if status := run(context.Background(), []string{"unknown"}, &stdout, &stderr, nil); status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("unknown command status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if status := run(context.Background(), []string{"--output=yaml", "node"}, &stdout, &stderr, nil); status != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "--output must be table or json") {
		t.Fatalf("invalid output status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestCLIJSONAndTableOutputContracts(t *testing.T) {
	service := management.NewService(management.NodeInfo{ID: "node-1", Name: "edge", Version: "v1"}, stats.New(), nil)
	server, err := rpc.NewServer([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, service.Handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(context.Background()) }()
	client := management.NewClient(server.Addr().String(), localPeerID, remotePeerID)

	var jsonOut, jsonErr bytes.Buffer
	if status := run(context.Background(), []string{"--output=json", "node"}, &jsonOut, &jsonErr, client); status != 0 || jsonErr.Len() != 0 {
		t.Fatalf("JSON node status=%d stdout=%q stderr=%q", status, jsonOut.String(), jsonErr.String())
	}
	if !strings.Contains(jsonOut.String(), `"id": "node-1"`) || !strings.HasSuffix(jsonOut.String(), "\n") {
		t.Fatalf("JSON node output = %q", jsonOut.String())
	}
	var tableOut, tableErr bytes.Buffer
	if status := run(context.Background(), []string{"stats"}, &tableOut, &tableErr, client); status != 0 || tableErr.Len() != 0 || tableOut.String() != "NAME\tVALUE\n" {
		t.Fatalf("stats status=%d stdout=%q stderr=%q", status, tableOut.String(), tableErr.String())
	}
}

func TestCLIExtendedCommandsAndUnsupportedContracts(t *testing.T) {
	service := management.NewServiceWithOptions(management.ServiceOptions{
		NodeInfo: management.NodeInfo{ID: "node-1", Name: "edge", Version: "v1"},
		Counters: stats.New(),
		Config: &config.Config{
			NetworkIdentity: config.NetworkIdentity{NetworkName: "mesh"},
			Peers:           []config.Peer{{URI: "tcp://127.0.0.1:11010"}},
			MappedListeners: []string{"tcp://127.0.0.1:12000"},
			TCPWhitelist:    []string{"80", "8000-8080"},
		},
		UpdateConfig: func(context.Context, config.Config) error { return nil },
	})
	server, err := rpc.NewServer([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, service.Handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(context.Background()) }()
	client := management.NewClient(server.Addr().String(), localPeerID, remotePeerID)

	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--output=json", "mapped-listener", "list"}, "mapped_listeners"},
		{[]string{"--output=json", "whitelist", "show"}, "tcp_ports"},
		{[]string{"connector", "add", "tcp://127.0.0.1:11011"}, "Connector added"},
		{[]string{"connector", "list"}, "tcp://127.0.0.1:11011"},
		{[]string{"whitelist", "set-udp", "53,5000-5002"}, "UDP whitelist updated"},
		{[]string{"proxy"}, "SRC\tDST"},
		{[]string{"--output=json", "proxy"}, "entries"},
	} {
		var stdout, stderr bytes.Buffer
		if status := run(context.Background(), test.args, &stdout, &stderr, client); status != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), test.want) {
			t.Fatalf("args=%v status=%d stdout=%q stderr=%q", test.args, status, stdout.String(), stderr.String())
		}
	}

	for _, args := range [][]string{{"acl", "stats"}} {
		var stdout, stderr bytes.Buffer
		if status := run(context.Background(), args, &stdout, &stderr, client); status != 3 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "not supported") {
			t.Fatalf("unsupported args=%v status=%d stdout=%q stderr=%q", args, status, stdout.String(), stderr.String())
		}
	}
}

func TestCLIManagesLoopbackService(t *testing.T) {
	service := management.NewService(management.NodeInfo{ID: "node-1", Name: "edge", Version: "v1"}, stats.New(), nil)
	server, err := rpc.NewServer([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, service.Handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(context.Background()) }()
	client := management.NewClient(server.Addr().String(), localPeerID, remotePeerID)

	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--output=json", "node"}, `"id": "node-1"`},
		{[]string{"logger", "set", "debug"}, "Log level successfully set to: debug"},
		{[]string{"logger"}, "Current Log Level: debug"},
		{[]string{"instance", "list"}, "INSTANCE ID\tNAME"},
	} {
		var stdout, stderr bytes.Buffer
		if status := run(context.Background(), test.args, &stdout, &stderr, client); status != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), test.want) {
			t.Fatalf("args=%v status=%d stdout=%q stderr=%q", test.args, status, stdout.String(), stderr.String())
		}
	}
}

func TestCLIInstanceSelectorAndFanout(t *testing.T) {
	instances := instance.NewInstanceManager()
	if err := instances.Add(cliTestInstance{id: "inst-a-id", name: "inst-a"}); err != nil {
		t.Fatal(err)
	}
	if err := instances.Add(cliTestInstance{id: "inst-b-id", name: "inst-b"}); err != nil {
		t.Fatal(err)
	}
	service := management.NewService(management.NodeInfo{ID: "node-1", Name: "edge", Version: "v1"}, stats.New(), instances)
	server, err := rpc.NewServer([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, service.Handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(context.Background()) }()
	client := management.NewClient(server.Addr().String(), localPeerID, remotePeerID)

	// Single instance selector via name should succeed
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"--instance-name", "inst-a", "node"}, &stdout, &stderr, client); status != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "node-1") {
		t.Fatalf("instance-name selector status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if status := run(context.Background(), []string{"--instance-id", "inst-b-id", "--output=json", "node"}, &stdout, &stderr, client); status != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "node-1") {
		t.Fatalf("instance-id selector status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if status := run(context.Background(), []string{"--fan-out", "--output=json", "node"}, &stdout, &stderr, client); status != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "instance_id") || !strings.Contains(stdout.String(), "inst-a-id") || !strings.Contains(stdout.String(), "inst-b-id") {
		t.Fatalf("fan-out json status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if status := run(context.Background(), []string{"--fan-out", "node"}, &stdout, &stderr, client); status != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "== inst-a") || !strings.Contains(stdout.String(), "== inst-b") {
		t.Fatalf("fan-out table status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if status := run(context.Background(), []string{"--instance-name", "missing", "node"}, &stdout, &stderr, client); status == 0 || !strings.Contains(stderr.String(), "not found") {
		t.Fatalf("missing instance should fail status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

type cliTestInstance struct {
	id   string
	name string
}

func (i cliTestInstance) ID() string                { return i.id }
func (i cliTestInstance) Name() string              { return i.name }
func (cliTestInstance) Start(context.Context) error { return nil }
func (cliTestInstance) Close() error                { return nil }

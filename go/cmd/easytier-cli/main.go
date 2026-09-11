// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// EasyTier Go CLI is the replacement client for the Rust easytier-cli binary.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/forward"
	"github.com/EasyTier/EasyTier/go/internal/management"
)

var version = "0.0.0-dev"

const (
	defaultPortal = "127.0.0.1:15888"
	localPeerID   = 1
	remotePeerID  = 2
)

type outputFormat string

const (
	outputTable outputFormat = "table"
	outputJSON  outputFormat = "json"
)

type options struct {
	showHelp     bool
	showVersion  bool
	rpcPortal    string
	output       outputFormat
	verbose      bool
	noTrunc      bool
	instanceID   string
	instanceName string
	fanOut       bool
	command      []string
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, nil))
}

func parseArgs(args []string) (options, error) {
	var options options
	if hasHelp(args) {
		options.showHelp = true
		return options, nil
	}
	args = moveGlobalFlagsFirst(args)
	flags := flag.NewFlagSet("easytier-cli", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {
		fmt.Fprintln(io.Discard, "Usage: easytier-cli [OPTIONS] COMMAND")
	}
	flags.BoolVar(&options.showVersion, "version", false, "print version and exit")
	flags.StringVar(&options.rpcPortal, "rpc-portal", defaultPortal, "easytier-core RPC portal address")
	flags.StringVar(&options.rpcPortal, "p", defaultPortal, "easytier-core RPC portal address")
	var output string
	flags.StringVar(&output, "output", string(outputTable), "output format: table or json")
	flags.StringVar(&output, "o", string(outputTable), "output format: table or json")
	flags.BoolVar(&options.verbose, "verbose", false, "include verbose output")
	flags.BoolVar(&options.verbose, "v", false, "include verbose output")
	flags.BoolVar(&options.noTrunc, "no-trunc", false, "disable column truncation")
	flags.StringVar(&options.instanceID, "instance-id", "", "select one instance by ID")
	flags.StringVar(&options.instanceID, "i", "", "select one instance by ID")
	flags.StringVar(&options.instanceName, "instance-name", "", "select one instance by name")
	flags.StringVar(&options.instanceName, "n", "", "select one instance by name")
	flags.BoolVar(&options.fanOut, "fan-out", false, "run the command against all instances")
	flags.BoolVar(&options.fanOut, "fanout", false, "run the command against all instances")
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	if options.rpcPortal == "" {
		return options, errors.New("--rpc-portal must not be empty")
	}
	options.output = outputFormat(output)
	if options.output != outputTable && options.output != outputJSON {
		return options, fmt.Errorf("--output must be table or json, got %q", output)
	}
	if options.instanceID != "" && options.instanceName != "" {
		return options, errors.New("--instance-id and --instance-name are mutually exclusive")
	}
	if options.fanOut && (options.instanceID != "" || options.instanceName != "") {
		return options, errors.New("--fan-out cannot be combined with an instance selector")
	}
	options.command = flags.Args()
	return options, nil
}

// The Rust CLI accepts global options on either side of a subcommand. The Go
// flag package stops at the first positional argument, so normalize only the
// known global options before handing the result to it.
func moveGlobalFlagsFirst(args []string) []string {
	var globals, command []string
	withValue := func(arg string) bool {
		for _, name := range []string{"--rpc-portal", "-p", "--output", "-o", "--instance-id", "-i", "--instance-name", "-n"} {
			if arg == name {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			command = append(command, args[i:]...)
			break
		}
		isGlobal := withValue(arg)
		if !isGlobal {
			for _, name := range []string{"--version", "--verbose", "-v", "--no-trunc", "--fan-out", "--fanout"} {
				if arg == name {
					isGlobal = true
					break
				}
			}
		}
		if !isGlobal {
			for _, name := range []string{"--rpc-portal=", "--output=", "--instance-id=", "--instance-name="} {
				if strings.HasPrefix(arg, name) {
					isGlobal = true
					break
				}
			}
		}
		if !isGlobal {
			command = append(command, arg)
			continue
		}
		globals = append(globals, arg)
		if withValue(arg) && i+1 < len(args) {
			i++
			globals = append(globals, args[i])
		}
	}
	return append(globals, command...)
}

// run accepts an optional client for tests. Production passes nil to create a
// client for the configured standalone RPC portal.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, client *management.Client) int {
	options, err := parseArgs(args)
	if err != nil {
		return commandError(stderr, 2, err)
	}
	if options.showVersion {
		fmt.Fprintf(stdout, "easytier-cli %s (go rewrite)\n", version)
		return 0
	}
	if options.showHelp {
		_, _ = io.WriteString(stdout, cliHelp())
		return 0
	}
	if client == nil {
		client = management.NewClient(options.rpcPortal, localPeerID, remotePeerID)
	}
	if options.instanceID != "" || options.instanceName != "" || options.fanOut {
		targets, resolveErr := resolveTargets(ctx, client, options)
		if resolveErr != nil {
			return commandError(stderr, 1, resolveErr)
		}
		if options.fanOut {
			if len(targets) == 0 {
				return commandError(stderr, 1, fmt.Errorf("no instances found for --fan-out"))
			}
			if err := runFanout(ctx, options, client, targets, stdout); err != nil {
				status := 1
				if errors.Is(err, management.ErrUnsupported) {
					status = 3
				}
				return commandError(stderr, status, err)
			}
			return 0
		}
		// Single instance selector: validate exists, then run single command
		if len(targets) == 0 {
			return commandError(stderr, 1, fmt.Errorf("instance not found"))
		}
		// Fall through to single execution (validated)
	}
	err = executeCommand(ctx, options, client, stdout)
	if err != nil {
		status := 1
		if errors.Is(err, management.ErrUnsupported) {
			status = 3
		}
		return commandError(stderr, status, err)
	}
	return 0
}

func resolveTargets(ctx context.Context, client *management.Client, options options) ([]management.InstanceInfo, error) {
	if options.instanceID != "" {
		list, err := client.InstanceList(ctx)
		if err != nil {
			return nil, err
		}
		for _, inst := range list {
			if inst.ID == options.instanceID {
				return []management.InstanceInfo{inst}, nil
			}
		}
		return nil, fmt.Errorf("instance %q not found", options.instanceID)
	}
	if options.instanceName != "" {
		list, err := client.InstanceList(ctx)
		if err != nil {
			return nil, err
		}
		for _, inst := range list {
			if inst.Name == options.instanceName {
				return []management.InstanceInfo{inst}, nil
			}
		}
		return nil, fmt.Errorf("instance %q not found", options.instanceName)
	}
	if options.fanOut {
		list, err := client.InstanceList(ctx)
		if err != nil {
			return nil, err
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("no instances found for --fan-out")
		}
		return list, nil
	}
	return nil, nil
}

func fanoutLabel(inst management.InstanceInfo) string {
	switch {
	case inst.Name != "" && inst.ID != "":
		return fmt.Sprintf("%s (%s)", inst.Name, inst.ID)
	case inst.Name != "":
		return inst.Name
	case inst.ID != "":
		return inst.ID
	default:
		return "selected instance"
	}
}

func runFanout(ctx context.Context, options options, client *management.Client, targets []management.InstanceInfo, stdout io.Writer) error {
	if len(targets) == 0 {
		return fmt.Errorf("no instances found for --fan-out")
	}
	if options.output == outputJSON {
		// Collect per-instance JSON results
		wrapped := make([]map[string]any, 0, len(targets))
		for _, target := range targets {
			var buf strings.Builder
			// Use a buffer to capture single execution as JSON
			optsCopy := options
			// Ensure per-instance execution doesn't recursively fan-out
			optsCopy.fanOut = false
			optsCopy.instanceID = ""
			optsCopy.instanceName = ""
			if err := executeCommand(ctx, optsCopy, client, &buf); err != nil {
				return fmt.Errorf("instance %s: %w", fanoutLabel(target), err)
			}
			var result any
			if err := json.Unmarshal([]byte(buf.String()), &result); err != nil {
				// If not JSON (e.g., empty), treat as string
				result = strings.TrimSpace(buf.String())
			}
			wrapped = append(wrapped, map[string]any{
				"instance_id":   target.ID,
				"instance_name": target.Name,
				"result":        result,
			})
		}
		return writeJSON(stdout, wrapped)
	}
	// Table mode: print header per instance
	for i, target := range targets {
		if i > 0 {
			if _, err := fmt.Fprintln(stdout, ""); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(stdout, "== %s ==\n", fanoutLabel(target)); err != nil {
			return err
		}
		optsCopy := options
		optsCopy.fanOut = false
		optsCopy.instanceID = ""
		optsCopy.instanceName = ""
		if err := executeCommand(ctx, optsCopy, client, stdout); err != nil {
			return fmt.Errorf("instance %s: %w", fanoutLabel(target), err)
		}
	}
	return nil
}

func executeCommand(ctx context.Context, options options, client *management.Client, stdout io.Writer) error {
	switch {
	case len(options.command) == 1 && options.command[0] == "node":
		return renderNode(ctx, client, options.output, stdout)
	case len(options.command) == 1 && options.command[0] == "stats":
		return renderStats(ctx, client, options.output, stdout)
	case len(options.command) == 2 && options.command[0] == "stats" && options.command[1] == "prometheus":
		return renderStatsPrometheus(ctx, client, options.output, stdout)
	case len(options.command) == 2 && options.command[0] == "stats" && options.command[1] == "show":
		return renderStats(ctx, client, options.output, stdout)
	case len(options.command) == 1 && options.command[0] == "logger":
		return renderLoggerGet(ctx, client, options.output, stdout)
	case len(options.command) == 2 && options.command[0] == "logger" && options.command[1] == "get":
		return renderLoggerGet(ctx, client, options.output, stdout)
	case len(options.command) == 3 && options.command[0] == "logger" && options.command[1] == "set":
		return renderLoggerSet(ctx, client, options.output, management.LoggerLevel(strings.ToLower(options.command[2])), stdout)
	case len(options.command) == 2 && options.command[0] == "instance" && options.command[1] == "list":
		return renderInstanceList(ctx, client, options.output, stdout)
	case len(options.command) == 2 && options.command[0] == "instance" && options.command[1] == "status":
		return renderInstanceStatus(ctx, client, options.output, stdout)
	case len(options.command) == 3 && options.command[0] == "instance" && options.command[1] == "start":
		return renderInstanceStart(ctx, client, options.output, options.command[2], stdout)
	case len(options.command) == 3 && options.command[0] == "instance" && options.command[1] == "stop":
		return renderInstanceStop(ctx, client, options.output, options.command[2], stdout)
	case len(options.command) == 2 && options.command[0] == "stats" && options.command[1] == "snapshot":
		return renderStatsSnapshot(ctx, client, options.output, stdout)
	case len(options.command) == 2 && options.command[0] == "config" && options.command[1] == "get":
		return renderConfigGet(ctx, client, options.output, stdout)
	case len(options.command) == 3 && options.command[0] == "config" && options.command[1] == "set":
		return renderConfigSet(ctx, client, options.output, options.command[2], stdout)
	case (len(options.command) == 1 && options.command[0] == "peer") || (len(options.command) == 2 && options.command[0] == "peer" && options.command[1] == "list"):
		return renderPeerList(ctx, client, options.output, stdout)
	case len(options.command) == 2 && options.command[0] == "peer" && options.command[1] != "list":
		return unsupportedCommand("peer " + options.command[1])
	case (len(options.command) == 1 && options.command[0] == "route") || (len(options.command) == 2 && options.command[0] == "route" && options.command[1] == "list"):
		return renderRouteList(ctx, client, options.output, stdout)
	case len(options.command) == 2 && options.command[0] == "route" && options.command[1] == "dump":
		return unsupportedCommand("route dump")
	case (len(options.command) == 1 && options.command[0] == "connector") || (len(options.command) == 2 && options.command[0] == "connector" && options.command[1] == "list"):
		return renderConnectorList(ctx, client, options.output, stdout)
	case len(options.command) == 3 && options.command[0] == "connector" && options.command[1] == "add":
		return renderConnectorModify(ctx, client, options.output, options.command[2], true, stdout)
	case len(options.command) == 3 && options.command[0] == "connector" && options.command[1] == "remove":
		return renderConnectorModify(ctx, client, options.output, options.command[2], false, stdout)
	case (len(options.command) == 1 && options.command[0] == "mapped-listener") || (len(options.command) == 2 && options.command[0] == "mapped-listener" && options.command[1] == "list"):
		return renderMappedListenerList(ctx, client, options.output, stdout)
	case len(options.command) == 3 && options.command[0] == "mapped-listener" && options.command[1] == "add":
		return renderMappedListenerModify(ctx, client, options.output, options.command[2], true, stdout)
	case len(options.command) == 3 && options.command[0] == "mapped-listener" && options.command[1] == "remove":
		return renderMappedListenerModify(ctx, client, options.output, options.command[2], false, stdout)
	case len(options.command) == 1 && options.command[0] == "proxy":
		return renderProxy(ctx, client, options.output, stdout)
	case len(options.command) == 1 && options.command[0] == "vpn-portal":
		return renderVPNPortal(ctx, client, options.output, stdout)
	case len(options.command) == 1 && options.command[0] == "peer-center":
		return renderPeerCenter(ctx, client, options.output, stdout)
	case len(options.command) == 1 && options.command[0] == "acl":
		return renderACLStats(ctx, client, options.output, stdout)
	case len(options.command) == 2 && options.command[0] == "acl" && options.command[1] == "stats":
		return renderACLStats(ctx, client, options.output, stdout)
	case len(options.command) == 1 && options.command[0] == "whitelist":
		return renderWhitelistShow(ctx, client, options.output, stdout)
	case len(options.command) == 2 && options.command[0] == "whitelist" && options.command[1] == "show":
		return renderWhitelistShow(ctx, client, options.output, stdout)
	case len(options.command) == 3 && options.command[0] == "whitelist" && options.command[1] == "set-tcp":
		return renderWhitelistSet(ctx, client, options.output, options.command[2], true, stdout)
	case len(options.command) == 3 && options.command[0] == "whitelist" && options.command[1] == "set-udp":
		return renderWhitelistSet(ctx, client, options.output, options.command[2], false, stdout)
	case len(options.command) == 2 && options.command[0] == "whitelist" && options.command[1] == "clear-tcp":
		return renderWhitelistSet(ctx, client, options.output, "", true, stdout)
	case len(options.command) == 2 && options.command[0] == "whitelist" && options.command[1] == "clear-udp":
		return renderWhitelistSet(ctx, client, options.output, "", false, stdout)
	case (len(options.command) == 1 && options.command[0] == "port-forward") || (len(options.command) == 2 && options.command[0] == "port-forward" && options.command[1] == "list"):
		return renderForwardList(ctx, client, options.output, stdout)
	case len(options.command) == 5 && options.command[0] == "port-forward" && options.command[1] == "add":
		if options.command[2] != "tcp" {
			return unsupportedCommand("port-forward " + options.command[2])
		}
		return renderForwardAdd(ctx, client, options.output, forward.Rule{Bind: options.command[3], Destination: options.command[4]}, stdout)
	case len(options.command) == 4 && options.command[0] == "port-forward" && options.command[1] == "remove":
		if options.command[2] != "tcp" {
			return unsupportedCommand("port-forward " + options.command[2])
		}
		return renderForwardRemove(ctx, client, options.output, forward.Rule{Bind: options.command[3]}, stdout)
	case len(options.command) == 5 && options.command[0] == "port-forward" && options.command[1] == "remove":
		if options.command[2] != "tcp" {
			return unsupportedCommand("port-forward " + options.command[2])
		}
		return renderForwardRemove(ctx, client, options.output, forward.Rule{Bind: options.command[3], Destination: options.command[4]}, stdout)
	case len(options.command) == 2 && options.command[0] == "credential" && options.command[1] == "list":
		return renderCredentialList(ctx, client, options.output, stdout)
	case len(options.command) >= 3 && len(options.command) <= 4 && options.command[0] == "credential" && options.command[1] == "generate":
		return renderCredentialGenerate(ctx, client, options.output, options.command[2:], stdout)
	case len(options.command) == 3 && options.command[0] == "credential" && options.command[1] == "revoke":
		return renderCredentialRevoke(ctx, client, options.output, options.command[2], stdout)
	case len(options.command) == 2 && options.command[0] == "dns" && options.command[1] == "list":
		return renderDNSList(ctx, client, options.output, stdout)
	case len(options.command) == 2 && options.command[0] == "dns" && options.command[1] == "status":
		return renderDNSStatus(ctx, client, options.output, stdout)
	case len(options.command) >= 4 && options.command[0] == "dns" && options.command[1] == "set":
		return renderDNSSet(ctx, client, options.output, options.command[2], options.command[3:], stdout)
	case len(options.command) == 3 && options.command[0] == "dns" && options.command[1] == "delete":
		return renderDNSDelete(ctx, client, options.output, options.command[2], stdout)
	case len(options.command) == 3 && options.command[0] == "web" && options.command[1] == "session" && options.command[2] == "list":
		return renderWebSessions(ctx, client, options.output, stdout)
	default:
		return errors.New("unknown command; use --help for supported commands")
	}
}

func renderNode(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	info, err := client.NodeInfo(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, info)
	}
	_, err = fmt.Fprintf(stdout, "FIELD\tVALUE\nID\t%s\nNAME\t%s\nVERSION\t%s\n", info.ID, info.Name, info.Version)
	return err
}

func renderStats(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	items, err := client.StatsSnapshot(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Metrics []management.StatsInfo `json:"metrics"`
		}{items})
	}
	if _, err := fmt.Fprintln(stdout, "NAME\tVALUE"); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(stdout, "%s\t%d\n", item.Name, item.Value); err != nil {
			return err
		}
	}
	return nil
}

func renderStatsPrometheus(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	text, err := client.StatsPrometheus(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, map[string]string{"prometheus_text": text})
	}
	_, err = fmt.Fprint(stdout, text)
	return err
}

func renderLoggerGet(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	level, err := client.LoggerGet(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, map[string]string{"level": string(level)})
	}
	_, err = fmt.Fprintf(stdout, "Current Log Level: %s\n", level)
	return err
}

func renderLoggerSet(ctx context.Context, client *management.Client, output outputFormat, level management.LoggerLevel, stdout io.Writer) error {
	level, err := client.LoggerSet(ctx, level)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, map[string]string{"level": string(level)})
	}
	_, err = fmt.Fprintf(stdout, "Log level successfully set to: %s\n", level)
	return err
}

func renderInstanceList(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	instances, err := client.InstanceList(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, instances)
	}
	if _, err := fmt.Fprintln(stdout, "INSTANCE ID\tNAME"); err != nil {
		return err
	}
	for _, item := range instances {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\n", item.ID, item.Name); err != nil {
			return err
		}
	}
	return nil
}

func renderInstanceStatus(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	items, err := client.InstanceStatusList(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Instances []management.InstanceStatus `json:"instances"`
		}{items})
	}
	if _, err := fmt.Fprintln(stdout, "INSTANCE ID\tNAME\tSTATE\tRUNNING"); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\t%t\n", item.ID, item.Name, item.State, item.Running); err != nil {
			return err
		}
	}
	return nil
}

func renderInstanceStart(ctx context.Context, client *management.Client, output outputFormat, name string, stdout io.Writer) error {
	status, err := client.InstanceStart(ctx, name)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, status)
	}
	_, err = fmt.Fprintf(stdout, "Instance started: %s (%s)\n", status.Name, status.State)
	return err
}

func renderInstanceStop(ctx context.Context, client *management.Client, output outputFormat, name string, stdout io.Writer) error {
	if err := client.InstanceStop(ctx, name); err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, map[string]bool{"stopped": true})
	}
	_, err := fmt.Fprintf(stdout, "Instance stopped: %s\n", name)
	return err
}

func renderStatsSnapshot(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	items, err := client.StatsSnapshot(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Metrics []management.StatsInfo `json:"metrics"`
		}{items})
	}
	if _, err := fmt.Fprintln(stdout, "NAME\tVALUE"); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(stdout, "%s\t%d\n", item.Name, item.Value); err != nil {
			return err
		}
	}
	return nil
}

func renderConfigGet(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	value, err := client.ConfigGet(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, value)
	}
	_, err = fmt.Fprint(stdout, value.TOML)
	return err
}

func renderConfigSet(ctx context.Context, client *management.Client, output outputFormat, path string, stdout io.Writer) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	value, err := client.ConfigSetTOML(ctx, string(data))
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, value)
	}
	_, err = fmt.Fprintf(stdout, "Configuration updated (read_only=%t)\n", value.ReadOnly)
	return err
}

func renderPeerList(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	items, err := client.PeerList(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Peers []management.PeerInfo `json:"peers"`
		}{items})
	}
	if _, err := fmt.Fprintln(stdout, "PEER ID\tCONNECTIONS"); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(stdout, "%d\t%d\n", item.ID, item.PeerCount); err != nil {
			return err
		}
	}
	return nil
}

func renderRouteList(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	items, err := client.RouteList(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Routes any `json:"routes"`
		}{items})
	}
	if _, err := fmt.Fprintln(stdout, "DESTINATION\tNEXT HOP\tCOST"); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(stdout, "%d\t%d\t%d\n", item.Destination, item.NextHop, item.Cost); err != nil {
			return err
		}
	}
	return nil
}

func renderConnectorList(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	items, err := client.ConnectorList(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Connectors []management.ConnectorInfo `json:"connectors"`
		}{items})
	}
	if _, err := fmt.Fprintln(stdout, "URL\tSTATUS"); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\n", item.URL, item.Status); err != nil {
			return err
		}
	}
	return nil
}

func renderConnectorModify(ctx context.Context, client *management.Client, output outputFormat, rawURL string, add bool, stdout io.Writer) error {
	if _, err := config.ParseEndpoint(rawURL); err != nil {
		return fmt.Errorf("invalid connector URL: %w", err)
	}
	value, err := updateConfig(ctx, client, func(cfg *config.Config) error {
		if add {
			for _, item := range cfg.Peers {
				if item.URI == rawURL {
					return fmt.Errorf("connector already exists: %s", rawURL)
				}
			}
			cfg.Peers = append(cfg.Peers, config.Peer{URI: rawURL})
			return nil
		}
		for i, item := range cfg.Peers {
			if item.URI == rawURL {
				cfg.Peers = append(cfg.Peers[:i], cfg.Peers[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("connector not found: %s", rawURL)
	})
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, value)
	}
	action := "removed"
	if add {
		action = "added"
	}
	_, err = fmt.Fprintf(stdout, "Connector %s: %s\n", action, rawURL)
	return err
}

func renderMappedListenerList(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	items, err := client.MappedListenerList(ctx)
	if err != nil {
		return err
	}
	result := struct {
		MappedListeners []management.MappedListenerStatus `json:"mapped_listeners"`
	}{items}
	if output == outputJSON {
		return writeJSON(stdout, result)
	}
	if _, err := fmt.Fprintln(stdout, "URL\tSTATE\tERROR"); err != nil {
		return err
	}
	for _, listener := range items {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\n", listener.URL, listener.State, listener.Error); err != nil {
			return err
		}
	}
	return nil
}

func renderMappedListenerModify(ctx context.Context, client *management.Client, output outputFormat, rawURL string, add bool, stdout io.Writer) error {
	if err := config.ValidateMappedListenerURL(rawURL); err != nil {
		return fmt.Errorf("mapped listener URL is invalid: %w", err)
	}
	if add {
		if err := client.MappedListenerAdd(ctx, rawURL); err != nil {
			return err
		}
		if output == outputJSON {
			return writeJSON(stdout, map[string]string{"url": rawURL, "added": "true"})
		}
		_, err := fmt.Fprintf(stdout, "Mapped listener added: %s\n", rawURL)
		return err
	}
	if err := client.MappedListenerRemove(ctx, rawURL); err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, map[string]bool{"removed": true})
	}
	_, err := fmt.Fprintf(stdout, "Mapped listener removed: %s\n", rawURL)
	return err
}

func renderACLStats(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	value, err := client.ACLStats(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, value)
	}
	if _, err := fmt.Fprintf(stdout, "EVALUATIONS\t%d\nDEFAULT ALLOW\t%d\nDEFAULT DROP\t%d\nRULE\tACTION\tMATCHES\n", value.Evaluations, value.DefaultAllows, value.DefaultDrops); err != nil {
		return err
	}
	for _, rule := range value.Rules {
		if _, err := fmt.Fprintf(stdout, "%s\t%d\t%d\n", rule.Name, rule.Action, rule.Matches); err != nil {
			return err
		}
	}
	return nil
}

func renderWhitelistShow(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	value, err := client.ConfigGet(ctx)
	if err != nil {
		return err
	}
	result := struct {
		TCP []string `json:"tcp_ports"`
		UDP []string `json:"udp_ports"`
	}{append([]string(nil), value.Config.TCPWhitelist...), append([]string(nil), value.Config.UDPWhitelist...)}
	if output == outputJSON {
		return writeJSON(stdout, result)
	}
	_, err = fmt.Fprintf(stdout, "TCP Whitelist: %s\nUDP Whitelist: %s\n", whitelistText(result.TCP), whitelistText(result.UDP))
	return err
}

func renderWhitelistSet(ctx context.Context, client *management.Client, output outputFormat, rawPorts string, tcp bool, stdout io.Writer) error {
	ports, err := parsePortList(rawPorts)
	if err != nil {
		return err
	}
	value, err := updateConfig(ctx, client, func(cfg *config.Config) error {
		if tcp {
			cfg.TCPWhitelist = ports
		} else {
			cfg.UDPWhitelist = ports
		}
		return nil
	})
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, value)
	}
	protocol := "UDP"
	if tcp {
		protocol = "TCP"
	}
	action := "updated"
	if len(ports) == 0 {
		action = "cleared"
	}
	_, err = fmt.Fprintf(stdout, "%s whitelist %s\n", protocol, action)
	return err
}

func updateConfig(ctx context.Context, client *management.Client, update func(*config.Config) error) (management.ConfigInfo, error) {
	value, err := client.ConfigGet(ctx)
	if err != nil {
		return management.ConfigInfo{}, err
	}
	if err := update(&value.Config); err != nil {
		return management.ConfigInfo{}, err
	}
	return client.ConfigSet(ctx, value.Config)
}

func parsePortList(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return []string{}, nil
	}
	ports := make([]string, 0)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		parts := strings.Split(item, "-")
		if len(parts) > 2 || item == "" {
			return nil, fmt.Errorf("invalid port specification %q", item)
		}
		start, err := parsePort(parts[0])
		if err != nil {
			return nil, err
		}
		if len(parts) == 1 {
			ports = append(ports, strconv.Itoa(start))
			continue
		}
		end, err := parsePort(parts[1])
		if err != nil {
			return nil, err
		}
		if start > end {
			return nil, fmt.Errorf("invalid port range %q: start is greater than end", item)
		}
		ports = append(ports, fmt.Sprintf("%d-%d", start, end))
	}
	return ports, nil
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	return port, nil
}

func whitelistText(values []string) string {
	if len(values) == 0 {
		return "None"
	}
	return strings.Join(values, ", ")
}

func renderForwardList(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	items, err := client.ForwardStatusList(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Forwards []management.ForwardStatus `json:"forwards"`
		}{items})
	}
	if _, err := fmt.Fprintln(stdout, "BIND\tDESTINATION\tSTATE\tACTIVE\tACCEPTED\tFAILED"); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\t%d\t%d\t%d\n", item.Bind, item.Destination, item.State, item.ActiveConnections, item.Accepted, item.Failed); err != nil {
			return err
		}
	}
	return nil
}

func renderForwardAdd(ctx context.Context, client *management.Client, output outputFormat, rule forward.Rule, stdout io.Writer) error {
	item, err := client.ForwardAdd(ctx, rule)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Rule forward.Rule `json:"rule"`
		}{item})
	}
	_, err = fmt.Fprintf(stdout, "Forwarding rule added: %s -> %s\n", item.Bind, item.Destination)
	return err
}

func renderForwardRemove(ctx context.Context, client *management.Client, output outputFormat, rule forward.Rule, stdout io.Writer) error {
	if rule.Destination == "" {
		return unsupportedCommand("port-forward remove without destination")
	}
	if err := client.ForwardRemove(ctx, rule); err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, map[string]bool{"removed": true})
	}
	_, err := fmt.Fprintf(stdout, "Forwarding rule removed: %s -> %s\n", rule.Bind, rule.Destination)
	return err
}

func renderProxy(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	info, err := client.Proxy(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, info)
	}
	if _, err := fmt.Fprintln(stdout, "SRC\tDST\tSTATE\tTRANSPORT"); err != nil {
		return err
	}
	for _, entry := range info.Entries {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", entry.Source, entry.Destination, entry.State, entry.TransportType); err != nil {
			return err
		}
	}
	return nil
}

func renderVPNPortal(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	info, err := client.VPNPortal(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, info)
	}
	if _, err := fmt.Fprintf(stdout, "VPN Type: %s\nClient Config:\n%s\nConnected Clients: %s\n", info.VPNType, info.ClientConfig, strings.Join(info.ConnectedClients, ", ")); err != nil {
		return err
	}
	return nil
}

func renderPeerCenter(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	info, err := client.PeerCenter(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, info)
	}
	if _, err := fmt.Fprintln(stdout, "NODE\tDIRECT PEERS"); err != nil {
		return err
	}
	for node, group := range info.GlobalPeerMap {
		peers := make([]string, 0, len(group.DirectPeers))
		for peer, data := range group.DirectPeers {
			peers = append(peers, fmt.Sprintf("%s(%dms)", peer, data.LatencyMs))
		}
		sort.Strings(peers)
		if _, err := fmt.Fprintf(stdout, "%s\t%s\n", node, strings.Join(peers, ",")); err != nil {
			return err
		}
	}
	return nil
}

func renderCredentialList(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	items, err := client.CredentialList(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Credentials []management.CredentialInfo `json:"credentials"`
		}{items})
	}
	if _, err := fmt.Fprintln(stdout, "ID\tEXPIRES\tREUSABLE"); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%t\n", item.ID, item.ExpiresAt, item.Reusable); err != nil {
			return err
		}
	}
	return nil
}

func renderCredentialGenerate(ctx context.Context, client *management.Client, output outputFormat, args []string, stdout io.Writer) error {
	ttl, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil || ttl <= 0 {
		return errors.New("credential generate requires a positive TTL in seconds")
	}
	request := management.CredentialGenerateRequest{TTLSeconds: ttl}
	if len(args) == 2 {
		request.ID = args[1]
	}
	value, err := client.CredentialGenerate(ctx, request)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, value)
	}
	_, err = fmt.Fprintf(stdout, "Credential generated: %s\nSECRET\t%s\n", value.CredentialID, value.CredentialSecret)
	return err
}

func renderCredentialRevoke(ctx context.Context, client *management.Client, output outputFormat, id string, stdout io.Writer) error {
	if err := client.CredentialRevoke(ctx, id); err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, map[string]bool{"success": true})
	}
	_, err := fmt.Fprintf(stdout, "Credential revoked: %s\n", id)
	return err
}

func renderDNSList(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	zone, records, err := client.DNSList(ctx)
	if err != nil {
		return err
	}
	value := struct {
		Zone    string                     `json:"zone"`
		Records []management.DNSRecordInfo `json:"records"`
		Status  management.DNSStatus       `json:"status"`
	}{Zone: zone, Records: records}
	value.Status, err = client.DNSStatus(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, value)
	}
	if _, err := fmt.Fprintf(stdout, "ZONE\t%s\nNAME\tTTL\tADDRESSES\n", zone); err != nil {
		return err
	}
	for _, item := range records {
		if _, err := fmt.Fprintf(stdout, "%s\t%d\t%s\n", item.Name, item.TTL, strings.Join(item.Addresses, ",")); err != nil {
			return err
		}
	}
	return nil
}

func renderDNSStatus(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	status, err := client.DNSStatus(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, status)
	}
	if _, err := fmt.Fprintf(stdout, "ADDRESS\t%s\nZONE\t%s\nTTL\t%d\nSERVING\t%t\nUPSTREAM\tSTATE\tQUERIES\tSUCCESSES\tFAILURES\n", status.Address, status.Zone, status.TTL, status.Serving); err != nil {
		return err
	}
	for _, upstream := range status.Upstreams {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%d\t%d\t%d\n", upstream.Address, upstream.State, upstream.Queries, upstream.Successes, upstream.Failures); err != nil {
			return err
		}
	}
	return nil
}

func renderDNSSet(ctx context.Context, client *management.Client, output outputFormat, name string, addresses []string, stdout io.Writer) error {
	item, err := client.DNSSet(ctx, name, addresses)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Record management.DNSRecordInfo `json:"record"`
		}{item})
	}
	_, err = fmt.Fprintf(stdout, "DNS record set: %s\t%s\n", item.Name, strings.Join(item.Addresses, ","))
	return err
}

func renderDNSDelete(ctx context.Context, client *management.Client, output outputFormat, name string, stdout io.Writer) error {
	if err := client.DNSDelete(ctx, name); err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, map[string]bool{"removed": true})
	}
	_, err := fmt.Fprintf(stdout, "DNS record removed: %s\n", name)
	return err
}

func renderWebSessions(ctx context.Context, client *management.Client, output outputFormat, stdout io.Writer) error {
	items, err := client.WebSessions(ctx)
	if err != nil {
		return err
	}
	if output == outputJSON {
		return writeJSON(stdout, struct {
			Sessions any `json:"sessions"`
		}{items})
	}
	if _, err := fmt.Fprintln(stdout, "MACHINE ID\tNAME\tCONNECTED\tLAST SEEN"); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%t\t%s\n", item.MachineID, item.Name, item.Connected, item.LastSeen.UTC().Format("2006-01-02T15:04:05Z07:00")); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(writer io.Writer, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(writer, string(encoded))
	return err
}

func commandError(stderr io.Writer, status int, err error) int {
	fmt.Fprintf(stderr, "easytier-cli: %v\n", err)
	return status
}

func unsupportedCommand(name string) error {
	return fmt.Errorf("%w: %s is not supported by the Go management API", management.ErrUnsupported, name)
}

func hasHelp(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func cliHelp() string {
	return "Usage: easytier-cli [OPTIONS] COMMAND\n\nOptions:\n  -p, --rpc-portal <address>  easytier-core RPC portal address (default 127.0.0.1:15888)\n  -o, --output <format>       output format: table or json (default table)\n  -i, --instance-id <id>      select one instance by ID\n  -n, --instance-name <name>  select one instance by name\n      --fan-out               run the command against all instances\n  -v, --verbose               include verbose output\n      --no-trunc              disable column truncation\n      --version               print version and exit\n\nCommands:\n  node\n  peer [list|ipv6|list-foreign|list-global-foreign]\n  route [list|dump]\n  connector [list|add URL|remove URL]\n  mapped-listener [list|add URL|remove URL]\n  proxy\n  vpn-portal\n  peer-center\n  acl [stats]\n  port-forward [list|add tcp BIND DESTINATION|remove tcp BIND [DESTINATION]]\n  whitelist [show|set-tcp PORTS|set-udp PORTS|clear-tcp|clear-udp]\n  stats [show|prometheus]\n  logger [get|set LEVEL]\n  instance list|status|start NAME|stop NAME\n  config get|set FILE\n  credential list|generate TTL_SECONDS [ID]|revoke ID\n  dns list|set NAME ADDRESS...|delete NAME\n  web session list\n\nExit status:\n  0 success, 1 runtime error, 2 usage error, 3 unsupported management capability\n"
}

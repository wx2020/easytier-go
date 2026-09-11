// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

type boolFlag struct {
	set func(bool)
}

func (f boolFlag) String() string { return "false" }

func (f boolFlag) Set(value string) error {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("invalid boolean %q", value)
	}
	f.set(parsed)
	return nil
}

func (f boolFlag) IsBoolFlag() bool { return true }

func newCoreFlagSet(options *options, output io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet("easytier-core", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.Usage = func() {
		fmt.Fprintln(output, "Usage: easytier-core [OPTIONS]")
		flags.PrintDefaults()
	}

	flags.BoolVar(&options.showVersion, "version", false, "print version and exit")
	registerList(flags, &options.listeners, "l", "listener URL (repeatable or comma-separated)")
	registerList(flags, &options.listeners, "listeners", "listener URL (repeatable or comma-separated)")
	// Keep the original flag spelling working while --listeners is adopted.
	registerList(flags, &options.listeners, "listen", "listener URL (repeatable or comma-separated)")
	registerList(flags, &options.peers, "p", "peer URL (repeatable or comma-separated)")
	registerList(flags, &options.peers, "peers", "peer URL (repeatable or comma-separated)")
	registerString(flags, &options.ipv4, "i", "IPv4 address or CIDR")
	registerString(flags, &options.ipv4, "ipv4", "IPv4 address or CIDR")
	registerBool(flags, &options.dhcp, options.boolSet, "dhcp", "d", "enable DHCP")
	registerBool(flags, &options.dhcp, options.boolSet, "dhcp", "dhcp", "enable DHCP")
	registerString(flags, &options.networkName, "network-name", "network name")
	registerString(flags, &options.networkSecret, "network-secret", "network secret")
	registerList(flags, &options.configFiles, "f", "TOML configuration file (repeatable, comma-separated, or - for stdin)")
	registerList(flags, &options.configFiles, "c", "TOML configuration file (alias for --config-file)")
	registerList(flags, &options.configFiles, "config-file", "TOML configuration file (repeatable, comma-separated, or - for stdin)")
	registerString(flags, &options.configDir, "config-dir", "directory containing TOML configuration files")
	flags.BoolVar(&options.checkConfig, "check-config", false, "validate the TOML configuration and exit")
	flags.BoolVar(&options.disableEnvironmentParsing, "disable-env-parsing", false, "disable ${VAR} expansion in TOML configuration")
	registerString(flags, &options.rpcPortal, "r", "RPC portal address")
	registerString(flags, &options.rpcPortal, "rpc-portal", "RPC portal address")
	registerList(flags, &options.rpcPortalWhitelist, "rpc-portal-whitelist", "RPC portal whitelist CIDR (repeatable or comma-separated)")
	// --config-server / ET_CONFIG_SERVER wires to webclient.Client like Rust core.rs:93.
	// When set, the daemon starts a reconnecting config-server session in the background.
	registerString(flags, &options.configServer, "w", "config server URL (e.g. tcp://host:22020)")
	registerString(flags, &options.configServer, "config-server", "config server URL (e.g. tcp://host:22020)")
	registerString(flags, &options.machineID, "machine-id", "machine identifier")
	registerString(flags, &options.consoleLogLevel, "console-log-level", "console log level (trace/debug/info/warn/error)")
	registerString(flags, &options.fileLogLevel, "file-log-level", "file log level (trace/debug/info/warn/error)")
	registerString(flags, &options.fileLogDir, "file-log-dir", "file log directory")
	registerString(flags, &options.fileLogSize, "file-log-size", "file log max size")
	registerString(flags, &options.fileLogCount, "file-log-count", "file log max count")
	registerString(flags, &options.credentialFile, "credential-file", "credential file path")
	registerBool(flags, &options.disableRelayData, options.boolSet, "disable-relay-data", "", "disable relay data")
	registerUint(flags, &options.quicListenPort, "quic-listen-port", "QUIC listen port")
	flags.BoolVar(&options.daemon, "daemon", false, "run as daemon")
	registerString(flags, &options.genAutocomplete, "gen-autocomplete", "generate shell completion (bash/zsh/fish/powershell/nushell)")
	registerString(flags, &options.genAutocomplete, "gen_autocomplete", "generate shell completion (bash/zsh/fish/powershell/nushell)")

	registerString(flags, &options.ipv6, "ipv6", "IPv6 address or CIDR")
	registerBool(flags, &options.ipv6PublicAddrProvider, options.boolSet, "ipv6-public-addr-provider", "", "enable IPv6 public address provider")
	registerBool(flags, &options.ipv6PublicAddrAuto, options.boolSet, "ipv6-public-addr-auto", "", "automatically discover a public IPv6 address")
	registerString(flags, &options.ipv6PublicAddrPrefix, "ipv6-public-addr-prefix", "IPv6 public address prefix")
	registerString(flags, &options.externalNode, "e", "external node URL")
	registerString(flags, &options.externalNode, "external-node", "external node URL")
	registerList(flags, &options.proxyNetworks, "n", "proxy network (CIDR or CIDR->mapped-CIDR; repeatable or comma-separated)")
	registerList(flags, &options.proxyNetworks, "proxy-networks", "proxy network (CIDR or CIDR->mapped-CIDR; repeatable or comma-separated)")
	registerList(flags, &options.mappedListeners, "mapped-listeners", "mapped listener URL (repeatable or comma-separated)")
	registerBool(flags, &options.noListener, options.boolSet, "no-listener", "", "disable listeners")
	registerString(flags, &options.hostname, "hostname", "node hostname")
	registerString(flags, &options.instanceName, "m", "instance name")
	registerString(flags, &options.instanceName, "instance-name", "instance name")
	registerString(flags, &options.vpnPortal, "vpn-portal", "VPN portal URL")
	registerString(flags, &options.defaultProtocol, "default-protocol", "default listener protocol")
	registerBool(flags, &options.disableEncryption, options.boolSet, "disable-encryption", "u", "disable encryption")
	registerBool(flags, &options.disableEncryption, options.boolSet, "disable-encryption", "disable-encryption", "disable encryption")
	registerString(flags, &options.encryptionAlgorithm, "encryption-algorithm", "encryption algorithm")
	registerBool(flags, &options.multiThread, options.boolSet, "multi-thread", "", "enable multiple worker threads")
	registerUint(flags, &options.multiThreadCount, "multi-thread-count", "worker thread count")
	registerBool(flags, &options.disableIPv6, options.boolSet, "disable-ipv6", "", "disable IPv6")
	registerString(flags, &options.devName, "dev-name", "virtual device name")
	registerUint(flags, &options.mtu, "mtu", "virtual device MTU")
	registerBool(flags, &options.latencyFirst, options.boolSet, "latency-first", "", "prefer lower latency paths")
	registerList(flags, &options.exitNodes, "exit-nodes", "exit node address (repeatable or comma-separated)")
	registerBool(flags, &options.enableExitNode, options.boolSet, "enable-exit-node", "", "enable exit node")
	registerBool(flags, &options.proxyForwardBySystem, options.boolSet, "proxy-forward-by-system", "", "forward proxy traffic through the system")
	registerBool(flags, &options.noTun, options.boolSet, "no-tun", "", "disable the virtual TUN device")
	registerBool(flags, &options.useSmoltcp, options.boolSet, "use-smoltcp", "", "use smoltcp")
	registerList(flags, &options.manualRoutes, "manual-routes", "manual route (repeatable or comma-separated)")
	registerList(flags, &options.relayNetworkWhitelist, "relay-network-whitelist", "relay network whitelist (comma-separated)")
	registerBool(flags, &options.p2pOnly, options.boolSet, "p2p-only", "", "use only peer-to-peer paths")
	registerBool(flags, &options.lazyP2P, options.boolSet, "lazy-p2p", "", "enable lazy peer-to-peer connections")
	registerBool(flags, &options.disableP2P, options.boolSet, "disable-p2p", "", "disable peer-to-peer connections")
	registerBool(flags, &options.disableUDPHolePunching, options.boolSet, "disable-udp-hole-punching", "", "disable UDP hole punching")
	registerBool(flags, &options.disableTCPHolePunching, options.boolSet, "disable-tcp-hole-punching", "", "disable TCP hole punching")
	registerBool(flags, &options.disableSymHolePunching, options.boolSet, "disable-sym-hole-punching", "", "disable symmetric hole punching")
	registerBool(flags, &options.disableUPnP, options.boolSet, "disable-upnp", "", "disable UPnP")
	registerBool(flags, &options.enableUDPBroadcastRelay, options.boolSet, "enable-udp-broadcast-relay", "", "enable UDP broadcast relay")
	registerBool(flags, &options.relayAllPeerRPC, options.boolSet, "relay-all-peer-rpc", "", "relay all peer RPC")
	registerBool(flags, &options.needP2P, options.boolSet, "need-p2p", "", "require peer-to-peer paths")
	registerString(flags, &options.compression, "compression", "data compression: none or zstd")
	registerUint(flags, &options.socks5, "socks5", "SOCKS5 listen port")
	registerBool(flags, &options.bindDevice, options.boolSet, "bind-device", "", "bind sockets to the virtual device")
	registerBool(flags, &options.enableKCPProxy, options.boolSet, "enable-kcp-proxy", "", "enable KCP proxy")
	registerBool(flags, &options.disableKCPInput, options.boolSet, "disable-kcp-input", "", "disable KCP input")
	registerBool(flags, &options.enableQUICProxy, options.boolSet, "enable-quic-proxy", "", "enable QUIC proxy")
	registerBool(flags, &options.disableQUICInput, options.boolSet, "disable-quic-input", "", "disable QUIC input")
	registerList(flags, &options.portForwards, "port-forward", "port forward URL (repeatable or comma-separated)")
	registerBool(flags, &options.acceptDNS, options.boolSet, "accept-dns", "", "accept DNS")
	registerString(flags, &options.tldDNSZone, "tld-dns-zone", "TLD DNS zone")
	registerBool(flags, &options.privateMode, options.boolSet, "private-mode", "", "enable private mode")
	registerUint64(flags, &options.foreignRelayBPSLimit, "foreign-relay-bps-limit", "foreign relay bandwidth limit")
	registerUint64(flags, &options.instanceRecvBPSLimit, "instance-recv-bps-limit", "instance receive bandwidth limit")
	registerBool(flags, &options.disableRelayKCP, options.boolSet, "disable-relay-kcp", "", "disable KCP relay")
	registerBool(flags, &options.disableRelayQUIC, options.boolSet, "disable-relay-quic", "", "disable QUIC relay")
	registerBool(flags, &options.enableRelayForeignKCP, options.boolSet, "enable-relay-foreign-network-kcp", "", "enable foreign-network KCP relay")
	registerBool(flags, &options.enableRelayForeignQUIC, options.boolSet, "enable-relay-foreign-network-quic", "", "enable foreign-network QUIC relay")
	registerList(flags, &options.tcpWhitelist, "tcp-whitelist", "TCP whitelist (repeatable or comma-separated)")
	registerList(flags, &options.udpWhitelist, "udp-whitelist", "UDP whitelist (repeatable or comma-separated)")
	registerList(flags, &options.stunServers, "stun-servers", "STUN server (repeatable or comma-separated)")
	registerList(flags, &options.stunServersV6, "stun-servers-v6", "IPv6 STUN server (repeatable or comma-separated)")
	registerBool(flags, &options.secureMode, options.boolSet, "secure-mode", "", "enable secure mode")
	registerString(flags, &options.localPrivateKey, "local-private-key", "secure mode private key")
	registerString(flags, &options.localPublicKey, "local-public-key", "secure mode public key")
	registerString(flags, &options.credential, "credential", "credential private key")
	return flags
}

func registerString(flags *flag.FlagSet, target *string, name, usage string) {
	flags.StringVar(target, name, *target, usage)
}

func registerList(flags *flag.FlagSet, target *stringList, name, usage string) {
	flags.Var(target, name, usage)
}

func registerUint(flags *flag.FlagSet, target *uint, name, usage string) {
	flags.UintVar(target, name, 0, usage)
}

func registerUint64(flags *flag.FlagSet, target *uint64, name, usage string) {
	flags.Uint64Var(target, name, 0, usage)
}

func registerBool(flags *flag.FlagSet, target *bool, boolSet map[string]bool, canonical, name, usage string) {
	if name == "" {
		name = canonical
	}
	flags.Var(boolFlag{set: func(value bool) {
		*target = value
		boolSet[canonical] = true
	}}, name, usage)
}

var coreFlagAliases = map[string]string{
	"l": "listeners", "listen": "listeners", "listeners": "listeners",
	"p": "peers", "peers": "peers", "i": "ipv4", "ipv4": "ipv4",
	"d": "dhcp", "dhcp": "dhcp", "f": "config-file", "c": "config-file", "config-file": "config-file",
	"r": "rpc-portal", "rpc-portal": "rpc-portal", "e": "external-node", "external-node": "external-node",
	"n": "proxy-networks", "proxy-networks": "proxy-networks", "m": "instance-name", "instance-name": "instance-name",
	"u": "disable-encryption", "disable-encryption": "disable-encryption",
	"w": "config-server", "config-server": "config-server",
}

func parseArgs(args []string) (options, error) {
	options := options{rpcPortal: "127.0.0.1:15888", boolSet: make(map[string]bool), flagSet: make(map[string]bool)}
	if hasHelp(args) {
		options.showHelp = true
		return options, nil
	}
	flags := newCoreFlagSet(&options, io.Discard)
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	flags.Visit(func(value *flag.Flag) {
		canonical := value.Name
		if alias, ok := coreFlagAliases[value.Name]; ok {
			canonical = alias
		}
		options.flagSet[canonical] = true
	})
	options.rpcPortalSet = options.flagSet["rpc-portal"]

	for _, env := range []struct {
		name string
		flag string
	}{
		{"ET_CONFIG_FILE", "config-file"}, {"ET_CONFIG_DIR", "config-dir"},
		{"ET_RPC_PORTAL", "rpc-portal"},
		{"ET_NETWORK_NAME", "network-name"}, {"ET_NETWORK_SECRET", "network-secret"},
		{"ET_IPV4", "ipv4"}, {"ET_IPV6", "ipv6"},
		{"ET_IPV6_PUBLIC_ADDR_PROVIDER", "ipv6-public-addr-provider"},
		{"ET_IPV6_PUBLIC_ADDR_AUTO", "ipv6-public-addr-auto"}, {"ET_IPV6_PUBLIC_ADDR_PREFIX", "ipv6-public-addr-prefix"},
		{"ET_DHCP", "dhcp"}, {"ET_PEERS", "peers"}, {"ET_EXTERNAL_NODE", "external-node"},
		{"ET_PROXY_NETWORKS", "proxy-networks"}, {"ET_LISTENERS", "listeners"}, {"ET_MAPPED_LISTENERS", "mapped-listeners"},
		{"ET_NO_LISTENER", "no-listener"}, {"ET_HOSTNAME", "hostname"}, {"ET_INSTANCE_NAME", "instance-name"},
		{"ET_VPN_PORTAL", "vpn-portal"}, {"ET_DEFAULT_PROTOCOL", "default-protocol"}, {"ET_DISABLE_ENCRYPTION", "disable-encryption"},
		{"ET_ENCRYPTION_ALGORITHM", "encryption-algorithm"}, {"ET_MULTI_THREAD", "multi-thread"}, {"ET_MULTI_THREAD_COUNT", "multi-thread-count"},
		{"ET_DISABLE_IPV6", "disable-ipv6"}, {"ET_DEV_NAME", "dev-name"}, {"ET_MTU", "mtu"}, {"ET_LATENCY_FIRST", "latency-first"},
		{"ET_EXIT_NODES", "exit-nodes"}, {"ET_ENABLE_EXIT_NODE", "enable-exit-node"}, {"ET_PROXY_FORWARD_BY_SYSTEM", "proxy-forward-by-system"},
		{"ET_NO_TUN", "no-tun"}, {"ET_USE_SMOLTCP", "use-smoltcp"}, {"ET_MANUAL_ROUTES", "manual-routes"},
		{"ET_RELAY_NETWORK_WHITELIST", "relay-network-whitelist"}, {"ET_P2P_ONLY", "p2p-only"}, {"ET_LAZY_P2P", "lazy-p2p"},
		{"ET_DISABLE_P2P", "disable-p2p"}, {"ET_DISABLE_UDP_HOLE_PUNCHING", "disable-udp-hole-punching"},
		{"ET_DISABLE_TCP_HOLE_PUNCHING", "disable-tcp-hole-punching"}, {"ET_DISABLE_SYM_HOLE_PUNCHING", "disable-sym-hole-punching"},
		{"ET_DISABLE_UPNP", "disable-upnp"}, {"ET_ENABLE_UDP_BROADCAST_RELAY", "enable-udp-broadcast-relay"},
		{"ET_RELAY_ALL_PEER_RPC", "relay-all-peer-rpc"}, {"ET_NEED_P2P", "need-p2p"}, {"ET_COMPRESSION", "compression"},
		{"ET_SOCKS5", "socks5"},
		{"ET_BIND_DEVICE", "bind-device"}, {"ET_ENABLE_KCP_PROXY", "enable-kcp-proxy"}, {"ET_DISABLE_KCP_INPUT", "disable-kcp-input"},
		{"ET_ENABLE_QUIC_PROXY", "enable-quic-proxy"}, {"ET_DISABLE_QUIC_INPUT", "disable-quic-input"}, {"ET_PORT_FORWARD", "port-forward"},
		{"ET_ACCEPT_DNS", "accept-dns"}, {"ET_TLD_DNS_ZONE", "tld-dns-zone"}, {"ET_PRIVATE_MODE", "private-mode"},
		{"ET_FOREIGN_RELAY_BPS_LIMIT", "foreign-relay-bps-limit"}, {"ET_INSTANCE_RECV_BPS_LIMIT", "instance-recv-bps-limit"},
		{"ET_DISABLE_RELAY_KCP", "disable-relay-kcp"}, {"ET_DISABLE_RELAY_QUIC", "disable-relay-quic"},
		{"ET_ENABLE_RELAY_FOREIGN_NETWORK_KCP", "enable-relay-foreign-network-kcp"}, {"ET_ENABLE_RELAY_FOREIGN_NETWORK_QUIC", "enable-relay-foreign-network-quic"},
		{"ET_STUN_SERVERS", "stun-servers"}, {"ET_STUN_SERVERS_V6", "stun-servers-v6"}, {"ET_SECURE_MODE", "secure-mode"},
		{"ET_LOCAL_PRIVATE_KEY", "local-private-key"}, {"ET_LOCAL_PUBLIC_KEY", "local-public-key"}, {"ET_CREDENTIAL", "credential"},
		{"ET_CONFIG_SERVER", "config-server"}, {"ET_MACHINE_ID", "machine-id"},
		{"ET_CONSOLE_LOG_LEVEL", "console-log-level"}, {"ET_FILE_LOG_LEVEL", "file-log-level"}, {"ET_FILE_LOG_DIR", "file-log-dir"}, {"ET_FILE_LOG_SIZE", "file-log-size"}, {"ET_FILE_LOG_COUNT", "file-log-count"},
		{"ET_RPC_PORTAL_WHITELIST", "rpc-portal-whitelist"}, {"ET_CREDENTIAL_FILE", "credential-file"}, {"ET_QUIC_LISTEN_PORT", "quic-listen-port"}, {"ET_DAEMON", "daemon"},
	} {
		canonical := env.flag
		if alias, ok := coreFlagAliases[canonical]; ok {
			canonical = alias
		}
		if options.flagSet[canonical] {
			continue
		}
		value, ok := os.LookupEnv(env.name)
		if !ok {
			continue
		}
		if env.flag == "config-file" && value == "" {
			continue
		}
		if err := flags.Set(env.flag, value); err != nil {
			return options, fmt.Errorf("%s: %w", env.name, err)
		}
		options.flagSet[canonical] = true
	}
	options.rpcPortalSet = options.flagSet["rpc-portal"]
	if len(options.configFiles) > 0 {
		options.configFile = options.configFiles[0]
	}
	return options, nil
}

func hasHelp(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func coreHelp() string {
	var output strings.Builder
	options := options{rpcPortal: "127.0.0.1:15888", boolSet: make(map[string]bool)}
	flags := newCoreFlagSet(&options, &output)
	fmt.Fprintln(&output, "Usage: easytier-core [OPTIONS]")
	flags.PrintDefaults()
	return output.String()
}

func isSet(options options, name string) bool {
	canonical := name
	if alias, ok := coreFlagAliases[name]; ok {
		canonical = alias
	}
	return options.flagSet[canonical]
}

func applyOptions(cfg *config.Config, options options) error {
	if isSet(options, "hostname") {
		cfg.Hostname = options.hostname
	}
	if isSet(options, "network-name") {
		cfg.NetworkIdentity.NetworkName = options.networkName
	}
	if isSet(options, "network-secret") {
		cfg.NetworkIdentity.NetworkSecret = options.networkSecret
	}
	if isSet(options, "ipv4") {
		cfg.IPv4 = options.ipv4
	}
	if isSet(options, "ipv6") {
		cfg.IPv6 = options.ipv6
	}
	if isSet(options, "ipv6-public-addr-provider") {
		cfg.IPv6PublicAddrProvider = options.ipv6PublicAddrProvider
	}
	if isSet(options, "ipv6-public-addr-auto") {
		cfg.IPv6PublicAddrAuto = options.ipv6PublicAddrAuto
	}
	if isSet(options, "ipv6-public-addr-prefix") {
		cfg.IPv6PublicAddrPrefix = options.ipv6PublicAddrPrefix
	}
	if isSet(options, "dhcp") {
		cfg.DHCP = options.dhcp
	}
	if isSet(options, "instance-name") {
		cfg.InstanceName = options.instanceName
	}
	if isSet(options, "listeners") {
		if options.noListener && options.boolSet["no-listener"] {
			cfg.Listeners = nil
		} else {
			cfg.Listeners = append([]string(nil), options.listeners...)
		}
	} else if options.boolSet["no-listener"] && options.noListener {
		cfg.Listeners = nil
	}
	if len(options.peers) > 0 {
		for _, peer := range options.peers {
			cfg.Peers = append(cfg.Peers, config.Peer{URI: peer})
		}
	}
	if isSet(options, "external-node") {
		cfg.Peers = append(cfg.Peers, config.Peer{URI: options.externalNode})
	}
	for _, value := range options.proxyNetworks {
		network, err := parseProxyNetwork(value)
		if err != nil {
			return err
		}
		cfg.ProxyNetworks = append(cfg.ProxyNetworks, network)
	}
	if len(options.mappedListeners) > 0 {
		cfg.MappedListeners = append([]string(nil), options.mappedListeners...)
	}
	if len(options.exitNodes) > 0 {
		for _, value := range options.exitNodes {
			if _, err := netipParseAddr(value); err != nil {
				return fmt.Errorf("invalid exit node %q: %w", value, err)
			}
		}
		cfg.ExitNodes = append([]string(nil), options.exitNodes...)
	}
	if len(options.manualRoutes) > 0 {
		cfg.Routes = append([]string(nil), options.manualRoutes...)
	}
	if isSet(options, "vpn-portal") {
		portal, err := parseVPNPortal(options.vpnPortal)
		if err != nil {
			return err
		}
		cfg.VPNPortalConfig = &portal
	}
	if isSet(options, "socks5") {
		if options.socks5 > 65535 {
			return fmt.Errorf("SOCKS5 port %d is out of range", options.socks5)
		}
		cfg.Socks5Proxy = fmt.Sprintf("socks5://0.0.0.0:%d", options.socks5)
	}
	for _, value := range options.portForwards {
		forward, err := parsePortForward(value)
		if err != nil {
			return err
		}
		cfg.PortForwards = append(cfg.PortForwards, forward)
	}
	if len(options.tcpWhitelist) > 0 {
		cfg.TCPWhitelist = append(cfg.TCPWhitelist, options.tcpWhitelist...)
	}
	if len(options.udpWhitelist) > 0 {
		cfg.UDPWhitelist = append(cfg.UDPWhitelist, options.udpWhitelist...)
	}
	if len(options.stunServers) > 0 {
		cfg.STUNServers = append(cfg.STUNServers, nonEmpty(options.stunServers)...)
	}
	if len(options.stunServersV6) > 0 {
		cfg.STUNServersV6 = append(cfg.STUNServersV6, nonEmpty(options.stunServersV6)...)
	}
	if isSet(options, "secure-mode") || isSet(options, "local-private-key") || isSet(options, "local-public-key") || isSet(options, "credential") {
		secure := cfg.SecureMode
		if secure == nil {
			secure = &config.SecureMode{}
		}
		secure.Enabled = options.secureMode || secure.Enabled
		if isSet(options, "local-private-key") {
			secure.LocalPrivateKey = options.localPrivateKey
		}
		if isSet(options, "local-public-key") {
			secure.LocalPublicKey = options.localPublicKey
		}
		if isSet(options, "credential") {
			secure.Enabled = true
			secure.LocalPrivateKey = options.credential
		}
		cfg.SecureMode = secure
	}

	if hasFlagOptions(options) {
		flags := cfg.Flags
		if flags == nil {
			defaults := defaultFlags()
			flags = &defaults
		}
		if isSet(options, "default-protocol") {
			flags.DefaultProtocol = options.defaultProtocol
		}
		if isSet(options, "disable-encryption") {
			flags.EnableEncryption = !options.disableEncryption
		}
		if isSet(options, "encryption-algorithm") {
			flags.EncryptionAlgorithm = options.encryptionAlgorithm
		}
		if isSet(options, "disable-ipv6") {
			flags.EnableIPv6 = !options.disableIPv6
		}
		if isSet(options, "dev-name") {
			flags.DevName = options.devName
		}
		if isSet(options, "mtu") {
			flags.MTU = uint32(options.mtu)
		}
		setFlagBool(options, "latency-first", &flags.LatencyFirst, options.latencyFirst)
		setFlagBool(options, "enable-exit-node", &flags.EnableExitNode, options.enableExitNode)
		setFlagBool(options, "proxy-forward-by-system", &flags.ProxyForwardBySystem, options.proxyForwardBySystem)
		setFlagBool(options, "no-tun", &flags.NoTUN, options.noTun)
		setFlagBool(options, "use-smoltcp", &flags.UseSmoltcp, options.useSmoltcp)
		if len(options.relayNetworkWhitelist) > 0 {
			flags.RelayNetworkWhitelist = strings.Join(nonEmpty(options.relayNetworkWhitelist), " ")
		}
		setFlagBool(options, "p2p-only", &flags.P2POnly, options.p2pOnly)
		setFlagBool(options, "lazy-p2p", &flags.LazyP2P, options.lazyP2P)
		setFlagBool(options, "disable-p2p", &flags.DisableP2P, options.disableP2P)
		setFlagBool(options, "disable-tcp-hole-punching", &flags.DisableTCPHolePunching, options.disableTCPHolePunching)
		setFlagBool(options, "disable-udp-hole-punching", &flags.DisableUDPHolePunching, options.disableUDPHolePunching)
		setFlagBool(options, "relay-all-peer-rpc", &flags.RelayAllPeerRPC, options.relayAllPeerRPC)
		setFlagBool(options, "need-p2p", &flags.NeedP2P, options.needP2P)
		if isSet(options, "compression") {
			flags.DataCompressAlgo = options.compression
		}
		setFlagBool(options, "bind-device", &flags.BindDevice, options.bindDevice)
		setFlagBool(options, "enable-kcp-proxy", &flags.EnableKCPProxy, options.enableKCPProxy)
		setFlagBool(options, "disable-kcp-input", &flags.DisableKCPInput, options.disableKCPInput)
		setFlagBool(options, "enable-quic-proxy", &flags.EnableQUICProxy, options.enableQUICProxy)
		setFlagBool(options, "disable-quic-input", &flags.DisableQUICInput, options.disableQUICInput)
		setFlagBool(options, "accept-dns", &flags.AcceptDNS, options.acceptDNS)
		setFlagBool(options, "private-mode", &flags.PrivateMode, options.privateMode)
		if isSet(options, "tld-dns-zone") {
			flags.TLDDNSZone = options.tldDNSZone
		}
		if isSet(options, "foreign-relay-bps-limit") {
			flags.ForeignRelayBPSLimit = options.foreignRelayBPSLimit
		}
		if isSet(options, "instance-recv-bps-limit") {
			flags.InstanceRecvBPSLimit = options.instanceRecvBPSLimit
		}
		if isSet(options, "multi-thread-count") {
			flags.MultiThreadCount = uint32(options.multiThreadCount)
		}
		setFlagBool(options, "multi-thread", &flags.MultiThread, options.multiThread)
		setFlagBool(options, "disable-relay-kcp", &flags.DisableRelayKCP, options.disableRelayKCP)
		setFlagBool(options, "disable-relay-quic", &flags.DisableRelayQUIC, options.disableRelayQUIC)
		setFlagBool(options, "enable-relay-foreign-network-kcp", &flags.EnableRelayForeignNetworkKCP, options.enableRelayForeignKCP)
		setFlagBool(options, "enable-relay-foreign-network-quic", &flags.EnableRelayForeignNetworkQUIC, options.enableRelayForeignQUIC)
		setFlagBool(options, "disable-sym-hole-punching", &flags.DisableSymHolePunching, options.disableSymHolePunching)
		setFlagBool(options, "disable-upnp", &flags.DisableUPnP, options.disableUPnP)
		setFlagBool(options, "enable-udp-broadcast-relay", &flags.EnableUDPBroadcastRelay, options.enableUDPBroadcastRelay)
		setFlagBool(options, "disable-relay-data", &flags.DisableRelayData, options.disableRelayData)
		if isSet(options, "quic-listen-port") {
			flags.QuicListenPort = uint32(options.quicListenPort)
		}
		cfg.Flags = flags
	}
	if isSet(options, "credential-file") {
		cfg.CredentialFile = options.credentialFile
	}
	return nil
}

func hasFlagOptions(options options) bool {
	for _, name := range []string{"default-protocol", "disable-encryption", "encryption-algorithm", "disable-ipv6", "dev-name", "mtu", "latency-first", "enable-exit-node", "proxy-forward-by-system", "no-tun", "use-smoltcp", "relay-network-whitelist", "p2p-only", "lazy-p2p", "disable-p2p", "disable-tcp-hole-punching", "disable-udp-hole-punching", "relay-all-peer-rpc", "need-p2p", "compression", "bind-device", "enable-kcp-proxy", "disable-kcp-input", "enable-quic-proxy", "disable-quic-input", "accept-dns", "private-mode", "tld-dns-zone", "foreign-relay-bps-limit", "instance-recv-bps-limit", "multi-thread-count", "multi-thread", "disable-relay-kcp", "disable-relay-quic", "enable-relay-foreign-network-kcp", "enable-relay-foreign-network-quic", "disable-sym-hole-punching", "disable-upnp", "enable-udp-broadcast-relay", "disable-relay-data", "quic-listen-port"} {
		if isSet(options, name) {
			return true
		}
	}
	return false
}

func setFlagBool(options options, name string, target *bool, value bool) {
	if isSet(options, name) {
		*target = value
	}
}

func defaultFlags() config.Flags {
	return config.Flags{
		DefaultProtocol: "tcp", EnableEncryption: true, EnableIPv6: true, MTU: 1380,
		MultiThread: true, RelayNetworkWhitelist: "*", BindDevice: true,
		DataCompressAlgo: "none", MultiThreadCount: 2, ForeignRelayBPSLimit: ^uint64(0),
		InstanceRecvBPSLimit: ^uint64(0), TLDDNSZone: "et.net.",
	}
}

func parseProxyNetwork(value string) (config.ProxyNetwork, error) {
	parts := strings.Split(value, "->")
	if len(parts) > 2 || parts[0] == "" {
		return config.ProxyNetwork{}, fmt.Errorf("invalid proxy network format %q", value)
	}
	result := config.ProxyNetwork{CIDR: parts[0]}
	if len(parts) == 2 {
		result.MappedCIDR = parts[1]
	}
	return result, nil
}

func parseVPNPortal(value string) (config.VPNPortalConfig, error) {
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.Port() == "" || strings.Trim(u.Path, "/") == "" {
		return config.VPNPortalConfig{}, fmt.Errorf("invalid VPN portal URL %q", value)
	}
	if _, err := netipParsePrefix(strings.Trim(u.Path, "/")); err != nil {
		return config.VPNPortalConfig{}, fmt.Errorf("invalid VPN portal client CIDR: %w", err)
	}
	return config.VPNPortalConfig{WireGuardListen: net.JoinHostPort(u.Hostname(), u.Port()), ClientCIDR: strings.Trim(u.Path, "/")}, nil
}

func parsePortForward(value string) (config.PortForward, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Hostname() == "" || u.Port() == "" {
		return config.PortForward{}, fmt.Errorf("invalid port forward URL %q", value)
	}
	path := strings.Trim(u.Path, "/")
	if path == "" {
		return config.PortForward{}, fmt.Errorf("port forward %q is missing destination", value)
	}
	return config.PortForward{BindAddr: net.JoinHostPort(u.Hostname(), u.Port()), DstAddr: path, Proto: u.Scheme}, nil
}

func nonEmpty(values []string) []string {
	filtered := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

// Small wrappers keep this file independent from a particular netip API in
// callers and make the command-line errors easier to test.
func netipParseAddr(value string) (string, error) {
	address, err := netip.ParseAddr(value)
	return address.String(), err
}

func netipParsePrefix(value string) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	return prefix.String(), err
}

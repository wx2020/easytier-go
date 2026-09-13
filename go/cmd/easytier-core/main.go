// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// EasyTier Go core is the replacement daemon for the Rust easytier-core binary.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/core"
	"github.com/EasyTier/EasyTier/go/internal/instance"
	"github.com/EasyTier/EasyTier/go/internal/logging"
	"github.com/EasyTier/EasyTier/go/internal/management"
	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/stats"
	"github.com/EasyTier/EasyTier/go/internal/tun"
	"github.com/EasyTier/EasyTier/go/internal/vpnportal"
	"github.com/EasyTier/EasyTier/go/internal/webclient"
)

var version = "0.0.0-dev"

type options struct {
	showHelp                  bool
	showVersion               bool
	listeners                 stringList
	mappedListeners           stringList
	peers                     stringList
	externalNode              string
	proxyNetworks             stringList
	ipv4                      string
	ipv6                      string
	ipv6PublicAddrProvider    bool
	ipv6PublicAddrAuto        bool
	ipv6PublicAddrPrefix      string
	dhcp                      bool
	noListener                bool
	hostname                  string
	networkName               string
	networkSecret             string
	instanceName              string
	vpnPortal                 string
	defaultProtocol           string
	disableEncryption         bool
	encryptionAlgorithm       string
	multiThread               bool
	multiThreadCount          uint
	disableIPv6               bool
	devName                   string
	mtu                       uint
	latencyFirst              bool
	exitNodes                 stringList
	enableExitNode            bool
	proxyForwardBySystem      bool
	noTun                     bool
	useSmoltcp                bool
	manualRoutes              stringList
	relayNetworkWhitelist     stringList
	p2pOnly                   bool
	lazyP2P                   bool
	disableP2P                bool
	disableUDPHolePunching    bool
	disableTCPHolePunching    bool
	disableSymHolePunching    bool
	disableUPnP               bool
	enableUDPBroadcastRelay   bool
	relayAllPeerRPC           bool
	needP2P                   bool
	compression               string
	socks5                    uint
	bindDevice                bool
	enableKCPProxy            bool
	disableKCPInput           bool
	enableQUICProxy           bool
	disableQUICInput          bool
	portForwards              stringList
	acceptDNS                 bool
	tldDNSZone                string
	privateMode               bool
	foreignRelayBPSLimit      uint64
	instanceRecvBPSLimit      uint64
	disableRelayKCP           bool
	disableRelayQUIC          bool
	enableRelayForeignKCP     bool
	enableRelayForeignQUIC    bool
	stunServers               stringList
	stunServersV6             stringList
	secureMode                bool
	localPrivateKey           string
	localPublicKey            string
	credential                string
	tcpWhitelist              stringList
	udpWhitelist              stringList
	configFile                string
	configFiles               stringList
	configDir                 string
	checkConfig               bool
	disableEnvironmentParsing bool
	rpcPortal                 string
	rpcPortalWhitelist        stringList
	rpcPortalSet              bool
	configServer              string
	machineID                 string
	consoleLogLevel           string
	fileLogLevel              string
	fileLogDir                string
	fileLogSize               string
	fileLogCount              string
	credentialFile            string
	disableRelayData          bool
	quicListenPort            uint
	daemon                    bool
	genAutocomplete           string
	flagSet                   map[string]bool
	boolSet                   map[string]bool
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	*values = append(*values, strings.Split(value, ",")...)
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	options, err := parseArgs(args)
	if err != nil {
		return commandError(stderr, 2, err)
	}
	if options.showVersion {
		fmt.Fprintf(stdout, "easytier-core %s (go rewrite)\n", version)
		return 0
	}
	if options.showHelp {
		_, _ = io.WriteString(stdout, coreHelp())
		return 0
	}
	if options.genAutocomplete != "" {
		_, _ = io.WriteString(stdout, generateCompletion(options.genAutocomplete))
		return 0
	}
	loadedConfigs, err := config.LoadSources([]string(options.configFiles), options.configDir, options.disableEnvironmentParsing)
	if err != nil {
		return commandError(stderr, 2, err)
	}
	if options.checkConfig {
		if len(loadedConfigs) == 0 {
			return commandError(stderr, 2, fmt.Errorf("--check-config requires --config-file or --config-dir"))
		}
		if len(loadedConfigs) > 1 {
			return 0
		}
	}
	configs := make([]config.Config, 0, len(loadedConfigs))
	if len(loadedConfigs) == 0 {
		var cfg config.Config
		if err := applyOptions(&cfg, options); err != nil {
			return commandError(stderr, 2, err)
		}
		configs = append(configs, cfg)
	} else {
		for _, loaded := range loadedConfigs {
			cfg := loaded.Config
			if err := applyOptions(&cfg, options); err != nil {
				return commandError(stderr, 2, err)
			}
			if err := cfg.Validate(); err != nil {
				return commandError(stderr, 2, fmt.Errorf("validate command-line configuration %q: %w", loaded.Path, err))
			}
			if loaded.Expanded {
				fmt.Fprintln(stderr, "easytier-core: configuration contains expanded environment values and is read-only")
			}
			configs = append(configs, cfg)
		}
	}
	if options.checkConfig {
		if len(loadedConfigs) == 0 {
			return commandError(stderr, 2, fmt.Errorf("--check-config requires --config-file or --config-dir"))
		}
		return 0
	}
	// Wire --config-server / ET_CONFIG_SERVER to webclient.Client like Rust core.rs:93.
	// For now the client runs with reconnect backoff and heartbeat; config updates are logged.
	var wc *webclient.Client
	var wcCancel context.CancelFunc
	if options.configServer != "" {
		machineID := options.machineID
		if machineID == "" {
			if h, err := os.Hostname(); err == nil && h != "" {
				machineID = h
			} else {
				machineID = "default-machine"
			}
		}
		machineName := options.hostname
		if machineName == "" {
			if h, err := os.Hostname(); err == nil {
				machineName = h
			}
		}
		client, err := webclient.NewClient(webclient.ClientConfig{
			Address:     options.configServer,
			MachineID:   machineID,
			MachineName: machineName,
			Version:     version,
		})
		if err != nil {
			fmt.Fprintf(stderr, "easytier-core: config server %q: %v\n", options.configServer, err)
		} else {
			wc = client
			wcCtx, cancel := context.WithCancel(ctx)
			wcCancel = cancel
			go func() {
				if err := wc.Run(wcCtx); err != nil {
					fmt.Fprintf(stderr, "easytier-core: config server stopped: %v\n", err)
				}
			}()
			fmt.Fprintf(stderr, "easytier-core: config server %s started (machine %s)\n", options.configServer, machineID)
		}
	}
	if wcCancel != nil {
		defer wcCancel()
	}
	if wc != nil {
		defer func() { _ = wc.Close() }()
	}
	for _, cfg := range configs {
		if len(cfg.Listeners) == 0 {
			return commandError(stderr, 2, fmt.Errorf("--listen is required while the Go daemon compatibility foundation is in progress"))
		}
		if _, _, err := runtimeListenerAddresses(cfg); err != nil {
			return commandError(stderr, 2, err)
		}
	}

	manager := instance.NewInstanceManager()
	managed := make([]*configuredInstance, 0, len(configs))
	for index, cfg := range configs {
		name := configuredName(cfg, configPath(loadedConfigs, index), index, len(configs))
		item := newConfiguredInstance(ctx, name, cfg)
		if err := manager.Add(item); err != nil {
			_ = item.Close()
			_ = manager.CloseAll()
			return commandError(stderr, 2, fmt.Errorf("register instance %q: %w", name, err))
		}
		managed = append(managed, item)
	}
	defer manager.CloseAll()
	for _, item := range managed {
		if err := manager.Start(ctx, item.Name()); err != nil {
			_ = manager.CloseAll()
			return commandError(stderr, 1, fmt.Errorf("start instance %q: %w", item.Name(), err))
		}
	}
	if len(managed) == 0 {
		return commandError(stderr, 2, errors.New("no configuration instances were loaded"))
	}
	node := managed[0].Node()
	if node == nil {
		return commandError(stderr, 1, errors.New("first configuration instance did not start"))
	}
	cfg := configs[0]
	managementConfig := &cfg
	managementName := cfg.InstanceName
	if len(configs) > 1 {
		managementConfig = nil
		managementName = managed[0].Name()
	}

	counters := stats.New()
	counters.Add("easytier_core_starts_total", 1)
	logger := logging.New(stderr, logging.LevelInfo)
	var vpnPortal management.VPNPortalProvider
	if len(managed) > 0 {
		if p := managed[0].Portal(); p != nil {
			vpnPortal = p
		}
	}
	service := management.NewServiceWithOptions(management.ServiceOptions{
		NodeInfo: management.NodeInfo{
			ID:      node.Address().String(),
			Name:    managementName,
			Version: version,
		},
		Counters:       counters,
		Instances:      manager,
		Logger:         logger,
		Config:         managementConfig,
		ConfigReadOnly: len(configs) == 1 && len(loadedConfigs) == 1 && loadedConfigs[0].ReadOnly,
		Peers:          node.PeerManager(),
		Connectors:     configuredConnectors(cfg),
		MetricLabels:   map[string]string{"node_id": node.Address().String(), "instance": managementName},
		VPNPortal:      vpnPortal,
	})
	portal, err := rpc.NewServer(loopbackWhitelist(), service.Handler)
	if err != nil {
		return commandError(stderr, 1, err)
	}
	if err := portal.Listen(options.rpcPortal); err != nil {
		return commandError(stderr, 1, err)
	}
	defer portal.Close()
	if len(managed) == 1 {
		fmt.Fprintf(stdout, "easytier-core listening on %s\n", node.Address())
		if node.UDPAddress() != nil {
			fmt.Fprintf(stdout, "easytier-core UDP listening on %s\n", node.UDPAddress())
		}
	} else {
		for _, item := range managed {
			node := item.Node()
			fmt.Fprintf(stdout, "easytier-core instance %s listening on %s\n", item.Name(), node.Address())
			if node.UDPAddress() != nil {
				fmt.Fprintf(stdout, "easytier-core instance %s UDP listening on %s\n", item.Name(), node.UDPAddress())
			}
		}
	}
	fmt.Fprintf(stdout, "easytier-core RPC portal on %s\n", portal.Addr())
	portalResult := make(chan error, 1)
	go func() { portalResult <- portal.Serve(ctx) }()
	if err := <-portalResult; err != nil {
		return commandError(stderr, 1, err)
	}
	return 0
}

// Small adapters keep command setup readable without exposing core internals.
type peerIdentity struct{ value peer.LegacyIdentity }

func newCoreNode(address string, identity *peerIdentity) (*core.Node, error) {
	if identity == nil {
		return core.Listen(address, 0)
	}
	return core.ListenWithIdentity(address, 0, &identity.value)
}

func newConfiguredCoreNode(tcpAddress, udpAddress string, cfg config.Config) (*core.Node, error) {
	identity, err := cfg.LegacyIdentity(2)
	if err != nil {
		return nil, err
	}
	compression := ""
	if cfg.Flags != nil {
		compression = cfg.Flags.DataCompressAlgo
	}
	algorithm := protocol.CompressionNone
	if compression == "zstd" {
		algorithm = protocol.CompressionZstd
	}
	peers := make([]string, 0, len(cfg.Peers))
	for _, configured := range cfg.Peers {
		peers = append(peers, configured.URI)
	}
	// Handle no-TUN mode: skip TUN but still expose management.
	noTun := false
	mtu := uint32(tun.DefaultMTU)
	enableEncryption := true
	devName := ""
	if cfg.Flags != nil {
		noTun = cfg.Flags.NoTUN
		if cfg.Flags.MTU != 0 {
			mtu = cfg.Flags.MTU
		}
		enableEncryption = cfg.Flags.EnableEncryption
		devName = cfg.Flags.DevName
		_ = devName
	}
	// MTU effective handling
	effectiveMTU := tun.EffectiveMTU(mtu, enableEncryption)
	// Determine if TUN should be created (static IP or DHCP or explicit)
	shouldCreateTUN := !noTun && (cfg.DHCP || strings.TrimSpace(cfg.IPv4) != "" || strings.TrimSpace(cfg.IPv6) != "")
	var tunDevice tun.Device
	var tunMTU int
	var tunDestination uint32
	if shouldCreateTUN {
		// Prefer MemoryDevice for daemon fallback; real platform TUN would be created here
		// with devName for Linux. For now use MemoryDevice with MTU.
		dev, _, err := tun.NewMemoryDevicePairWithMTU(128, effectiveMTU)
		if err != nil {
			// fallback to simple pair
			dev, _, err = tun.NewMemoryDevicePair(128)
			if err != nil {
				return nil, err
			}
			_ = dev.SetMTU(effectiveMTU)
		}
		// Resolve addresses: DHCP vs static
		tunCfg := tun.TunConfig{
			IPv4:             cfg.IPv4,
			IPv6:             cfg.IPv6,
			DHCP:             cfg.DHCP,
			NoTUN:            noTun,
			MTU:              mtu,
			EnableEncryption: enableEncryption,
		}
		// For DHCP, allocate from pool; for static, assign directly.
		assigned, err := tun.ResolveAssigned(tunCfg, nil)
		if err == nil {
			if assigned.IPv4 != nil {
				_ = dev.AssignIPv4(*assigned.IPv4)
			}
			if assigned.IPv6 != nil {
				_ = dev.AssignIPv6(*assigned.IPv6)
			}
			if assigned.MTU > 0 {
				effectiveMTU = assigned.MTU
				_ = dev.SetMTU(effectiveMTU)
			}
		}
		tunDevice = dev
		tunMTU = effectiveMTU
		// For daemon, destination is dynamic via routing; use 0 to indicate
		// dynamic lookup (core will route by IP when destination is 0). For test
		// compatibility, when a fixed destination is needed, tests will provide it
		// directly via core.NodeOptions. Here we leave 0 for dynamic.
		tunDestination = 0
		// If still 0 and we have at least one peer, use first peer's ID as hint?
		// Not required for GWY-01.
	}
	// When TUN was created but destination is 0, we allow it for dynamic routing.
	// For the case where shouldCreateTUN is false, TUN remains nil (no-TUN mode).
	// Global traffic encryption keys derive from the network secret; nil keeps
	// the null cipher, which rejects inbound encrypted packets.
	var legacyCipher peer.LegacyCipher
	if enableEncryption {
		encryptionAlgorithm := ""
		if cfg.Flags != nil {
			encryptionAlgorithm = cfg.Flags.EncryptionAlgorithm
		}
		key128, key256 := protocol.DeriveLegacyKeys(cfg.NetworkIdentity.NetworkSecret)
		cipher, err := peer.NewLegacyCipher(encryptionAlgorithm, key128, key256)
		if err != nil {
			return nil, fmt.Errorf("create legacy cipher: %w", err)
		}
		legacyCipher = cipher
	}
	opts := core.NodeOptions{
		Address:    tcpAddress,
		UDPAddress: udpAddress,
		Peers:      peers,
		PeerManager: peer.PeerConnectionManagerConfig{
			LocalPeerID:      identity.PeerID,
			LegacyIdentity:   identity,
			DataCompressAlgo: algorithm,
			LegacyCipher:     legacyCipher,
		},
		PeerCenterNetworkName: cfg.NetworkIdentity.NetworkName,
		NoTUN:                 noTun,
		EnableEncryption:      enableEncryption,
		DHCP:                  cfg.DHCP,
		IPv4:                  cfg.IPv4,
		IPv6:                  cfg.IPv6,
		TUN:                   tunDevice,
		TUNMTU:                tunMTU,
		TUNDestination:        tunDestination,
	}
	if cfg.NetworkIdentity.NetworkName != "" {
		opts.P2P = p2pConfigFrom(cfg)
	}
	return core.ListenWithOptions(opts)
}

// p2pConfigFrom derives the NAT traversal configuration from the instance
// config: STUN detection, hole punching, the direct connector, and manual
// connectors for the configured peers.
func p2pConfigFrom(cfg config.Config) *core.P2PConfig {
	p2p := &core.P2PConfig{
		NetworkName:      cfg.NetworkIdentity.NetworkName,
		ManualConnectors: make([]string, 0, len(cfg.Peers)),
	}
	for _, configured := range cfg.Peers {
		p2p.ManualConnectors = append(p2p.ManualConnectors, configured.URI)
	}
	p2p.ExtraListeners = append(p2p.ExtraListeners, cfg.MappedListeners...)
	if cfg.Flags != nil {
		flags := cfg.Flags
		p2p.DisableP2P = flags.DisableP2P
		p2p.NeedP2P = flags.NeedP2P
		p2p.LazyP2P = flags.LazyP2P
		p2p.DisableUDPHolePunching = flags.DisableUDPHolePunching
		p2p.DisableTCPHolePunching = flags.DisableTCPHolePunching
		p2p.DisableSymHolePunching = flags.DisableSymHolePunching
		p2p.DisableUPnP = flags.DisableUPnP
		p2p.EnableIPv6 = flags.EnableIPv6
		if flags.DefaultProtocol != "" {
			p2p.DefaultProtocol = flags.DefaultProtocol
		}
	}
	return p2p
}

type configuredInstance struct {
	mu        sync.Mutex
	name      string
	identity  string
	cfg       config.Config
	lifetime  context.Context
	node      *core.Node
	portal    *vpnportal.Portal
	serveDone chan error
}

func newConfiguredInstance(lifetime context.Context, name string, cfg config.Config) *configuredInstance {
	return &configuredInstance{name: name, identity: name, cfg: cfg, lifetime: lifetime}
}

func (i *configuredInstance) ID() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.node != nil {
		return i.node.Address().String()
	}
	return i.identity
}

func (i *configuredInstance) Name() string { return i.name }

func (i *configuredInstance) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("instance start context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tcpAddress, udpAddress, err := runtimeListenerAddresses(i.cfg)
	if err != nil {
		return err
	}
	node, err := newConfiguredCoreNode(tcpAddress, udpAddress, i.cfg)
	if err != nil {
		return err
	}
	// Start VPN portal if configured (GWY-09).
	var portal *vpnportal.Portal
	if i.cfg.VPNPortalConfig != nil {
		p, err := vpnportal.NewPortal(*i.cfg.VPNPortalConfig, i.cfg.NetworkIdentity)
		if err != nil {
			_ = node.Close()
			return fmt.Errorf("create vpn portal: %w", err)
		}
		if err := p.Start(i.lifetime); err != nil {
			_ = node.Close()
			return fmt.Errorf("start vpn portal: %w", err)
		}
		// Bidirectional stock-client path: decapsulated portal packets
		// enter the mesh here, return traffic leaves via node.SetPortal.
		p.SetMeshForwarder(func(ctx context.Context, ipPacket []byte) error {
			return node.SendIPPacket(ctx, ipPacket)
		})
		node.SetPortal(p)
		portal = p
	}
	done := make(chan error, 1)
	i.mu.Lock()
	i.node = node
	i.portal = portal
	i.serveDone = done
	i.mu.Unlock()
	go func() { done <- node.Serve(i.lifetime) }()
	return nil
}

func (i *configuredInstance) Close() error {
	i.mu.Lock()
	node, done, portal := i.node, i.serveDone, i.portal
	i.mu.Unlock()
	if node == nil && portal == nil {
		return nil
	}
	var portalErr error
	if portal != nil {
		portalErr = portal.Close()
	}
	var closeErr error
	var serveErr error
	if node != nil {
		closeErr = node.Close()
		if done != nil {
			serveErr = <-done
		}
	}
	i.mu.Lock()
	i.node = nil
	i.portal = nil
	i.serveDone = nil
	i.mu.Unlock()
	if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
		return errors.Join(portalErr, closeErr, serveErr)
	}
	return errors.Join(portalErr, closeErr)
}

func (i *configuredInstance) Portal() *vpnportal.Portal {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.portal
}

func (i *configuredInstance) Node() *core.Node {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.node
}

func configPath(loaded []config.LoadedConfig, index int) string {
	if index >= len(loaded) {
		return ""
	}
	return loaded[index].Path
}

func configuredName(cfg config.Config, path string, index, total int) string {
	if name := strings.TrimSpace(cfg.InstanceName); name != "" {
		return name
	}
	if path != "" && path != "-" {
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if name != "" {
			return name
		}
	}
	if total == 1 {
		return "default"
	}
	return fmt.Sprintf("instance-%d", index+1)
}

func tcpListenerAddress(listener string) (string, error) {
	if !strings.Contains(listener, "://") {
		return listener, nil
	}
	endpoint, err := config.ParseEndpoint(listener)
	if err != nil {
		return "", err
	}
	if endpoint.Protocol != config.ProtocolTCP {
		return "", fmt.Errorf("listener %q uses %s; only tcp:// is runnable in the current Go daemon slice", listener, endpoint.Protocol)
	}
	return endpoint.Address(), nil
}

func runtimeListenerAddresses(cfg config.Config) (string, string, error) {
	endpoints, err := cfg.NormalizedListeners()
	if err != nil {
		return "", "", err
	}
	var tcpAddress, udpAddress string
	for _, endpoint := range endpoints {
		switch endpoint.Protocol {
		case config.ProtocolTCP:
			if tcpAddress != "" {
				return "", "", fmt.Errorf("multiple TCP listeners are not supported by one Go instance")
			}
			tcpAddress = endpoint.Address()
		case config.ProtocolUDP:
			if udpAddress != "" {
				return "", "", fmt.Errorf("multiple UDP listeners are not supported by one Go instance")
			}
			udpAddress = endpoint.Address()
		case config.ProtocolUnix, config.ProtocolWG, config.ProtocolQUIC, config.ProtocolWS, config.ProtocolWSS, config.ProtocolFakeTCP:
			// These listeners remain outside the host Linux entry point. The
			// transport packages are available to embedders and peer dials.
			continue
		default:
			return "", "", fmt.Errorf("listener protocol %s is invalid", endpoint.Protocol)
		}
	}
	if tcpAddress == "" {
		return "", "", fmt.Errorf("a TCP listener is required by the Go core entry point")
	}
	return tcpAddress, udpAddress, nil
}

func loopbackWhitelist() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
}

func configuredConnectors(cfg config.Config) []management.ConnectorInfo {
	connectors := make([]management.ConnectorInfo, 0, len(cfg.Peers))
	for _, configured := range cfg.Peers {
		connectors = append(connectors, management.ConnectorInfo{URL: configured.URI, Status: "configured"})
	}
	return connectors
}

func generateCompletion(shell string) string {
	switch shell {
	case "bash":
		return "# easytier-core bash completion\n_complete_easytier_core() { local cur=${COMP_WORDS[COMP_CWORD]}; COMPREPLY=($(compgen -W \"$(easytier-core --help | grep -o -- '--[^ ]*')\" -- \"$cur\")); } \ncomplete -F _complete_easytier_core easytier-core\n"
	case "zsh":
		return "#compdef easytier-core\n_arguments \"--help[show help]\" \"--version[show version]\" \"--config-file[TOML file]:\" \"--config-dir[config dir]:\" \"--config-server[config server]:\"\n"
	case "fish":
		return "complete -c easytier-core -l help -d 'show help' -l version -d 'show version'\n"
	case "powershell":
		return "# PowerShell completion for easytier-core\nRegister-ArgumentCompleter -CommandName easytier-core -ScriptBlock { param($w,$p,$c); @('--help','--version','--config-file') | Where-Object { $_ -like \"$w*\" } }\n"
	case "nushell":
		return "# Nushell completion for easytier-core\ndef \"nu-complete easytier-core\" [] { [\"--help\", \"--version\", \"--config-file\"] }\n"
	default:
		return fmt.Sprintf("# Unknown shell %q, supported: bash/zsh/fish/powershell/nushell\n", shell)
	}
}

func commandError(stderr io.Writer, status int, err error) int {
	fmt.Fprintf(stderr, "easytier-core: %v\n", err)
	return status
}

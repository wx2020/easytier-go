// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/core"
	"github.com/EasyTier/EasyTier/go/internal/instance"
	"github.com/EasyTier/EasyTier/go/internal/peer"
	instancepb "github.com/EasyTier/EasyTier/go/internal/proto/api_instance"
	managepb "github.com/EasyTier/EasyTier/go/internal/proto/api_manage"
	commonpb "github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/route"
	"github.com/EasyTier/EasyTier/go/internal/webconsole"
)

// webConsoleBackend owns the instances a web console drives. It keeps one
// configuredInstance per console instance ID and remembers the configuration
// so GetNetworkInstanceConfig/PatchConfig can serve it back.
type webConsoleBackend struct {
	lifetime context.Context
	manager  *instance.InstanceManager
	version  string
	logf     func(string, ...any)

	mu       sync.Mutex
	configs  map[string]config.Config
	names    map[string]string
	stateDir string
}

func newWebConsoleBackend(lifetime context.Context, manager *instance.InstanceManager, version string, logf func(string, ...any)) *webConsoleBackend {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &webConsoleBackend{
		lifetime: lifetime,
		manager:  manager,
		version:  version,
		logf:     logf,
		configs:  make(map[string]config.Config),
		names:    make(map[string]string),
		stateDir: webConsoleStateDir(),
	}
}

// instanceName is the instance-manager key for one console instance ID.
func instanceName(instID string) string {
	trimmed := strings.TrimSpace(instID)
	if len(trimmed) > 8 {
		trimmed = trimmed[:8]
	}
	if trimmed == "" {
		trimmed = "default"
	}
	return "web-" + trimmed
}

// InstanceIDs implements webconsole.Backend.
func (b *webConsoleBackend) InstanceIDs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	ids := make([]string, 0, len(b.configs))
	for id := range b.configs {
		ids = append(ids, id)
	}
	return ids
}

// RunInstance implements webconsole.Backend.
func (b *webConsoleBackend) RunInstance(ctx context.Context, instID string, cfg *config.Config, overwrite bool) error {
	if cfg == nil {
		return errors.New("web console instance config is nil")
	}
	name := instanceName(instID)

	b.mu.Lock()
	_, exists := b.configs[instID]
	b.mu.Unlock()
	if exists && !overwrite {
		b.logf("web console instance %s already running, ignoring non-overwrite run", instID)
		return nil
	}
	if exists {
		if err := b.stopInstance(instID); err != nil {
			return fmt.Errorf("replace instance %s: %w", instID, err)
		}
	}

	item := newConfiguredInstance(b.lifetime, name, *cfg)
	if err := b.manager.Add(item); err != nil {
		return fmt.Errorf("register instance %s: %w", instID, err)
	}
	if err := b.manager.Start(ctx, name); err != nil {
		_ = b.manager.Stop(name)
		_ = b.manager.Remove(name)
		b.logf("web console instance %s failed to start: %v", instID, err)
		return fmt.Errorf("start instance %s: %w", instID, err)
	}
	b.logf("web console instance %s started as %s (network %q, ipv4 %q, peers %d)",
		instID, name, cfg.NetworkIdentity.NetworkName, cfg.IPv4, len(cfg.Peers))
	go b.watchPeers(ctx, instID, name)
	b.mu.Lock()
	b.configs[instID] = *cfg
	b.names[instID] = name
	b.mu.Unlock()
	b.persist(instID, *cfg)
	return nil
}

// DeleteInstances implements webconsole.Backend.
func (b *webConsoleBackend) DeleteInstances(instIDs []string) []string {
	var remaining []string
	for _, instID := range instIDs {
		if err := b.stopInstance(instID); err != nil {
			b.logf("web console instance %s could not be deleted: %v", instID, err)
			remaining = append(remaining, instID)
		}
	}
	return remaining
}

// RetainInstances implements webconsole.Backend.
func (b *webConsoleBackend) RetainInstances(instIDs []string) []string {
	keep := make(map[string]bool, len(instIDs))
	for _, instID := range instIDs {
		keep[instID] = true
	}
	for _, existing := range b.InstanceIDs() {
		if keep[existing] {
			continue
		}
		if err := b.stopInstance(existing); err != nil {
			b.logf("web console instance %s could not be stopped: %v", existing, err)
		}
	}
	// Report the retained IDs that are still known to this machine.
	remaining := make([]string, 0, len(instIDs))
	for _, instID := range instIDs {
		b.mu.Lock()
		_, known := b.configs[instID]
		b.mu.Unlock()
		if known {
			remaining = append(remaining, instID)
		}
	}
	return remaining
}

// FirstInstanceInfo returns the running information of the instance this
// machine hosts, regardless of the id the console asks for.
func (b *webConsoleBackend) FirstInstanceInfo() *managepb.NetworkInstanceRunningInfo {
	b.mu.Lock()
	ids := make([]string, 0, len(b.configs))
	names := make(map[string]string, len(b.names))
	for id := range b.configs {
		ids = append(ids, id)
	}
	for id, name := range b.names {
		names[id] = name
	}
	b.mu.Unlock()
	sort.Strings(ids)
	for _, id := range ids {
		b.mu.Lock()
		cfg := b.configs[id]
		b.mu.Unlock()
		return b.describeInstance(cfg, names[id])
	}
	return nil
}

// InstanceConfig implements webconsole.Backend.
func (b *webConsoleBackend) InstanceConfig(instID string) (*config.Config, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cfg, ok := b.configs[instID]
	if !ok {
		return nil, false
	}
	copied := cfg
	return &copied, true
}

// InstanceInfo implements webconsole.Backend.
func (b *webConsoleBackend) InstanceInfo(instIDs []string) map[string]*managepb.NetworkInstanceRunningInfo {
	info := make(map[string]*managepb.NetworkInstanceRunningInfo, len(instIDs))
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, instID := range instIDs {
		cfg, ok := b.configs[instID]
		if !ok {
			continue
		}
		info[instID] = b.describeInstance(cfg, b.names[instID])
	}
	return info
}

// describeInstance reports the live state of one console instance in the
// shape the console renders: the peer list with per-connection statistics, the
// route table, the peer/route pairs and our own node information.
//
// The console shows NaN and empty cells for fields this message does not
// carry, so every field the reference fills is filled here too: the virtual
// IPv4 address, hostname, version, next hop, cost, path latency, the
// connection type (p2p or relay), the round trip time, the loss rate and the
// traffic counters.
func (b *webConsoleBackend) describeInstance(cfg config.Config, name string) *managepb.NetworkInstanceRunningInfo {
	running := &managepb.NetworkInstanceRunningInfo{DevName: devNameFor(cfg, name)}
	item, ok := b.manager.Get(name)
	if !ok {
		return running
	}
	running.Running = true
	managed, ok := item.(*configuredInstance)
	if !ok {
		return running
	}
	node := managed.Node()
	if node == nil {
		return running
	}
	peers := node.PeerManager()
	localPeerID := peers.LocalPeerID()

	// Our own node information: the console shows it as the "local" row.
	running.MyNodeInfo = &managepb.MyNodeInfo{
		VirtualIpv4: ipv4InetFromCIDR(cfg.IPv4),
		Hostname:    cfg.Hostname,
		Version:     b.version,
		PeerId:      localPeerID,
	}
	for _, listener := range cfg.Listeners {
		running.MyNodeInfo.Listeners = append(running.MyNodeInfo.Listeners, &commonpb.Url{Url: listener})
	}

	// Route table: one entry per known peer.
	nextHop := make(map[uint32]uint32)
	cost := make(map[uint32]uint64)
	ospf := node.OSPF()
	var advertisements []route.Advertisement
	if ospf != nil {
		for _, item := range ospf.Table().Snapshot() {
			nextHop[item.Destination] = item.NextHop
			cost[item.Destination] = item.Cost
		}
		advertisements = ospf.Table().Advertisements()
	}

	// Peer list with one connection entry per peer.
	peerInfos := make(map[uint32]*instancepb.PeerInfo, len(advertisements))
	for _, advertisement := range advertisements {
		if advertisement.Origin == localPeerID {
			continue
		}
		hop := nextHop[advertisement.Origin]
		direct := hop == 0 || hop == advertisement.Origin
		latencyPeer := advertisement.Origin
		if !direct {
			latencyPeer = hop
		}
		latencyMS := peers.PeerLatencyMS(latencyPeer)
		lossRate := peers.PeerLossRate(latencyPeer)
		connType := "relay"
		connID := fmt.Sprintf("relay-%d", hop)
		if direct {
			connType = "p2p"
			connID = fmt.Sprintf("p2p-%d", advertisement.Origin)
		}
		info := &instancepb.PeerInfo{PeerId: advertisement.Origin}
		connStats := &instancepb.PeerConnStats{LatencyUs: uint64(maxInt32(latencyMS)) * 1000}
		if session, ok := peers.Peer(advertisement.Origin); ok {
			rxBytes, txBytes, rxPackets, txPackets := session.TrafficStats()
			connStats.RxBytes = rxBytes
			connStats.TxBytes = txBytes
			connStats.RxPackets = rxPackets
			connStats.TxPackets = txPackets
		}
		info.Conns = []*instancepb.PeerConnInfo{{
			ConnId:      connID,
			MyPeerId:    localPeerID,
			PeerId:      advertisement.Origin,
			Tunnel:      &commonpb.TunnelInfo{TunnelType: connType},
			Stats:       connStats,
			LossRate:    float32(maxInt32(lossRate)) / 100,
			NetworkName: cfg.NetworkIdentity.NetworkName,
		}}
		peerInfos[advertisement.Origin] = info
	}

	// Routes and the peer/route pairs the console renders.
	for _, advertisement := range advertisements {
		if advertisement.Origin == localPeerID {
			continue
		}
		hop := nextHop[advertisement.Origin]
		direct := hop == 0 || hop == advertisement.Origin
		latencyPeer := advertisement.Origin
		if !direct {
			latencyPeer = hop
		}
		routeEntry := &instancepb.Route{
			PeerId:        advertisement.Origin,
			Ipv4Addr:      ipv4InetFromCIDR(advertisement.IPv4),
			NextHopPeerId: hop,
			Cost:          int32(cost[advertisement.Origin]),
			PathLatency:   peers.PeerLatencyMS(latencyPeer),
			Hostname:      advertisement.Hostname,
			Version:       advertisement.EasytierVersion,
			ProxyCidrs:    advertisement.ProxyCIDRs,
			// The console's peer table dereferences route.feature_flag
			// directly for every row that has a non-zero cost, so the field
			// must be present even when we do not know the peer's flags;
			// without it the whole table fails to render.
			FeatureFlag: &commonpb.PeerFeatureFlag{},
		}
		running.Routes = append(running.Routes, routeEntry)
		info := peerInfos[advertisement.Origin]
		if info == nil {
			continue
		}
		running.Peers = append(running.Peers, info)
		running.PeerRoutePairs = append(running.PeerRoutePairs, &instancepb.PeerRoutePair{
			Peer:  info,
			Route: routeEntry,
		})
	}
	return running
}

func maxInt32(value int32) int32 {
	if value < 0 {
		return 0
	}
	return value
}

// ipv4InetFromCIDR converts "10.64.0.1/24" into the wire address form.
func ipv4InetFromCIDR(value string) *commonpb.Ipv4Inet {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	prefix, err := netip.ParsePrefix(trimmed)
	if err != nil {
		return nil
	}
	address := prefix.Addr().As4()
	return &commonpb.Ipv4Inet{
		Address: &commonpb.Ipv4Addr{
			Addr: uint32(address[0])<<24 | uint32(address[1])<<16 | uint32(address[2])<<8 | uint32(address[3]),
		},
		NetworkLength: uint32(prefix.Bits()),
	}
}

func devNameFor(cfg config.Config, fallback string) string {
	if cfg.Flags != nil && cfg.Flags.DevName != "" {
		return cfg.Flags.DevName
	}
	return fallback
}

// webConsoleStateDir is where console-delivered instance configs are cached so
// a restart restores the mesh without waiting for the console to push again.
func webConsoleStateDir() string {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "easytier", "webconsole")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", "easytier", "webconsole")
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "easytier", "webconsole")
	}
	return ""
}

func (b *webConsoleBackend) configPath(instID string) string {
	if b.stateDir == "" {
		return ""
	}
	return filepath.Join(b.stateDir, instID+".toml")
}

// persist writes one instance config to the state directory.
func (b *webConsoleBackend) persist(instID string, cfg config.Config) {
	path := b.configPath(instID)
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		b.logf("web console cannot create state dir: %v", err)
		return
	}
	data, err := cfg.Marshal()
	if err != nil {
		b.logf("web console cannot marshal instance %s: %v", instID, err)
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		b.logf("web console cannot persist instance %s: %v", instID, err)
	}
}

// forget removes the cached config of a deleted instance.
func (b *webConsoleBackend) forget(instID string) {
	if path := b.configPath(instID); path != "" {
		_ = os.Remove(path)
	}
}

// Restore replays the cached console instance configs, so a daemon restart
// brings the mesh back even if the console does not push again immediately.
func (b *webConsoleBackend) Restore(ctx context.Context) {
	if b.stateDir == "" {
		return
	}
	entries, err := os.ReadDir(b.stateDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		instID := strings.TrimSuffix(entry.Name(), ".toml")
		data, readErr := os.ReadFile(filepath.Join(b.stateDir, entry.Name()))
		if readErr != nil {
			b.logf("web console cannot read cached instance %s: %v", instID, readErr)
			continue
		}
		cfg, parseErr := config.ParseTOML(data)
		if parseErr != nil {
			b.logf("web console cached instance %s is invalid: %v", instID, parseErr)
			continue
		}
		if runErr := b.RunInstance(ctx, instID, &cfg, false); runErr != nil {
			b.logf("web console cannot restore instance %s: %v", instID, runErr)
		} else {
			b.logf("web console restored instance %s from cache", instID)
		}
	}
}

// watchPeers reports the live peer table of a managed instance, which is the
// only way to observe mesh membership without an RPC portal.
func (b *webConsoleBackend) watchPeers(ctx context.Context, instID, name string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		item, ok := b.manager.Get(name)
		if !ok {
			return
		}
		managed, ok := item.(*configuredInstance)
		if !ok {
			continue
		}
		node := managed.Node()
		if node == nil {
			continue
		}
		peers := node.PeerManager().Peers()
		known := 0
		if ospf := node.OSPF(); ospf != nil {
			known = len(ospf.Table().Advertisements())
		}
		if len(peers) == 0 && known == 0 {
			b.logf("web console instance %s has no peers yet", instID)
			continue
		}
		descriptions := make([]string, 0, len(peers))
		for peerID := range peers {
			descriptions = append(descriptions, fmt.Sprintf("%d(%dms)", peerID, node.PeerManager().PeerLatencyMS(peerID)))
		}
		b.logf("web console instance %s has %d direct peers, %d routed peers: %s (status file %s)",
			instID, len(peers), known, strings.Join(descriptions, " "), statusFilePath())
		b.writeStatusFile(instID, node)
	}
}

// statusFilePath is where the live peer table is published for the LuCI
// dashboard, which cannot use easytier-cli in console mode (no RPC portal).
func statusFilePath() string {
	if path := os.Getenv("ET_CONSOLE_STATUS_FILE"); path != "" {
		return path
	}
	// The dashboard reads a fixed path, so prefer it over the temporary
	// directory: a service manager may not pass the environment through.
	const dashboardPath = "/root/config/easytier/console-status.json"
	if _, err := os.Stat(filepath.Dir(dashboardPath)); err == nil {
		return dashboardPath
	}
	return filepath.Join(os.TempDir(), "easytier-console-status.json")
}

// consolePeerEntry mirrors the peer entry shape the LuCI dashboard reads from
// easytier-cli's JSON output.
type consolePeerEntry struct {
	ID             uint32 `json:"id"`
	Hostname       string `json:"hostname"`
	IPv4           string `json:"ipv4"`
	Version        string `json:"version"`
	LatencyMS      int32  `json:"latency_ms"`
	NextHop        uint32 `json:"next_hop"`
	Cost           uint64 `json:"cost"`
	LossRate       int32  `json:"loss_rate"`
	LatencySamples int    `json:"latency_samples"`
}

// pathLatencyMS reports the latency the way the reference peer table does: a
// directly connected peer shows its own ping round trip, while a relayed peer
// shows the latency of the path that reaches it (the round trip to the next
// hop). The peer itself may answer a ping from a different node on the path,
// so its own ping RTT would report the wrong distance.
func pathLatencyMS(peers *peer.PeerConnectionManager, peerID, nextHop uint32) int32 {
	if nextHop == 0 || nextHop == peerID {
		return peers.PeerLatencyMS(peerID)
	}
	return peers.PeerLatencyMS(nextHop)
}

// writeStatusFile publishes the peer table as JSON. Failures are logged once
// per tick and never affect the instance.
func (b *webConsoleBackend) writeStatusFile(instID string, node *core.Node) {
	path := statusFilePath()
	peers := node.PeerManager()
	ospf := node.OSPF()
	nextHop := make(map[uint32]uint32)
	cost := make(map[uint32]uint64)
	var advertisements []route.Advertisement
	if ospf != nil {
		for _, r := range ospf.Table().Snapshot() {
			nextHop[r.Destination] = r.NextHop
			cost[r.Destination] = r.Cost
		}
		advertisements = ospf.Table().Advertisements()
	}
	entries := make([]consolePeerEntry, 0, len(advertisements))
	seen := make(map[uint32]bool)
	localPeerID := peers.LocalPeerID()
	for _, adv := range advertisements {
		if adv.Origin == localPeerID {
			// Our own advertisement shows up in the table as a second "local"
			// row; the console renders it separately.
			continue
		}
		seen[adv.Origin] = true
		entries = append(entries, consolePeerEntry{
			ID:             adv.Origin,
			Hostname:       adv.Hostname,
			IPv4:           adv.IPv4,
			Version:        adv.EasytierVersion,
			LatencyMS:      pathLatencyMS(peers, adv.Origin, nextHop[adv.Origin]),
			NextHop:        nextHop[adv.Origin],
			Cost:           cost[adv.Origin],
			LossRate:       peers.PeerLossRate(adv.Origin),
			LatencySamples: peers.PeerLatencySamples(adv.Origin),
		})
	}
	for destination := range nextHop {
		if seen[destination] || destination == localPeerID {
			continue
		}
		entries = append(entries, consolePeerEntry{
			ID:      destination,
			NextHop: nextHop[destination],
			Cost:    cost[destination],
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	payload, err := json.Marshal(map[string]any{
		"instance": instID,
		"updated":  time.Now().Unix(),
		"peers":    map[string]any{"peers": entries},
		"routes":   map[string]any{"routes": []any{}},
	})
	if err != nil {
		b.logf("web console cannot marshal status file: %v", err)
		return
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		b.logf("web console cannot write status file: %v", err)
	}
}

// stopInstance stops and unregisters one console instance.
func (b *webConsoleBackend) stopInstance(instID string) error {
	b.mu.Lock()
	name, known := b.names[instID]
	b.mu.Unlock()
	if !known {
		return nil
	}
	var errs []error
	if err := b.manager.Stop(name); err != nil {
		errs = append(errs, err)
	}
	if err := b.manager.Remove(name); err != nil {
		errs = append(errs, err)
	}
	b.mu.Lock()
	delete(b.configs, instID)
	delete(b.names, instID)
	b.mu.Unlock()
	b.forget(instID)
	return errors.Join(errs...)
}

// runWebConsole is the `easytier-core -w <url>` path. It hosts the console
// session, creates instances the console asks for, and keeps running until the
// process context ends. No local configuration is required.
func runWebConsole(ctx context.Context, options options, stdout, stderr io.Writer) int {
	machineID, err := resolveMachineID(options.machineID)
	if err != nil {
		return commandError(stderr, 2, err)
	}
	hostname := strings.TrimSpace(options.hostname)
	if hostname == "" {
		if name, hostErr := os.Hostname(); hostErr == nil {
			hostname = name
		}
	}

	logf := func(format string, args ...any) {
		fmt.Fprintf(stderr, "easytier-core: "+format+"\n", args...)
	}
	manager := instance.NewInstanceManager()
	defer func() { _ = manager.CloseAll() }()
	backend := newWebConsoleBackend(ctx, manager, version, logf)
	backend.Restore(ctx)

	console, err := webconsole.NewConsole(webconsole.Options{
		ServerURL: options.configServer,
		MachineID: machineID,
		Hostname:  hostname,
		Version:   version,
		Backend:   backend,
		Logf:      logf,
		// ET_WEB_NO_NOISE forces the plaintext tunnel; useful when the
		// secure data path is unusable on a link.
		DisableNoise: os.Getenv("ET_WEB_NO_NOISE") != "",
	})
	if err != nil {
		return commandError(stderr, 2, err)
	}
	fmt.Fprintf(stdout, "easytier-core web console client started (server %s, machine %s, hostname %s)\n",
		options.configServer, machineID, hostname)
	if err := console.Run(ctx); err != nil {
		logf("web console client stopped: %v", err)
		return commandError(stderr, 1, err)
	}
	return 0
}

// resolveMachineID mirrors the reference machine-ID rules: an explicit value is
// accepted as a UUID or hashed into one, otherwise a per-machine UUID is
// generated once and persisted under the EasyTier data directory.
func resolveMachineID(explicit string) (string, error) {
	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		if isUUIDText(trimmed) {
			return strings.ToLower(trimmed), nil
		}
		return digestUUID(trimmed), nil
	}
	path, err := machineIDStatePath()
	if err != nil {
		return digestUUID(hostnameOrEmpty()), nil
	}
	if data, readErr := os.ReadFile(path); readErr == nil {
		if text := strings.TrimSpace(string(data)); isUUIDText(text) {
			return strings.ToLower(text), nil
		}
	}
	generated := webconsole.NewMachineID()
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
		return generated, nil
	}
	if writeErr := os.WriteFile(path, []byte(generated+"\n"), 0o600); writeErr != nil {
		return generated, nil
	}
	return generated, nil
}

func machineIDStatePath() (string, error) {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "easytier", "machine_id"), nil
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", "easytier", "machine_id"), nil
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "easytier", "machine_id"), nil
	}
	return "", errors.New("cannot resolve a machine ID state directory")
}

func hostnameOrEmpty() string {
	name, err := os.Hostname()
	if err != nil {
		return "easytier"
	}
	return name
}

func isUUIDText(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, r := range value {
		switch index {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
	}
	return true
}

// digestUUID derives a stable UUID from an arbitrary machine-ID string. The
// reference implementation hashes the text into 16 bytes; any stable
// derivation keeps one console machine identity across restarts, which is what
// the protocol needs, so SHA-256 is used here.
func digestUUID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	var raw16 [16]byte
	copy(raw16[:], sum[:16])
	// Format as an RFC 4122 version-4-shaped UUID for display stability.
	raw16[6] = raw16[6]&0x0f | 0x40
	raw16[8] = raw16[8]&0x3f | 0x80
	return formatUUID(raw16)
}

func formatUUID(raw [16]byte) string {
	buf := make([]byte, 36)
	hexDigits := "0123456789abcdef"
	pos := 0
	for index, value := range raw {
		if index == 4 || index == 6 || index == 8 || index == 10 {
			buf[pos] = '-'
			pos++
		}
		buf[pos] = hexDigits[value>>4]
		buf[pos+1] = hexDigits[value&0x0f]
		pos += 2
	}
	return string(buf)
}

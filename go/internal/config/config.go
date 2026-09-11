// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package config owns the persisted EasyTier configuration contract.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/pelletier/go-toml/v2"
)

// LoadedConfig contains a configuration and the persistence restriction that
// applies to its source. ReadOnly is also true for stdin, which has no file
// that can safely receive a management update.
type LoadedConfig struct {
	Path       string
	Config     Config
	ReadOnly   bool
	Expanded   bool
	Permission ConfigFilePermission
	Control    ConfigFileControl
}

// ConfigFilePermission mirrors Rust config.rs ConfigFilePermission (READ_ONLY|NO_DELETE).
type ConfigFilePermission uint8

const (
	PermissionReadOnly ConfigFilePermission = 1 << 0
	PermissionNoDelete ConfigFilePermission = 1 << 1
)

func (p ConfigFilePermission) HasFlag(flag ConfigFilePermission) bool { return p&flag != 0 }
func (p ConfigFilePermission) WithFlag(flag ConfigFilePermission) ConfigFilePermission { return p | flag }
func (p ConfigFilePermission) RemoveFlag(flag ConfigFilePermission) ConfigFilePermission {
	return p &^ flag
}

// ConfigFileControl mirrors Rust ConfigFileControl.
type ConfigFileControl struct {
	Path       string
	Permission ConfigFilePermission
}

// StaticConfigControl is used for stdin and other non-persistable sources
// (READ_ONLY|NO_DELETE) like Rust ConfigFileControl::STATIC_CONFIG.
var StaticConfigControl = ConfigFileControl{Permission: PermissionReadOnly | PermissionNoDelete}

func (c ConfigFileControl) IsReadOnly() bool { return c.Permission.HasFlag(PermissionReadOnly) }
func (c ConfigFileControl) IsNoDelete() bool { return c.Permission.HasFlag(PermissionNoDelete) }
func (c ConfigFileControl) IsDeletable() bool { return !c.IsNoDelete() }

// Config is the stable TOML shape used by the first Go core vertical slice.
// Additional reference fields are added without changing these field names.
type Config struct {
	NetNS                  string           `toml:"netns"`
	Hostname               string           `toml:"hostname"`
	InstanceName           string           `toml:"instance_name"`
	InstanceID             string           `toml:"instance_id"`
	IPv4                   string           `toml:"ipv4"`
	IPv6                   string           `toml:"ipv6"`
	IPv6PublicAddrProvider bool             `toml:"ipv6_public_addr_provider"`
	IPv6PublicAddrAuto     bool             `toml:"ipv6_public_addr_auto"`
	IPv6PublicAddrPrefix   string           `toml:"ipv6_public_addr_prefix"`
	DHCP                   bool             `toml:"dhcp"`
	NetworkIdentity        NetworkIdentity  `toml:"network_identity"`
	Listeners              []string         `toml:"listeners"`
	MappedListeners        []string         `toml:"mapped_listeners"`
	ExitNodes              []string         `toml:"exit_nodes"`
	Peers                  []Peer           `toml:"peer"`
	ProxyNetworks          []ProxyNetwork   `toml:"proxy_network"`
	VPNPortalConfig        *VPNPortalConfig `toml:"vpn_portal_config"`
	Routes                 []string         `toml:"routes"`
	Socks5Proxy            string           `toml:"socks5_proxy"`
	PortForwards           []PortForward    `toml:"port_forward"`
	SecureMode             *SecureMode      `toml:"secure_mode"`
	Flags                  *Flags           `toml:"flags"`
	ACL                    *ACL             `toml:"acl"`
	TCPWhitelist           []string         `toml:"tcp_whitelist"`
	UDPWhitelist           []string         `toml:"udp_whitelist"`
	STUNServers            []string         `toml:"stun_servers"`
	STUNServersV6          []string         `toml:"stun_servers_v6"`
	CredentialFile         string           `toml:"credential_file"`
	Source                 string           `toml:"source"`
	FileLogger             *FileLoggerConfig `toml:"file_logger"`
	ConsoleLogger          *ConsoleLoggerConfig `toml:"console_logger"`
}

type FileLoggerConfig struct {
	Level   string `toml:"level"`
	Dir     string `toml:"dir"`
	File    string `toml:"file"`
	MaxSize int    `toml:"max_size"`
	MaxCount int   `toml:"max_count"`
}

type ConsoleLoggerConfig struct {
	Level string `toml:"level"`
}

type NetworkIdentity struct {
	NetworkName   string `toml:"network_name"`
	NetworkSecret string `toml:"network_secret"`
}

type Peer struct {
	URI           string `toml:"uri"`
	PeerPublicKey string `toml:"peer_public_key"`
}

// ProxyNetwork is a subnet advertised through this node. MappedCIDR, when
// supplied, translates the advertised network to an equally sized subnet.
type ProxyNetwork struct {
	CIDR       string   `toml:"cidr"`
	MappedCIDR string   `toml:"mapped_cidr"`
	Allow      []string `toml:"allow"`
}

type VPNPortalConfig struct {
	ClientCIDR      string `toml:"client_cidr"`
	WireGuardListen string `toml:"wireguard_listen"`
}

type PortForward struct {
	BindAddr string `toml:"bind_addr"`
	DstAddr  string `toml:"dst_addr"`
	Proto    string `toml:"proto"`
}

type SecureMode struct {
	Enabled         bool   `toml:"enabled"`
	LocalPrivateKey string `toml:"local_private_key"`
	LocalPublicKey  string `toml:"local_public_key"`
}

// Flags contains the supported, typed subset of EasyTier runtime flags.
type Flags struct {
	DefaultProtocol               string `toml:"default_protocol"`
	DevName                       string `toml:"dev_name"`
	EnableEncryption              bool   `toml:"enable_encryption"`
	EnableIPv6                    bool   `toml:"enable_ipv6"`
	MTU                           uint32 `toml:"mtu"`
	LatencyFirst                  bool   `toml:"latency_first"`
	EnableExitNode                bool   `toml:"enable_exit_node"`
	ProxyForwardBySystem          bool   `toml:"proxy_forward_by_system"`
	NoTUN                         bool   `toml:"no_tun"`
	UseSmoltcp                    bool   `toml:"use_smoltcp"`
	RelayNetworkWhitelist         string `toml:"relay_network_whitelist"`
	DisableP2P                    bool   `toml:"disable_p2p"`
	P2POnly                       bool   `toml:"p2p_only"`
	LazyP2P                       bool   `toml:"lazy_p2p"`
	RelayAllPeerRPC               bool   `toml:"relay_all_peer_rpc"`
	DisableTCPHolePunching        bool   `toml:"disable_tcp_hole_punching"`
	DisableUDPHolePunching        bool   `toml:"disable_udp_hole_punching"`
	MultiThread                   bool   `toml:"multi_thread"`
	DataCompressAlgo              string `toml:"data_compress_algo"`
	BindDevice                    bool   `toml:"bind_device"`
	EnableKCPProxy                bool   `toml:"enable_kcp_proxy"`
	DisableKCPInput               bool   `toml:"disable_kcp_input"`
	DisableRelayKCP               bool   `toml:"disable_relay_kcp"`
	EnableRelayForeignNetworkKCP  bool   `toml:"enable_relay_foreign_network_kcp"`
	AcceptDNS                     bool   `toml:"accept_dns"`
	PrivateMode                   bool   `toml:"private_mode"`
	EnableQUICProxy               bool   `toml:"enable_quic_proxy"`
	DisableQUICInput              bool   `toml:"disable_quic_input"`
	DisableRelayQUIC              bool   `toml:"disable_relay_quic"`
	EnableRelayForeignNetworkQUIC bool   `toml:"enable_relay_foreign_network_quic"`
	ForeignRelayBPSLimit          uint64 `toml:"foreign_relay_bps_limit"`
	MultiThreadCount              uint32 `toml:"multi_thread_count"`
	EncryptionAlgorithm           string `toml:"encryption_algorithm"`
	DisableSymHolePunching        bool   `toml:"disable_sym_hole_punching"`
	TLDDNSZone                    string `toml:"tld_dns_zone"`
	NeedP2P                       bool   `toml:"need_p2p"`
	InstanceRecvBPSLimit          uint64 `toml:"instance_recv_bps_limit"`
	DisableUPnP                   bool   `toml:"disable_upnp"`
	DisableRelayData              bool   `toml:"disable_relay_data"`
	EnableUDPBroadcastRelay       bool   `toml:"enable_udp_broadcast_relay"`
	QuicListenPort                uint32 `toml:"quic_listen_port"`
}

func DefaultFlags() Flags {
	return Flags{
		DefaultProtocol:               "tcp",
		DevName:                       "",
		EnableEncryption:              true,
		EnableIPv6:                    true,
		MTU:                           1380,
		LatencyFirst:                  false,
		EnableExitNode:                false,
		ProxyForwardBySystem:          false,
		NoTUN:                         false,
		UseSmoltcp:                    false,
		RelayNetworkWhitelist:         "*",
		DisableP2P:                    false,
		P2POnly:                       false,
		LazyP2P:                       false,
		RelayAllPeerRPC:               false,
		DisableTCPHolePunching:        false,
		DisableUDPHolePunching:        false,
		MultiThread:                   true,
		DataCompressAlgo:              "none",
		BindDevice:                    true,
		EnableKCPProxy:                false,
		DisableKCPInput:               false,
		DisableRelayKCP:               false,
		EnableRelayForeignNetworkKCP:  false,
		AcceptDNS:                     false,
		PrivateMode:                   false,
		EnableQUICProxy:               false,
		DisableQUICInput:              false,
		DisableRelayQUIC:              false,
		EnableRelayForeignNetworkQUIC: false,
		ForeignRelayBPSLimit:          ^uint64(0),
		MultiThreadCount:              2,
		EncryptionAlgorithm:           "aes-gcm",
		DisableSymHolePunching:        false,
		TLDDNSZone:                    "et.net",
		NeedP2P:                       false,
		InstanceRecvBPSLimit:          ^uint64(0),
		DisableUPnP:                   false,
		DisableRelayData:              false,
		EnableUDPBroadcastRelay:       false,
		QuicListenPort:                ^uint32(0),
	}
}

var defaultSTUNServers = []string{
	"txt:stun.easytier.cn",
	"stun.miwifi.com",
	"stun.chat.bilibili.com",
	"stun.hitv.com",
}
var defaultSTUNServersV6 = []string{"txt:stun-v6.easytier.cn"}

type ACL struct {
	ACLV1 *ACLV1 `toml:"acl_v1"`
}

type ACLV1 struct {
	Chains []ACLChain `toml:"chains"`
	Group  *ACLGroup  `toml:"group"`
}

type ACLGroup struct {
	Declares []ACLGroupIdentity `toml:"declares"`
	Members  []string           `toml:"members"`
}

type ACLGroupIdentity struct {
	GroupName   string `toml:"group_name"`
	GroupSecret string `toml:"group_secret"`
}

type ACLChain struct {
	Name          string    `toml:"name"`
	ChainType     int       `toml:"chain_type"`
	Description   string    `toml:"description"`
	Enabled       bool      `toml:"enabled"`
	DefaultAction int       `toml:"default_action"`
	Rules         []ACLRule `toml:"rules"`
}

type ACLRule struct {
	Name              string   `toml:"name"`
	Description       string   `toml:"description"`
	Priority          uint32   `toml:"priority"`
	Enabled           bool     `toml:"enabled"`
	Protocol          int      `toml:"protocol"`
	Ports             []string `toml:"ports"`
	SourceIPs         []string `toml:"source_ips"`
	DestinationIPs    []string `toml:"destination_ips"`
	SourcePorts       []string `toml:"source_ports"`
	Action            int      `toml:"action"`
	RateLimit         uint32   `toml:"rate_limit"`
	BurstLimit        uint32   `toml:"burst_limit"`
	Stateful          bool     `toml:"stateful"`
	SourceGroups      []string `toml:"source_groups"`
	DestinationGroups []string `toml:"destination_groups"`
}

// Load reads, optionally expands environment references, and validates TOML.
// Expanded files are marked read-only so management APIs cannot persist secrets
// that were supplied from the environment.
func Load(path string, disableEnvironmentParsing bool) (Config, bool, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return Config{}, true, fmt.Errorf("read config from stdin: %w", err)
		}
		cfg, _, err := parse("stdin", data, true)
		return cfg, true, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, false, fmt.Errorf("read config %q: %w", path, err)
	}
	return parse(path, data, disableEnvironmentParsing)
}

// LoadSources loads explicit config files followed by direct .toml files in
// directory. Directory entries are sorted so startup and validation are
// deterministic. A source of "-" reads stdin.
func LoadSources(paths []string, directory string, disableEnvironmentParsing bool) ([]LoadedConfig, error) {
	files := append([]string(nil), paths...)
	if directory != "" {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, fmt.Errorf("read config directory %q: %w", directory, err)
		}
		var directoryFiles []string
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".toml" {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if info.Mode().IsRegular() {
				directoryFiles = append(directoryFiles, path)
			}
		}
		sort.Strings(directoryFiles)
		files = append(files, directoryFiles...)
	}

	loaded := make([]LoadedConfig, 0, len(files))
	for _, path := range files {
		cfg, wasExpanded, err := Load(path, disableEnvironmentParsing)
		if err != nil {
			return nil, err
		}
		expanded := path != "-" && !disableEnvironmentParsing && wasExpanded
		var perm ConfigFilePermission
		var ctrl ConfigFileControl
		if path == "-" {
			perm = PermissionReadOnly | PermissionNoDelete
			ctrl = ConfigFileControl{Path: "", Permission: perm}
		} else {
			isReadOnly := isFileReadOnly(path)
			if isReadOnly {
				perm = perm.WithFlag(PermissionReadOnly)
			}
			if wasExpanded {
				perm = perm.WithFlag(PermissionReadOnly).WithFlag(PermissionNoDelete)
			} else if perm.HasFlag(PermissionReadOnly) {
				perm = perm.WithFlag(PermissionNoDelete)
			} else if directory != "" {
				parent := filepath.Clean(filepath.Dir(path))
				cleanDir := filepath.Clean(directory)
				ext := filepath.Ext(path)
				stem := strings.TrimSuffix(filepath.Base(path), ext)
				if parent == cleanDir && ext == ".toml" && cfg.InstanceID != "" && stem == cfg.InstanceID {
					// deletable: keep NO_DELETE off
				} else {
					perm = perm.WithFlag(PermissionNoDelete)
				}
			} else {
				perm = perm.WithFlag(PermissionNoDelete)
			}
			ctrl = ConfigFileControl{Path: path, Permission: perm}
		}
		loaded = append(loaded, LoadedConfig{
			Path:       path,
			Config:     cfg,
			ReadOnly:   perm.HasFlag(PermissionReadOnly),
			Expanded:   expanded,
			Permission: perm,
			Control:    ctrl,
		})
	}
	return loaded, nil
}

func isFileReadOnly(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return info.Mode().Perm()&0200 == 0
}

func parse(source string, data []byte, disableEnvironmentParsing bool) (Config, bool, error) {
	text := string(data)
	wasExpanded := false
	if !disableEnvironmentParsing {
		text, wasExpanded = expandEnvironment(text)
	}

	var cfg Config
	if err := toml.Unmarshal([]byte(text), &cfg); err != nil {
		return Config{}, false, fmt.Errorf("parse config %q: %w", source, err)
	}
	// Normalize hostname (filter control, take 32) like Rust get_hostname
	if cfg.Hostname != "" {
		filtered := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, cfg.Hostname)
		if len(filtered) > 32 {
			filtered = filtered[:32]
		}
		cfg.Hostname = filtered
	}
	// Normalize source: User -> None (empty string)
	if cfg.Source == "user" || cfg.Source == "User" {
		cfg.Source = ""
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, false, fmt.Errorf("validate config %q: %w", source, err)
	}
	return cfg, wasExpanded, nil
}

// Marshal serializes the configuration in TOML form.
func (c Config) Marshal() ([]byte, error) {
	return toml.Marshal(c)
}

// Dump returns the canonical pretty TOML like Rust's dump(): only non-default flags, normalized source, omitted default stun.
func (c Config) Dump() (string, error) {
	// Deep copy via Marshal/Unmarshal to avoid mutating original
	clone, err := c.Clone()
	if err != nil {
		return "", err
	}
	// Normalize source
	if clone.Source == "user" || clone.Source == "User" {
		clone.Source = ""
	}
	// Flags: only non-default
	if clone.Flags != nil {
		def := DefaultFlags()
		defJson, _ := json.Marshal(def)
		curJson, _ := json.Marshal(*clone.Flags)
		var defMap map[string]json.RawMessage
		var curMap map[string]json.RawMessage
		_ = json.Unmarshal(defJson, &defMap)
		_ = json.Unmarshal(curJson, &curMap)
		nonDefault := make(map[string]json.RawMessage)
		for k, v := range curMap {
			if dv, ok := defMap[k]; !ok || string(dv) != string(v) {
				nonDefault[k] = v
			}
		}
		if len(nonDefault) == 0 {
			clone.Flags = nil
		} else {
			// Reconstruct Flags from nonDefault via JSON
			b, _ := json.Marshal(nonDefault)
			var f Flags
			_ = json.Unmarshal(b, &f)
			// Preserve only non-default fields by clearing the rest? Instead we set Flags to a struct that will marshal only those keys via custom logic.
			// For simplicity, we keep Flags as filtered map and marshal via intermediate struct.
			// We will marshal Config with Flags as map, so we need to handle via RawMessage.
			// Instead, we use a trick: marshal Config to map, replace flags, then marshal to TOML
			clone.Flags = &f
			// If we want truly only non-default keys, we need to use map approach for TOML.
			// For now, we keep the filtered struct; its zero values will still be omitted only if we use omitempty via custom marshal.
			// To achieve Rust-like behavior, we will handle flags separately in the final TOML generation.
		}
	}
	// Stun default omission
	if equalStringSlices(clone.STUNServers, defaultSTUNServers) {
		clone.STUNServers = nil
	}
	if equalStringSlices(clone.STUNServersV6, defaultSTUNServersV6) {
		clone.STUNServersV6 = nil
	}
	// Use custom marshal that omits defaults: we marshal to map then clean
	// For simplicity, just use toml.Marshal and then post-process: if Flags was nil, it will be omitted; if not nil, it will emit all fields, but we want only non-default.
	// To get correct behavior, we manually build a map for flags.
	if clone.Flags != nil {
		// Re-marshal Config to map, replace flags with filtered map
		cfgMap := make(map[string]any)
		b, _ := toml.Marshal(clone)
		_ = toml.Unmarshal(b, &cfgMap)
		// Build filtered flags map
		def := DefaultFlags()
		defJson, _ := json.Marshal(def)
		curJson, _ := json.Marshal(*clone.Flags)
		var defMap2 map[string]json.RawMessage
		var curMap2 map[string]json.RawMessage
		_ = json.Unmarshal(defJson, &defMap2)
		_ = json.Unmarshal(curJson, &curMap2)
		filtered := make(map[string]any)
		for k, v := range curMap2 {
			if dv, ok := defMap2[k]; !ok || string(dv) != string(v) {
				var val any
				_ = json.Unmarshal(v, &val)
				filtered[k] = val
			}
		}
		if len(filtered) == 0 {
			delete(cfgMap, "flags")
		} else {
			cfgMap["flags"] = filtered
		}
		if len(filtered) == 0 && clone.Flags != nil {
			// ensure flags omitted
		}
		// Re-marshal the map
		out, err := toml.Marshal(cfgMap)
		if err != nil {
			return "", err
		}
		// Handle source omission
		if clone.Source == "" {
			// Remove source key if empty
			var m map[string]any
			_ = toml.Unmarshal(out, &m)
			delete(m, "source")
			out, _ = toml.Marshal(m)
		}
		return string(out), nil
	}
	out, err := toml.Marshal(clone)
	if err != nil {
		return "", err
	}
	// Remove source if empty
	if clone.Source == "" {
		var m map[string]any
		_ = toml.Unmarshal(out, &m)
		if _, ok := m["source"]; ok {
			delete(m, "source")
			out, _ = toml.Marshal(m)
		}
	}
	return string(out), nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Clone returns an independent configuration snapshot without applying
// validation. Callers that accept external configuration should validate it
// separately; preserving the clone operation's shape is useful for immutable
// management snapshots.
func (c Config) Clone() (Config, error) {
	data, err := c.Marshal()
	if err != nil {
		return Config{}, err
	}
	var clone Config
	if err := toml.Unmarshal(data, &clone); err != nil {
		return Config{}, err
	}
	return clone, nil
}

// ParseTOML parses and validates a configuration supplied by a management
// caller. Environment expansion is deliberately not performed here: a
// remotely supplied configuration must be explicit and is safe to persist.
func ParseTOML(data []byte) (Config, error) {
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse TOML configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate TOML configuration: %w", err)
	}
	return cfg, nil
}

func expandEnvironment(text string) (string, bool) {
	var result strings.Builder
	result.Grow(len(text))
	expanded := false

	for i := 0; i < len(text); {
		if text[i] != '$' {
			result.WriteByte(text[i])
			i++
			continue
		}
		if i+1 < len(text) && text[i+1] == '$' {
			result.WriteByte('$')
			expanded = true
			i += 2
			continue
		}

		// Braced form: ${VAR} or ${VAR:-default}
		if i+1 < len(text) && text[i+1] == '{' {
			end := strings.IndexByte(text[i+2:], '}')
			if end < 0 {
				return text, false
			}
			end += i + 2
			body := text[i+2 : end]

			var name string
			var defaultValue string
			hasDefault := false
			if marker := strings.Index(body, ":-"); marker >= 0 {
				name = body[:marker]
				defaultValue = body[marker+2:]
				hasDefault = true
			} else {
				name = body
			}
			if !validEnvironmentName(name) {
				return text, false
			}
			value, ok := os.LookupEnv(name)
			if !ok || (hasDefault && value == "") {
				if !hasDefault {
					return text, false
				}
				value = defaultValue
			}
			result.WriteString(value)
			expanded = true
			i = end + 1
			continue
		}

		if i+1 >= len(text) || !isEnvironmentNameStart(text[i+1]) {
			result.WriteByte('$')
			i++
			continue
		}
		nameEnd := i + 1
		for nameEnd < len(text) && isEnvironmentNamePart(text[nameEnd]) {
			nameEnd++
		}
		name := text[i+1 : nameEnd]
		value, ok := os.LookupEnv(name)
		if !ok {
			return text, false
		}
		result.WriteString(value)
		expanded = true
		i = nameEnd
	}
	return result.String(), expanded
}

func validEnvironmentName(name string) bool {
	if name == "" || !isEnvironmentNameStart(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isEnvironmentNamePart(name[i]) {
			return false
		}
	}
	return true
}

func isEnvironmentNameStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isEnvironmentNamePart(value byte) bool {
	return isEnvironmentNameStart(value) || value >= '0' && value <= '9'
}

// ValidateMappedListenerURL validates a mapped listener URL, mirroring Rust's validate_mapped_listener_url.
// It allows implicit port for IP-based schemes (tcp/udp/ws/wss/wg/quic/faketcp).
func ValidateMappedListenerURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("mapped listener url is empty")
	}
	endpoint, err := ParseEndpoint(raw)
	if err != nil {
		// For endpoints like ring:// that require host check, use url.Parse fallback for better error
		// But we want to match Rust: only port missing is error for non-IP schemes.
		// If ParseEndpoint fails due to missing port for ws/wss etc, it still succeeds because default port is applied.
		// So we need to distinguish: if scheme is ws/wss/tcp etc with no explicit port, ParseEndpoint will succeed due to defaults.
		// That's valid per Rust.
		// If scheme is unknown like ring, ParseEndpoint will error; we surface that.
		return fmt.Errorf("mapped listener is invalid: %w", err)
	}
	// Allow any endpoint that parsed; but ensure host is present
	if endpoint.Host == "" {
		return fmt.Errorf("mapped listener host is missing: %q", raw)
	}
	return nil
}

// Validate enforces constraints that are required before an instance can bind
// sockets or create an overlay interface.
func (c Config) Validate() error {
	if c.NetworkIdentity.NetworkName == "" {
		return fmt.Errorf("network_identity.network_name is required")
	}
	if c.IPv4 != "" {
		address := c.IPv4
		if !strings.Contains(address, "/") {
			address += "/24"
		}
		prefix, err := netip.ParsePrefix(address)
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("ipv4 must be an IPv4 address or CIDR: %q", c.IPv4)
		}
	}
	if c.IPv6 != "" {
		prefix, err := netip.ParsePrefix(c.IPv6)
		if err != nil || !prefix.Addr().Is6() {
			return fmt.Errorf("ipv6 must be an IPv6 CIDR: %q", c.IPv6)
		}
	}
	if c.IPv6PublicAddrPrefix != "" {
		prefix, err := netip.ParsePrefix(c.IPv6PublicAddrPrefix)
		if err != nil || !prefix.Addr().Is6() {
			return fmt.Errorf("ipv6_public_addr_prefix must be an IPv6 CIDR: %q", c.IPv6PublicAddrPrefix)
		}
	}
	if len(c.Listeners) > 0 {
		if _, err := c.NormalizedListeners(); err != nil {
			return fmt.Errorf("listeners are invalid: %w", err)
		}
	}
	for _, peer := range c.Peers {
		if peer.URI == "" {
			return fmt.Errorf("peer.uri is required")
		}
		if _, err := ParseEndpoint(peer.URI); err != nil {
			return fmt.Errorf("peer.uri is invalid: %q", peer.URI)
		}
	}
	for _, network := range c.ProxyNetworks {
		if err := validateCIDR("proxy_network.cidr", network.CIDR); err != nil {
			return err
		}
		if network.MappedCIDR != "" {
			if err := validateCIDR("proxy_network.mapped_cidr", network.MappedCIDR); err != nil {
				return err
			}
			// Rust checks that mapped_cidr has same prefix length
			c1, _ := netip.ParsePrefix(network.CIDR)
			c2, _ := netip.ParsePrefix(network.MappedCIDR)
			if c1.Bits() != c2.Bits() {
				return fmt.Errorf("proxy_network.mapped_cidr network length must equal cidr: %q vs %q", network.CIDR, network.MappedCIDR)
			}
		}
	}
	for _, route := range c.Routes {
		if err := validateCIDR("routes", route); err != nil {
			return err
		}
	}
	if c.Flags != nil {
		switch c.Flags.DataCompressAlgo {
		case "", "none", "zstd":
		default:
			return fmt.Errorf("flags.data_compress_algo must be one of: none, zstd")
		}
		if err := validateRelayWhitelist(c.Flags.RelayNetworkWhitelist); err != nil {
			return err
		}
		if len(c.Flags.RelayNetworkWhitelist) > 4096 {
			return fmt.Errorf("flags.relay_network_whitelist is too long")
		}
	}
	for _, ml := range c.MappedListeners {
		if err := ValidateMappedListenerURL(ml); err != nil {
			return fmt.Errorf("mapped_listeners is invalid: %w", err)
		}
	}
	// Hostname already normalized in parse, but validate again
	if c.Hostname != "" {
		for _, r := range c.Hostname {
			if unicode.IsControl(r) {
				return fmt.Errorf("hostname contains control character")
			}
		}
		if len(c.Hostname) > 32 {
			return fmt.Errorf("hostname must be at most 32 characters")
		}
	}
	return nil
}

func validateRelayWhitelist(whitelist string) error {
	whitelist = strings.TrimSpace(whitelist)
	if whitelist == "" || whitelist == "*" {
		return nil
	}
	// Split by whitespace/comma/semicolon like policy
	fields := strings.FieldsFunc(whitelist, func(r rune) bool { return r == ' ' || r == ',' || r == ';' })
	for _, pat := range fields {
		if pat == "" {
			continue
		}
		if strings.Contains(pat, "\x00") {
			return fmt.Errorf("flags.relay_network_whitelist contains null byte")
		}
		for _, r := range pat {
			if unicode.IsControl(r) {
				return fmt.Errorf("flags.relay_network_whitelist contains control character")
			}
		}
		// Validate pattern syntax via filepath.Match with dummy string
		if _, err := filepath.Match(pat, "test"); err != nil {
			return fmt.Errorf("flags.relay_network_whitelist pattern %q is invalid: %w", pat, err)
		}
		if len(pat) > 256 {
			return fmt.Errorf("flags.relay_network_whitelist pattern %q is too long", pat)
		}
	}
	return nil
}

func validateCIDR(field, value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.IsValid() {
		return fmt.Errorf("%s must be an IPv4 or IPv6 CIDR: %q", field, value)
	}
	return nil
}

// IPv4Prefix returns the configured IPv4 address with the reference /24
// default applied when an address omits its prefix length.
func (c Config) IPv4Prefix() (netip.Prefix, bool, error) {
	if c.IPv4 == "" {
		return netip.Prefix{}, false, nil
	}
	address := c.IPv4
	if !strings.Contains(address, "/") {
		address += "/24"
	}
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return netip.Prefix{}, false, err
	}
	return prefix, true, nil
}

// NormalizedListeners applies EasyTier listener expansion using the configured
// default protocol. The reference's default protocol is TCP when flags are
// absent.
func (c Config) NormalizedListeners() ([]Endpoint, error) {
	defaultProtocol := "tcp"
	if c.Flags != nil && c.Flags.DefaultProtocol != "" {
		defaultProtocol = c.Flags.DefaultProtocol
	}
	return NormalizeListeners(c.Listeners, defaultProtocol)
}

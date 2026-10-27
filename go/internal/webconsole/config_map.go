// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webconsole

import (
	"crypto/rand"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/EasyTier/EasyTier/go/internal/config"
	aclpb "github.com/EasyTier/EasyTier/go/internal/proto/acl"
	managepb "github.com/EasyTier/EasyTier/go/internal/proto/api_manage"
	commonpb "github.com/EasyTier/EasyTier/go/internal/proto/common"
	gproto "google.golang.org/protobuf/proto"
)

// defaultNetworkLength is the prefix length assumed when a console config
// supplies a bare address (no "/length") for an IPv4 network.
const defaultNetworkLength = 24

// NetworkConfigToConfig converts a console NetworkConfig into the local
// config.Config used by the core.
//
// Fields the console cannot express (netns, STUN server lists, TCP/UDP
// whitelists, logger sections, source) are left at their zero value and must
// be filled by the caller that owns the local file. The deprecated
// quic_listen_port and the UI-only advanced_settings hint are deliberately
// ignored: the former has no active console equivalent and the latter only
// drives the console's own form rendering.
func NetworkConfigToConfig(nc *managepb.NetworkConfig) (*config.Config, error) {
	if nc == nil {
		return nil, fmt.Errorf("network config is nil")
	}

	cfg := &config.Config{}

	instanceID := strings.TrimSpace(nc.GetInstanceId())
	if instanceID == "" {
		generated, err := newInstanceUUID()
		if err != nil {
			return nil, err
		}
		instanceID = generated
	}
	cfg.InstanceID = instanceID
	cfg.Hostname = nc.GetHostname()
	cfg.DHCP = nc.GetDhcp()
	networkName := nc.GetNetworkName()
	cfg.InstanceName = networkName

	// Credential mode: the console sends no network secret but pins a node
	// identity private key, which selects the credential-based identity path.
	credentialMode := false
	if nc.NetworkSecret == nil {
		if secure := nc.GetSecureMode(); secure.GetLocalPrivateKey() != "" {
			credentialMode = true
		}
	}
	if credentialMode {
		cfg.NetworkIdentity = config.NetworkIdentity{NetworkName: networkName}
		cfg.SecureMode = &config.SecureMode{
			Enabled:         true,
			LocalPrivateKey: nc.GetSecureMode().GetLocalPrivateKey(),
		}
	} else {
		cfg.NetworkIdentity = config.NetworkIdentity{
			NetworkName:   networkName,
			NetworkSecret: nc.GetNetworkSecret(),
		}
	}

	if !cfg.DHCP {
		virtualIPv4 := strings.TrimSpace(nc.GetVirtualIpv4())
		if virtualIPv4 != "" {
			cidr := withPrefixLength(virtualIPv4, int(nc.GetNetworkLength()), 32)
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil || !prefix.Addr().Is4() {
				return nil, fmt.Errorf("virtual_ipv4 %q is not an IPv4 address: %v", virtualIPv4, err)
			}
			cfg.IPv4 = cidr
		}
	}

	peers, err := peersFromNetworkingMethod(nc)
	if err != nil {
		return nil, err
	}
	cfg.Peers = peers

	cfg.Listeners = nonEmptyStrings(nc.GetListenerUrls())

	for _, raw := range nc.GetProxyCidrs() {
		cidr := strings.TrimSpace(raw)
		if cidr == "" {
			continue
		}
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return nil, fmt.Errorf("proxy_cidrs entry %q is not a CIDR: %v", raw, err)
		}
		cfg.ProxyNetworks = append(cfg.ProxyNetworks, config.ProxyNetwork{CIDR: cidr})
	}

	for _, forward := range nc.GetPortForwards() {
		if forward == nil || forward.GetBindIp() == "" || forward.GetDstIp() == "" {
			// The console form allows half-filled rows; those are not useful
			// to the core, so they are dropped instead of failing the whole
			// configuration.
			continue
		}
		cfg.PortForwards = append(cfg.PortForwards, config.PortForward{
			BindAddr: net.JoinHostPort(forward.GetBindIp(), strconv.FormatUint(uint64(forward.GetBindPort()), 10)),
			DstAddr:  net.JoinHostPort(forward.GetDstIp(), strconv.FormatUint(uint64(forward.GetDstPort()), 10)),
			Proto:    forward.GetProto(),
		})
	}

	if nc.GetEnableVpnPortal() {
		portal := &config.VPNPortalConfig{
			WireGuardListen: "0.0.0.0:" + strconv.FormatInt(int64(nc.GetVpnPortalListenPort()), 10),
		}
		addr := strings.TrimSpace(nc.GetVpnPortalClientNetworkAddr())
		if addr != "" {
			cidr := withPrefixLength(addr, int(nc.GetVpnPortalClientNetworkLen()), 128)
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return nil, fmt.Errorf("vpn_portal_client_network_addr %q is not a CIDR: %v", addr, err)
			}
			portal.ClientCIDR = cidr
		}
		cfg.VPNPortalConfig = portal
	}

	if nc.GetEnableManualRoutes() {
		for _, raw := range nc.GetRoutes() {
			route := strings.TrimSpace(raw)
			if route == "" {
				continue
			}
			if _, err := netip.ParsePrefix(route); err != nil {
				return nil, fmt.Errorf("routes entry %q is not a CIDR: %v", raw, err)
			}
			cfg.Routes = append(cfg.Routes, route)
		}
	}

	for _, raw := range nc.GetExitNodes() {
		node := strings.TrimSpace(raw)
		if node == "" {
			continue
		}
		if _, err := netip.ParseAddr(node); err != nil {
			return nil, fmt.Errorf("exit_nodes entry %q is not an IP address: %v", raw, err)
		}
		cfg.ExitNodes = append(cfg.ExitNodes, node)
	}

	if nc.GetEnableSocks5() && nc.Socks5Port != nil {
		cfg.Socks5Proxy = "socks5://0.0.0.0:" + strconv.FormatInt(int64(nc.GetSocks5Port()), 10)
	}

	cfg.MappedListeners = nonEmptyStrings(nc.GetMappedListeners())

	if file := strings.TrimSpace(nc.GetCredentialFile()); file != "" {
		cfg.CredentialFile = file
	}

	if !credentialMode {
		if secure := nc.GetSecureMode(); secure != nil {
			cfg.SecureMode = &config.SecureMode{
				Enabled:         secure.GetEnabled(),
				LocalPrivateKey: secure.GetLocalPrivateKey(),
				LocalPublicKey:  secure.GetLocalPublicKey(),
			}
		}
	}

	cfg.IPv6PublicAddrProvider = nc.GetIpv6PublicAddrProvider()
	cfg.IPv6PublicAddrAuto = nc.GetIpv6PublicAddrAuto()
	cfg.IPv6PublicAddrPrefix = nc.GetIpv6PublicAddrPrefix()

	if acl := aclToConfig(nc.GetAcl()); acl != nil {
		cfg.ACL = acl
	}

	cfg.Flags = flagsFromNetworkConfig(nc)

	return cfg, nil
}

// ConfigToNetworkConfig converts a local config.Config back into a console
// NetworkConfig. It is the best-effort inverse of NetworkConfigToConfig: local
// options the console has no field for (netns, STUN lists, logger sections,
// port-forward mappings, proxy_network allow lists) are not representable and
// are dropped.
func ConfigToNetworkConfig(instID string, cfg *config.Config) *managepb.NetworkConfig {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if instID == "" {
		instID = cfg.InstanceID
	}

	nc := &managepb.NetworkConfig{
		InstanceId:  gproto.String(instID),
		Hostname:    gproto.String(cfg.Hostname),
		Dhcp:        gproto.Bool(cfg.DHCP),
		NetworkName: gproto.String(cfg.NetworkIdentity.NetworkName),
	}
	if cfg.NetworkIdentity.NetworkSecret != "" {
		nc.NetworkSecret = gproto.String(cfg.NetworkIdentity.NetworkSecret)
	}

	if err := applyIPv4ToNetworkConfig(nc, cfg.IPv4); err != nil {
		// A malformed local ipv4 is surfaced by the console as an address the
		// user has to fix; keep the raw value so the form can show it.
		nc.VirtualIpv4 = gproto.String(cfg.IPv4)
	}

	if len(cfg.Peers) > 0 {
		method := managepb.NetworkingMethod_Manual
		nc.NetworkingMethod = &method
		for _, peer := range cfg.Peers {
			if peer.URI != "" {
				nc.PeerUrls = append(nc.PeerUrls, peer.URI)
			}
		}
	} else {
		method := managepb.NetworkingMethod_Standalone
		nc.NetworkingMethod = &method
	}

	nc.ListenerUrls = append([]string(nil), cfg.Listeners...)

	for _, network := range cfg.ProxyNetworks {
		if network.CIDR != "" {
			nc.ProxyCidrs = append(nc.ProxyCidrs, network.CIDR)
		}
	}

	for _, forward := range cfg.PortForwards {
		converted := portForwardToNetworkConfig(forward)
		if converted != nil {
			nc.PortForwards = append(nc.PortForwards, converted)
		}
	}

	applyVPNPortalToNetworkConfig(nc, cfg.VPNPortalConfig)

	if len(cfg.Routes) > 0 {
		nc.EnableManualRoutes = gproto.Bool(true)
		nc.Routes = append([]string(nil), cfg.Routes...)
	}
	if len(cfg.ExitNodes) > 0 {
		nc.ExitNodes = append([]string(nil), cfg.ExitNodes...)
	}

	if cfg.Socks5Proxy != "" {
		nc.EnableSocks5 = gproto.Bool(true)
		if parsed, err := url.Parse(cfg.Socks5Proxy); err == nil {
			if port, err := strconv.ParseUint(parsed.Port(), 10, 32); err == nil {
				nc.Socks5Port = gproto.Int32(int32(port))
			}
		}
	}

	if len(cfg.MappedListeners) > 0 {
		nc.MappedListeners = append([]string(nil), cfg.MappedListeners...)
	}
	if cfg.CredentialFile != "" {
		nc.CredentialFile = gproto.String(cfg.CredentialFile)
	}

	if cfg.SecureMode != nil {
		secure := &commonpb.SecureModeConfig{Enabled: cfg.SecureMode.Enabled}
		if cfg.SecureMode.LocalPrivateKey != "" {
			secure.LocalPrivateKey = gproto.String(cfg.SecureMode.LocalPrivateKey)
		}
		if cfg.SecureMode.LocalPublicKey != "" {
			secure.LocalPublicKey = gproto.String(cfg.SecureMode.LocalPublicKey)
		}
		nc.SecureMode = secure
	}

	if cfg.IPv6PublicAddrProvider {
		nc.Ipv6PublicAddrProvider = gproto.Bool(true)
	}
	if cfg.IPv6PublicAddrAuto {
		nc.Ipv6PublicAddrAuto = gproto.Bool(true)
	}
	if cfg.IPv6PublicAddrPrefix != "" {
		nc.Ipv6PublicAddrPrefix = gproto.String(cfg.IPv6PublicAddrPrefix)
	}

	if acl := configACLToProto(cfg.ACL); acl != nil {
		nc.Acl = acl
	}

	applyFlagsToNetworkConfig(nc, cfg.Flags)

	return nc
}

// ValidateNetworkConfig renders the TOML a console ValidateConfig call returns.
//
// The text is produced with config.Config.Marshal, the serializer the management
// ConfigGet path also uses, so the console previews exactly what the core would
// persist for this network.
func ValidateNetworkConfig(nc *managepb.NetworkConfig) (string, error) {
	cfg, err := NetworkConfigToConfig(nc)
	if err != nil {
		return "", err
	}
	// TOML integers are signed 64-bit, so the ^uint64(0) "unlimited" sentinel the
	// flags use for the BPS limits cannot be encoded. Clamp it to the largest
	// representable value: the flag keeps its meaning (no practical limit) and
	// the text still re-parses into config.Config.
	if cfg.Flags != nil {
		flags := *cfg.Flags
		if flags.InstanceRecvBPSLimit == ^uint64(0) {
			flags.InstanceRecvBPSLimit = uint64(math.MaxInt64)
		}
		if flags.ForeignRelayBPSLimit == ^uint64(0) {
			flags.ForeignRelayBPSLimit = uint64(math.MaxInt64)
		}
		cfg.Flags = &flags
	}
	text, err := cfg.Marshal()
	if err != nil {
		return "", fmt.Errorf("render network config as TOML: %w", err)
	}
	return string(text), nil
}

// newInstanceUUID returns a random RFC 4122 version 4 UUID in canonical form.
func newInstanceUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate instance id: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

// peersFromNetworkingMethod expands the console networking method into the
// peer list understood by the core. A method left unset means the console's
// default, which is "public server".
func peersFromNetworkingMethod(nc *managepb.NetworkConfig) ([]config.Peer, error) {
	// An unset method keeps the reference default, PublicServer, which then
	// requires public_server_url.
	switch nc.GetNetworkingMethod() {
	case managepb.NetworkingMethod_PublicServer:
		uri := strings.TrimSpace(nc.GetPublicServerUrl())
		if uri == "" {
			return nil, fmt.Errorf("public_server_url is required for the public server networking method")
		}
		if err := validatePeerURI(uri); err != nil {
			return nil, err
		}
		return []config.Peer{{URI: uri}}, nil
	case managepb.NetworkingMethod_Manual:
		var peers []config.Peer
		for _, raw := range nc.GetPeerUrls() {
			uri := strings.TrimSpace(raw)
			if uri == "" {
				continue
			}
			if err := validatePeerURI(uri); err != nil {
				return nil, err
			}
			peers = append(peers, config.Peer{URI: uri})
		}
		return peers, nil
	case managepb.NetworkingMethod_Standalone:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported networking method %d", int32(nc.GetNetworkingMethod()))
	}
}

// validatePeerURI accepts any absolute URL with a host, which covers every
// EasyTier transport (tcp, udp, ws, wss, wg, quic, ring, ...) without pinning
// the accepted scheme list.
func validatePeerURI(uri string) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("peer uri %q is invalid: %v", uri, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("peer uri %q is invalid: expected <scheme>://<host>[:port]", uri)
	}
	return nil
}

// withPrefixLength appends "/length" to a bare address. maxLength is used when
// the console left the length unset (zero or negative).
func withPrefixLength(address string, length, maxLength int) string {
	if strings.Contains(address, "/") {
		return address
	}
	if length <= 0 || length > maxLength {
		length = defaultNetworkLength
		if length > maxLength {
			length = maxLength
		}
	}
	return address + "/" + strconv.Itoa(length)
}

// nonEmptyStrings trims and drops empty entries, preserving order.
func nonEmptyStrings(values []string) []string {
	var out []string
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

// ncAssignBool copies src into dst only when the console actually sent it, so
// unset optional fields keep the local default instead of flipping to false.
func ncAssignBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}

func ncAssignString(dst *string, src *string) {
	if src != nil {
		*dst = *src
	}
}

// compressionAlgoName maps the console compression enum onto the TOML string
// the core accepts ("none"/"zstd"). Unknown values leave the default alone.
func compressionAlgoName(algo commonpb.CompressionAlgoPb) (string, bool) {
	switch algo {
	case commonpb.CompressionAlgoPb_None:
		return "none", true
	case commonpb.CompressionAlgoPb_Zstd:
		return "zstd", true
	default:
		return "", false
	}
}

// compressionAlgoValue is the inverse of compressionAlgoName.
func compressionAlgoValue(name string) (commonpb.CompressionAlgoPb, bool) {
	switch name {
	case "none":
		return commonpb.CompressionAlgoPb_None, true
	case "zstd":
		return commonpb.CompressionAlgoPb_Zstd, true
	default:
		return commonpb.CompressionAlgoPb_Invalid, false
	}
}

// flagsFromNetworkConfig starts from the local defaults and applies every
// switch the console actually sent.
func flagsFromNetworkConfig(nc *managepb.NetworkConfig) *config.Flags {
	flags := config.DefaultFlags()

	ncAssignBool(&flags.LatencyFirst, nc.LatencyFirst)
	ncAssignString(&flags.DevName, nc.DevName)
	ncAssignBool(&flags.UseSmoltcp, nc.UseSmoltcp)

	if nc.DisableIpv6 != nil {
		flags.EnableIPv6 = !*nc.DisableIpv6
	}

	ncAssignBool(&flags.EnableKCPProxy, nc.EnableKcpProxy)
	ncAssignBool(&flags.DisableKCPInput, nc.DisableKcpInput)
	ncAssignBool(&flags.EnableQUICProxy, nc.EnableQuicProxy)
	ncAssignBool(&flags.DisableQUICInput, nc.DisableQuicInput)

	ncAssignBool(&flags.DisableP2P, nc.DisableP2P)
	ncAssignBool(&flags.P2POnly, nc.P2POnly)
	ncAssignBool(&flags.LazyP2P, nc.LazyP2P)
	ncAssignBool(&flags.NeedP2P, nc.NeedP2P)

	ncAssignBool(&flags.BindDevice, nc.BindDevice)
	ncAssignBool(&flags.NoTUN, nc.NoTun)
	ncAssignBool(&flags.EnableExitNode, nc.EnableExitNode)
	ncAssignBool(&flags.RelayAllPeerRPC, nc.RelayAllPeerRpc)
	ncAssignBool(&flags.MultiThread, nc.MultiThread)
	ncAssignBool(&flags.ProxyForwardBySystem, nc.ProxyForwardBySystem)

	if nc.DisableEncryption != nil {
		flags.EnableEncryption = !*nc.DisableEncryption
	}

	if nc.GetEnableRelayNetworkWhitelist() {
		flags.RelayNetworkWhitelist = strings.Join(nc.GetRelayNetworkWhitelist(), " ")
	}

	ncAssignBool(&flags.DisableTCPHolePunching, nc.DisableTcpHolePunching)
	ncAssignBool(&flags.DisableUDPHolePunching, nc.DisableUdpHolePunching)
	ncAssignBool(&flags.DisableUPnP, nc.DisableUpnp)
	ncAssignBool(&flags.DisableRelayData, nc.DisableRelayData)
	ncAssignBool(&flags.EnableUDPBroadcastRelay, nc.EnableUdpBroadcastRelay)
	ncAssignBool(&flags.DisableSymHolePunching, nc.DisableSymHolePunching)
	ncAssignBool(&flags.AcceptDNS, nc.EnableMagicDns)
	ncAssignBool(&flags.PrivateMode, nc.EnablePrivateMode)

	if nc.Mtu != nil && *nc.Mtu > 0 {
		flags.MTU = uint32(*nc.Mtu)
	}
	if nc.InstanceRecvBpsLimit != nil {
		flags.InstanceRecvBPSLimit = *nc.InstanceRecvBpsLimit
	}
	ncAssignString(&flags.EncryptionAlgorithm, nc.EncryptionAlgorithm)

	// Compression: unset/invalid keeps the default, anything below "none" is
	// clamped to "none", otherwise the enum is mapped by name.
	if algo := nc.GetDataCompressAlgo(); algo >= commonpb.CompressionAlgoPb_None {
		if name, ok := compressionAlgoName(algo); ok {
			flags.DataCompressAlgo = name
		}
	}

	return &flags
}

// applyFlagsToNetworkConfig writes the inverse of every switch applied by
// flagsFromNetworkConfig.
func applyFlagsToNetworkConfig(nc *managepb.NetworkConfig, flags *config.Flags) {
	values := config.DefaultFlags()
	if flags != nil {
		values = *flags
	}

	nc.LatencyFirst = gproto.Bool(values.LatencyFirst)
	if values.DevName != "" {
		nc.DevName = gproto.String(values.DevName)
	}
	nc.UseSmoltcp = gproto.Bool(values.UseSmoltcp)
	nc.DisableIpv6 = gproto.Bool(!values.EnableIPv6)

	nc.EnableKcpProxy = gproto.Bool(values.EnableKCPProxy)
	nc.DisableKcpInput = gproto.Bool(values.DisableKCPInput)
	nc.EnableQuicProxy = gproto.Bool(values.EnableQUICProxy)
	nc.DisableQuicInput = gproto.Bool(values.DisableQUICInput)

	nc.DisableP2P = gproto.Bool(values.DisableP2P)
	nc.P2POnly = gproto.Bool(values.P2POnly)
	nc.LazyP2P = gproto.Bool(values.LazyP2P)
	nc.NeedP2P = gproto.Bool(values.NeedP2P)

	nc.BindDevice = gproto.Bool(values.BindDevice)
	nc.NoTun = gproto.Bool(values.NoTUN)
	nc.EnableExitNode = gproto.Bool(values.EnableExitNode)
	nc.RelayAllPeerRpc = gproto.Bool(values.RelayAllPeerRPC)
	nc.MultiThread = gproto.Bool(values.MultiThread)
	nc.ProxyForwardBySystem = gproto.Bool(values.ProxyForwardBySystem)
	nc.DisableEncryption = gproto.Bool(!values.EnableEncryption)

	if whitelist := values.RelayNetworkWhitelist; whitelist != "" && whitelist != "*" {
		nc.EnableRelayNetworkWhitelist = gproto.Bool(true)
		nc.RelayNetworkWhitelist = strings.Fields(whitelist)
	}

	nc.DisableTcpHolePunching = gproto.Bool(values.DisableTCPHolePunching)
	nc.DisableUdpHolePunching = gproto.Bool(values.DisableUDPHolePunching)
	nc.DisableUpnp = gproto.Bool(values.DisableUPnP)
	nc.DisableRelayData = gproto.Bool(values.DisableRelayData)
	nc.EnableUdpBroadcastRelay = gproto.Bool(values.EnableUDPBroadcastRelay)
	nc.DisableSymHolePunching = gproto.Bool(values.DisableSymHolePunching)
	nc.EnableMagicDns = gproto.Bool(values.AcceptDNS)
	nc.EnablePrivateMode = gproto.Bool(values.PrivateMode)

	if values.MTU > 0 {
		nc.Mtu = gproto.Int32(int32(values.MTU))
	}
	nc.InstanceRecvBpsLimit = gproto.Uint64(values.InstanceRecvBPSLimit)
	if values.EncryptionAlgorithm != "" {
		nc.EncryptionAlgorithm = gproto.String(values.EncryptionAlgorithm)
	}

	if algo, ok := compressionAlgoValue(values.DataCompressAlgo); ok {
		nc.DataCompressAlgo = &algo
	}
}

// applyIPv4ToNetworkConfig splits a local IPv4 CIDR into the console's
// address/prefix pair.
func applyIPv4ToNetworkConfig(nc *managepb.NetworkConfig, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	address := value
	var length int
	if idx := strings.IndexByte(value, '/'); idx >= 0 {
		address = value[:idx]
		parsed, err := strconv.Atoi(value[idx+1:])
		if err != nil {
			return fmt.Errorf("ipv4 %q has a malformed prefix length", value)
		}
		if _, err := netip.ParsePrefix(value); err != nil {
			return fmt.Errorf("ipv4 %q is not a CIDR: %v", value, err)
		}
		length = parsed
	}
	if _, err := netip.ParseAddr(address); err != nil {
		return fmt.Errorf("ipv4 %q is not an IP address: %v", value, err)
	}
	nc.VirtualIpv4 = gproto.String(address)
	if length > 0 {
		nc.NetworkLength = gproto.Int32(int32(length))
	}
	return nil
}

func applyVPNPortalToNetworkConfig(nc *managepb.NetworkConfig, portal *config.VPNPortalConfig) {
	if portal == nil {
		return
	}
	nc.EnableVpnPortal = gproto.Bool(true)
	if portal.ClientCIDR != "" {
		address := portal.ClientCIDR
		if idx := strings.IndexByte(address, '/'); idx >= 0 {
			if length, err := strconv.Atoi(address[idx+1:]); err == nil {
				nc.VpnPortalClientNetworkLen = gproto.Int32(int32(length))
			}
			address = address[:idx]
		}
		nc.VpnPortalClientNetworkAddr = gproto.String(address)
	}
	if _, port, err := net.SplitHostPort(portal.WireGuardListen); err == nil {
		if parsed, err := strconv.ParseUint(port, 10, 32); err == nil {
			nc.VpnPortalListenPort = gproto.Int32(int32(parsed))
		}
	}
}

func portForwardToNetworkConfig(forward config.PortForward) *managepb.PortForwardConfig {
	bindHost, bindPort, err := net.SplitHostPort(forward.BindAddr)
	if err != nil {
		return nil
	}
	dstHost, dstPort, err := net.SplitHostPort(forward.DstAddr)
	if err != nil {
		return nil
	}
	bind, err := strconv.ParseUint(bindPort, 10, 32)
	if err != nil {
		return nil
	}
	dst, err := strconv.ParseUint(dstPort, 10, 32)
	if err != nil {
		return nil
	}
	return &managepb.PortForwardConfig{
		BindIp:   bindHost,
		BindPort: uint32(bind),
		DstIp:    dstHost,
		DstPort:  uint32(dst),
		Proto:    forward.Proto,
	}
}

// aclToConfig converts a console ACL. The protobuf and the local TOML ACL
// share the same shape, so the conversion is lossless.
func aclToConfig(acl *aclpb.Acl) *config.ACL {
	if acl == nil {
		return nil
	}
	v1 := acl.GetAclV1()
	if v1 == nil {
		return nil
	}
	if len(v1.GetChains()) == 0 && v1.GetGroup() == nil {
		return nil
	}

	converted := &config.ACLV1{}
	for _, chain := range v1.GetChains() {
		if chain == nil {
			continue
		}
		out := config.ACLChain{
			Name:          chain.GetName(),
			ChainType:     int(chain.GetChainType()),
			Description:   chain.GetDescription(),
			Enabled:       chain.GetEnabled(),
			DefaultAction: int(chain.GetDefaultAction()),
		}
		for _, rule := range chain.GetRules() {
			if rule == nil {
				continue
			}
			out.Rules = append(out.Rules, config.ACLRule{
				Name:              rule.GetName(),
				Description:       rule.GetDescription(),
				Priority:          rule.GetPriority(),
				Enabled:           rule.GetEnabled(),
				Protocol:          int(rule.GetProtocol()),
				Ports:             append([]string(nil), rule.GetPorts()...),
				SourceIPs:         append([]string(nil), rule.GetSourceIps()...),
				DestinationIPs:    append([]string(nil), rule.GetDestinationIps()...),
				SourcePorts:       append([]string(nil), rule.GetSourcePorts()...),
				Action:            int(rule.GetAction()),
				RateLimit:         rule.GetRateLimit(),
				BurstLimit:        rule.GetBurstLimit(),
				Stateful:          rule.GetStateful(),
				SourceGroups:      append([]string(nil), rule.GetSourceGroups()...),
				DestinationGroups: append([]string(nil), rule.GetDestinationGroups()...),
			})
		}
		converted.Chains = append(converted.Chains, out)
	}
	if group := v1.GetGroup(); group != nil {
		out := &config.ACLGroup{
			Members: append([]string(nil), group.GetMembers()...),
		}
		for _, declare := range group.GetDeclares() {
			if declare == nil {
				continue
			}
			out.Declares = append(out.Declares, config.ACLGroupIdentity{
				GroupName:   declare.GetGroupName(),
				GroupSecret: declare.GetGroupSecret(),
			})
		}
		converted.Group = out
	}
	return &config.ACL{ACLV1: converted}
}

// configACLToProto is the inverse of aclToConfig.
func configACLToProto(acl *config.ACL) *aclpb.Acl {
	if acl == nil || acl.ACLV1 == nil {
		return nil
	}
	v1 := &aclpb.AclV1{}
	for _, chain := range acl.ACLV1.Chains {
		out := &aclpb.Chain{
			Name:          chain.Name,
			ChainType:     aclpb.ChainType(chain.ChainType),
			Description:   chain.Description,
			Enabled:       chain.Enabled,
			DefaultAction: aclpb.Action(chain.DefaultAction),
		}
		for _, rule := range chain.Rules {
			out.Rules = append(out.Rules, &aclpb.Rule{
				Name:              rule.Name,
				Description:       rule.Description,
				Priority:          rule.Priority,
				Enabled:           rule.Enabled,
				Protocol:          aclpb.Protocol(rule.Protocol),
				Ports:             append([]string(nil), rule.Ports...),
				SourceIps:         append([]string(nil), rule.SourceIPs...),
				DestinationIps:    append([]string(nil), rule.DestinationIPs...),
				SourcePorts:       append([]string(nil), rule.SourcePorts...),
				Action:            aclpb.Action(rule.Action),
				RateLimit:         rule.RateLimit,
				BurstLimit:        rule.BurstLimit,
				Stateful:          rule.Stateful,
				SourceGroups:      append([]string(nil), rule.SourceGroups...),
				DestinationGroups: append([]string(nil), rule.DestinationGroups...),
			})
		}
		v1.Chains = append(v1.Chains, out)
	}
	if group := acl.ACLV1.Group; group != nil {
		out := &aclpb.GroupInfo{Members: append([]string(nil), group.Members...)}
		for _, declare := range group.Declares {
			out.Declares = append(out.Declares, &aclpb.GroupIdentity{
				GroupName:   declare.GroupName,
				GroupSecret: declare.GroupSecret,
			})
		}
		v1.Group = out
	}
	if len(v1.Chains) == 0 && v1.Group == nil {
		return nil
	}
	return &aclpb.Acl{AclV1: v1}
}

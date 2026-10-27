// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webconsole

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/EasyTier/EasyTier/go/internal/config"
	configpb "github.com/EasyTier/EasyTier/go/internal/proto/api_config"
	managepb "github.com/EasyTier/EasyTier/go/internal/proto/api_manage"
	commonpb "github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"google.golang.org/protobuf/proto"
)

// Backend is the machine-side instance surface the console drives. The daemon
// implements it over internal/instance; tests implement it in memory.
type Backend interface {
	// InstanceIDs lists the instance IDs the console may manage.
	InstanceIDs() []string
	// RunInstance creates or (with overwrite) replaces one instance.
	RunInstance(ctx context.Context, instID string, cfg *config.Config, overwrite bool) error
	// DeleteInstances removes the named instances and returns the IDs that
	// could not be removed (they remain alive).
	DeleteInstances(instIDs []string) (remaining []string)
	// RetainInstances keeps exactly the named instances running and returns
	// the IDs that remain alive after the call.
	RetainInstances(instIDs []string) (remaining []string)
	// InstanceConfig returns the stored configuration of one instance.
	InstanceConfig(instID string) (*config.Config, bool)
	// InstanceInfo collects the running information of the named instances.
	InstanceInfo(instIDs []string) map[string]*managepb.NetworkInstanceRunningInfo
	// FirstInstanceInfo returns the running information of the instance this
	// machine hosts, regardless of the id the console asks for. The console
	// looks the instance up by the id it requested, so answering with the
	// requested id keeps its peer table populated even when its id differs
	// from the one we stored.
	FirstInstanceInfo() *managepb.NetworkInstanceRunningInfo
}

// debugCollect enables verbose logging of the CollectNetworkInfo instance
// identifiers (off by default; set ET_DEBUG_COLLECT=1).
var debugCollect = os.Getenv("ET_DEBUG_COLLECT") != ""

// WebClientService serves api.manage.WebClientService: the eight methods the
// console calls to validate, run, retain, inspect and delete instances.
type WebClientService struct {
	backend Backend
	logf    func(string, ...any)
}

// NewWebClientService creates the WebClientService handler set.
func NewWebClientService(backend Backend, logf func(string, ...any)) *WebClientService {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &WebClientService{backend: backend, logf: logf}
}

// ServiceName implements rpc.RpcService.
func (s *WebClientService) ServiceName() string { return ServiceWebClient }

// HandleMethod implements rpc.RpcService.
func (s *WebClientService) HandleMethod(methodIndex uint32, ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
	if s.backend == nil {
		return nil, errors.New("webclient service has no instance backend")
	}
	s.logf("webconsole WebClientService method=%d body=%d bytes", methodIndex, len(requestBody))
	switch methodIndex {
	case MethodValidateConfig:
		request := &managepb.ValidateConfigRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode ValidateConfig request: %w", err)
		}
		response, err := s.validateConfig(request)
		if err != nil {
			return nil, err
		}
		return proto.Marshal(response)
	case MethodRunNetworkInstance:
		request := &managepb.RunNetworkInstanceRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode RunNetworkInstance request: %w", err)
		}
		response, err := s.runNetworkInstance(ctx, request)
		if err != nil {
			return nil, err
		}
		return proto.Marshal(response)
	case MethodRetainNetworkInstance:
		request := &managepb.RetainNetworkInstanceRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode RetainNetworkInstance request: %w", err)
		}
		remaining := s.backend.RetainInstances(uuidList(request.GetInstIds()))
		return proto.Marshal(&managepb.RetainNetworkInstanceResponse{RemainInstIds: uuidMessages(remaining)})
	case MethodCollectNetworkInfo:
		request := &managepb.CollectNetworkInfoRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode CollectNetworkInfo request: %w", err)
		}
		ids := uuidList(request.GetInstIds())
		if len(ids) == 0 {
			ids = s.backend.InstanceIDs()
		}
		response := &managepb.CollectNetworkInfoResponse{
			Info: &managepb.NetworkInstanceRunningInfoMap{Map: map[string]*managepb.NetworkInstanceRunningInfo{}},
		}
		if debugCollect {
			for _, id := range ids {
				s.logf("webconsole CollectNetworkInfo requested inst_id=%q", id)
			}
		}
		// The console looks the instance up by the id it asked for, so the
		// reply is keyed by the requested id. When that id is unknown to us
		// (a stale or console-side id) we still answer with the instance we
		// run, otherwise the console renders an empty peer table.
		byID := s.backend.InstanceInfo(ids)
		for _, id := range ids {
			running := byID[id]
			if running == nil {
				running = s.backend.FirstInstanceInfo()
			}
			if running == nil {
				continue
			}
			if debugCollect {
				s.logf("webconsole CollectNetworkInfo replying with key=%q", id)
			}
			response.Info.Map[id] = running
			s.logf("webconsole instance %s running=%v peers=%d routes=%d",
				id, running.GetRunning(), len(running.GetPeers()), len(running.GetPeerRoutePairs()))
		}
		encoded, err := proto.Marshal(response)
		if err != nil {
			return nil, err
		}
		if debugCollect {
			s.logf("webconsole CollectNetworkInfo payload=%d bytes", len(encoded))
			_ = os.WriteFile("/tmp/collect-network-info.bin", encoded, 0o644)
		}
		return encoded, nil
	case MethodListNetworkInstance:
		request := &managepb.ListNetworkInstanceRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode ListNetworkInstance request: %w", err)
		}
		ids := s.backend.InstanceIDs()
		if debugCollect {
			s.logf("webconsole ListNetworkInstance returns %d ids: %v", len(ids), ids)
		}
		return proto.Marshal(&managepb.ListNetworkInstanceResponse{InstIds: uuidMessages(ids)})
	case MethodDeleteNetworkInstance:
		request := &managepb.DeleteNetworkInstanceRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode DeleteNetworkInstance request: %w", err)
		}
		remaining := s.backend.DeleteInstances(uuidList(request.GetInstIds()))
		return proto.Marshal(&managepb.DeleteNetworkInstanceResponse{RemainInstIds: uuidMessages(remaining)})
	case MethodGetNetworkInstanceConfig:
		request := &managepb.GetNetworkInstanceConfigRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode GetNetworkInstanceConfig request: %w", err)
		}
		id := uuidString(request.GetInstId())
		cfg, ok := s.backend.InstanceConfig(id)
		if !ok {
			return nil, fmt.Errorf("instance %s not found", id)
		}
		return proto.Marshal(&managepb.GetNetworkInstanceConfigResponse{
			Config: ConfigToNetworkConfig(id, cfg),
			Source: managepb.ConfigSource_ConfigSourceUser,
		})
	case MethodListNetworkInstanceMeta:
		request := &managepb.ListNetworkInstanceMetaRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode ListNetworkInstanceMeta request: %w", err)
		}
		ids := uuidList(request.GetInstIds())
		if len(ids) == 0 {
			ids = s.backend.InstanceIDs()
		}
		response := &managepb.ListNetworkInstanceMetaResponse{}
		for _, id := range ids {
			cfg, ok := s.backend.InstanceConfig(id)
			if !ok {
				continue
			}
			meta := &managepb.NetworkMeta{
				InstId:       uuidMessage(id),
				Source:       managepb.ConfigSource_ConfigSourceUser,
				InstanceName: cfg.InstanceName,
				NetworkName:  cfg.NetworkIdentity.NetworkName,
			}
			response.Metas = append(response.Metas, meta)
		}
		return proto.Marshal(response)
	default:
		return nil, fmt.Errorf("WebClientService has no method %d", methodIndex)
	}
}

func (s *WebClientService) validateConfig(req *managepb.ValidateConfigRequest) (*managepb.ValidateConfigResponse, error) {
	if req.GetConfig() == nil {
		return nil, errors.New("validate config requires a config")
	}
	toml, err := ValidateNetworkConfig(req.GetConfig())
	if err != nil {
		return nil, err
	}
	return &managepb.ValidateConfigResponse{TomlConfig: toml}, nil
}

func (s *WebClientService) runNetworkInstance(ctx context.Context, req *managepb.RunNetworkInstanceRequest) (*managepb.RunNetworkInstanceResponse, error) {
	if req.GetConfig() == nil {
		return nil, errors.New("run network instance requires a config")
	}
	cfg, err := NetworkConfigToConfig(req.GetConfig())
	if err != nil {
		return nil, err
	}
	instID := uuidString(req.GetInstId())
	if instID == "" {
		instID = cfg.InstanceID
	}
	if instID == "" {
		instID = newUUIDString()
	}
	cfg.InstanceID = instID
	if err := s.backend.RunInstance(ctx, instID, cfg, req.GetOverwrite()); err != nil {
		return nil, err
	}
	s.logf("webconsole instance %s started (overwrite=%v)", instID, req.GetOverwrite())
	return &managepb.RunNetworkInstanceResponse{InstId: uuidMessage(instID)}, nil
}

// ConfigService serves api.config.ConfigRpc: live GetConfig/PatchConfig.
type ConfigService struct {
	backend Backend
	logf    func(string, ...any)
}

// NewConfigService creates the ConfigRpc handler set.
func NewConfigService(backend Backend, logf func(string, ...any)) *ConfigService {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &ConfigService{backend: backend, logf: logf}
}

// ServiceName implements rpc.RpcService.
func (s *ConfigService) ServiceName() string { return ServiceConfigRPC }

// HandleMethod implements rpc.RpcService.
func (s *ConfigService) HandleMethod(methodIndex uint32, ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
	if s.backend == nil {
		return nil, errors.New("config service has no instance backend")
	}
	switch methodIndex {
	case MethodGetConfig:
		request := &configpb.GetConfigRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode GetConfig request: %w", err)
		}
		id := uuidString(request.GetInstance().GetId())
		cfg, ok := s.backend.InstanceConfig(id)
		if !ok {
			return nil, fmt.Errorf("instance %s not found", id)
		}
		return proto.Marshal(&configpb.GetConfigResponse{Config: ConfigToNetworkConfig(id, cfg)})
	case MethodPatchConfig:
		request := &configpb.PatchConfigRequest{}
		if err := proto.Unmarshal(requestBody, request); err != nil {
			return nil, fmt.Errorf("decode PatchConfig request: %w", err)
		}
		id := uuidString(request.GetInstance().GetId())
		cfg, ok := s.backend.InstanceConfig(id)
		if !ok {
			return nil, fmt.Errorf("instance %s not found", id)
		}
		updated, err := ApplyConfigPatch(cfg, request.GetPatch())
		if err != nil {
			return nil, err
		}
		updated.InstanceID = id
		if err := s.backend.RunInstance(ctx, id, updated, true); err != nil {
			return nil, err
		}
		s.logf("webconsole instance %s patched", id)
		return proto.Marshal(&configpb.PatchConfigResponse{})
	default:
		return nil, fmt.Errorf("ConfigRpc has no method %d", methodIndex)
	}
}

// ApplyConfigPatch applies one InstanceConfigPatch to a stored config and
// returns the updated copy. Add/Remove/Clear follow the ConfigPatchAction enum.
func ApplyConfigPatch(cfg *config.Config, patch *configpb.InstanceConfigPatch) (*config.Config, error) {
	if cfg == nil {
		return nil, errors.New("config patch requires a config")
	}
	if patch == nil {
		copied := *cfg
		return &copied, nil
	}
	updated := *cfg
	updated.Peers = append([]config.Peer(nil), cfg.Peers...)
	updated.Routes = append([]string(nil), cfg.Routes...)
	updated.ExitNodes = append([]string(nil), cfg.ExitNodes...)
	updated.Listeners = append([]string(nil), cfg.Listeners...)
	updated.MappedListeners = append([]string(nil), cfg.MappedListeners...)
	updated.PortForwards = append([]config.PortForward(nil), cfg.PortForwards...)
	updated.ProxyNetworks = append([]config.ProxyNetwork(nil), cfg.ProxyNetworks...)
	if cfg.Flags != nil {
		flags := *cfg.Flags
		updated.Flags = &flags
	}

	if patch.Hostname != nil {
		updated.Hostname = patch.GetHostname()
	}
	if patch.Ipv4 != nil {
		ipv4, err := ipv4InetString(patch.GetIpv4())
		if err != nil {
			return nil, err
		}
		updated.IPv4 = ipv4
	}
	for _, route := range patch.GetRoutes() {
		value := ipv4InetStringOrEmpty(route.GetCidr())
		updated.Routes = applyStringPatch(updated.Routes, route.GetAction(), value)
	}
	for _, node := range patch.GetExitNodes() {
		value := ipAddressString(node.GetNode())
		updated.ExitNodes = applyStringPatch(updated.ExitNodes, node.GetAction(), value)
	}
	for _, listener := range patch.GetMappedListeners() {
		value := listener.GetUrl().GetUrl()
		updated.MappedListeners = applyStringPatch(updated.MappedListeners, listener.GetAction(), value)
	}
	for _, connector := range patch.GetConnectors() {
		value := connector.GetUrl().GetUrl()
		uris := make([]string, 0, len(updated.Peers))
		for _, peer := range updated.Peers {
			uris = append(uris, peer.URI)
		}
		uris = applyStringPatch(uris, connector.GetAction(), value)
		updated.Peers = updated.Peers[:0]
		for _, uri := range uris {
			updated.Peers = append(updated.Peers, config.Peer{URI: uri})
		}
	}
	for _, portForward := range patch.GetPortForwards() {
		entry := config.PortForward{
			BindAddr: socketAddrString(portForward.GetCfg().GetBindAddr()),
			DstAddr:  socketAddrString(portForward.GetCfg().GetDstAddr()),
			Proto:    socketTypeString(portForward.GetCfg().GetSocketType()),
		}
		switch portForward.GetAction() {
		case configpb.ConfigPatchAction_ADD:
			updated.PortForwards = append(updated.PortForwards, entry)
		case configpb.ConfigPatchAction_REMOVE:
			filtered := updated.PortForwards[:0]
			for _, existing := range updated.PortForwards {
				if existing.BindAddr != entry.BindAddr || existing.DstAddr != entry.DstAddr || existing.Proto != entry.Proto {
					filtered = append(filtered, existing)
				}
			}
			updated.PortForwards = filtered
		case configpb.ConfigPatchAction_CLEAR:
			updated.PortForwards = nil
		}
	}
	if patch.Ipv6PublicAddrProvider != nil && updated.Flags != nil {
		updated.IPv6PublicAddrProvider = patch.GetIpv6PublicAddrProvider()
	}
	if patch.Ipv6PublicAddrAuto != nil {
		updated.IPv6PublicAddrAuto = patch.GetIpv6PublicAddrAuto()
	}
	if patch.Ipv6PublicAddrPrefix != nil {
		if prefix := strings.TrimSpace(patch.GetIpv6PublicAddrPrefix()); prefix != "" {
			if _, err := netip.ParsePrefix(prefix); err != nil {
				return nil, fmt.Errorf("invalid ipv6 public address prefix %q: %w", prefix, err)
			}
		}
		updated.IPv6PublicAddrPrefix = patch.GetIpv6PublicAddrPrefix()
	}
	if patch.DisableRelayData != nil && updated.Flags != nil {
		updated.Flags.DisableRelayData = patch.GetDisableRelayData()
	}
	return &updated, nil
}

func applyStringPatch(values []string, action configpb.ConfigPatchAction, value string) []string {
	switch action {
	case configpb.ConfigPatchAction_ADD:
		if value == "" {
			return values
		}
		for _, existing := range values {
			if existing == value {
				return values
			}
		}
		return append(values, value)
	case configpb.ConfigPatchAction_REMOVE:
		filtered := values[:0]
		for _, existing := range values {
			if existing != value {
				filtered = append(filtered, existing)
			}
		}
		return filtered
	case configpb.ConfigPatchAction_CLEAR:
		return nil
	default:
		return values
	}
}

func ipv4InetString(inet *commonpb.Ipv4Inet) (string, error) {
	if inet == nil {
		return "", nil
	}
	address := ipv4Addr(inet.GetAddress())
	if !address.IsValid() {
		return "", fmt.Errorf("invalid ipv4 address in %v", inet)
	}
	length := inet.GetNetworkLength()
	if length > 32 {
		return "", fmt.Errorf("invalid ipv4 network length %d", length)
	}
	return netip.PrefixFrom(address, int(length)).String(), nil
}

func ipv4InetStringOrEmpty(inet *commonpb.Ipv4Inet) string {
	value, err := ipv4InetString(inet)
	if err != nil {
		return ""
	}
	return value
}

func ipAddressString(address *commonpb.IpAddr) string {
	if address == nil {
		return ""
	}
	if v4 := address.GetIpv4(); v4 != nil {
		if parsed := ipv4Addr(v4); parsed.IsValid() {
			return parsed.String()
		}
		return ""
	}
	if v6 := address.GetIpv6(); v6 != nil {
		return ipv6String(v6)
	}
	return ""
}

// ipv4Addr renders the wire form (big-endian uint32) as a netip address.
func ipv4Addr(value *commonpb.Ipv4Addr) netip.Addr {
	if value == nil {
		return netip.Addr{}
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value.GetAddr())
	return netip.AddrFrom4(raw)
}

// ipv6String renders the 16-byte wire form as text.
func ipv6String(value *commonpb.Ipv6Addr) string {
	var raw [16]byte
	binary.BigEndian.PutUint32(raw[0:4], value.GetPart1())
	binary.BigEndian.PutUint32(raw[4:8], value.GetPart2())
	binary.BigEndian.PutUint32(raw[8:12], value.GetPart3())
	binary.BigEndian.PutUint32(raw[12:16], value.GetPart4())
	return netip.AddrFrom16(raw).String()
}

// socketAddrString renders a common.SocketAddr as host:port.
func socketAddrString(value *commonpb.SocketAddr) string {
	if value == nil {
		return ""
	}
	address := ipv4Addr(value.GetIpv4())
	if address.IsValid() {
		return netip.AddrPortFrom(address, uint16(value.GetPort())).String()
	}
	if v6 := value.GetIpv6(); v6 != nil {
		if parsed, err := netip.ParseAddr(ipv6String(v6)); err == nil {
			return netip.AddrPortFrom(parsed, uint16(value.GetPort())).String()
		}
	}
	return ""
}

func uuidList(messages []*commonpb.UUID) []string {
	out := make([]string, 0, len(messages))
	for _, message := range messages {
		id := uuidString(message)
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

func uuidMessages(ids []string) []*commonpb.UUID {
	out := make([]*commonpb.UUID, 0, len(ids))
	for _, id := range ids {
		out = append(out, uuidMessage(id))
	}
	return out
}

func readSmallFile(path string) ([]byte, error) { return os.ReadFile(path) }

// socketTypeString maps the proto socket type onto the TOML proto field.
func socketTypeString(kind commonpb.SocketType) string {
	switch kind {
	case commonpb.SocketType_TCP:
		return "tcp"
	case commonpb.SocketType_UDP:
		return "udp"
	default:
		return "tcp"
	}
}

var _ rpc.RpcService = (*ConfigService)(nil)

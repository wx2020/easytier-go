// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package management implements the EasyTier management RPC service.
package management

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/acl"
	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/credential"
	"github.com/EasyTier/EasyTier/go/internal/dns"
	"github.com/EasyTier/EasyTier/go/internal/forward"
	"github.com/EasyTier/EasyTier/go/internal/instance"
	"github.com/EasyTier/EasyTier/go/internal/logging"
	"github.com/EasyTier/EasyTier/go/internal/peer"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/route"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/stats"
	"github.com/EasyTier/EasyTier/go/internal/webclient"
)

const ServiceName = "EasyTierManagement"

// ErrUnsupported identifies a management method whose runtime component was
// not wired into this service. It is preferable to an empty success response.
var ErrUnsupported = errors.New("management operation is not supported by the configured runtime")

const (
	methodNodeInfo uint32 = iota
	methodStatsPrometheus
	methodLoggerGet
	methodLoggerSet
	methodInstanceList
	// Method index 5 was not part of the original service and remains reserved
	// for compatibility with clients that reject unknown methods.
	methodInstanceStatus uint32 = 6
	methodStatsSnapshot  uint32 = 7
	methodConfigGet      uint32 = iota + 1
	methodConfigSet
	methodPeerList
	methodRouteList
	methodConnectorList
	methodForwardList
	methodForwardAdd
	methodForwardRemove
	methodACLGet
	methodCredentialList
	methodCredentialGenerate
	methodCredentialRevoke
	methodDNSList
	methodDNSSet
	methodDNSDelete
	methodWebSessions
	methodInstanceStart uint32 = iota + 1
	methodInstanceStop
	methodForwardStatus
	methodACLStats
	methodDNSStatus
	methodMappedListenerList
	methodMappedListenerAdd
	methodMappedListenerRemove
	methodVPNPortal
	methodProxy
	methodPeerCenter
)

// NodeInfo identifies the node serving management requests.
type NodeInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InstanceInfo identifies one managed instance.
type InstanceInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// InstanceStatus is the lifecycle state exposed by the management API.
type InstanceStatus struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Running bool   `json:"running"`
}

type StatsInfo struct {
	Name   string            `json:"name"`
	Value  uint64            `json:"value"`
	Labels map[string]string `json:"labels,omitempty"`
}

type ConfigInfo struct {
	Config   config.Config `json:"config"`
	TOML     string        `json:"toml"`
	ReadOnly bool          `json:"read_only"`
}

type PeerInfo struct {
	ID        uint32 `json:"id"`
	PeerCount int    `json:"peer_count"`
}

type ConnectorInfo struct {
	URL    string `json:"url"`
	Status string `json:"status"`
}

type ACLInfo struct {
	DefaultAction acl.Action `json:"default_action"`
	Rules         []acl.Rule `json:"rules"`
	Stats         ACLStats   `json:"stats"`
}

type ACLRuleStats struct {
	Name     string     `json:"name"`
	Priority uint32     `json:"priority"`
	Action   acl.Action `json:"action"`
	Matches  uint64     `json:"matches"`
}

type ACLStats struct {
	Evaluations   uint64         `json:"evaluations"`
	DefaultAllows uint64         `json:"default_allows"`
	DefaultDrops  uint64         `json:"default_drops"`
	Rules         []ACLRuleStats `json:"rules"`
}

type CredentialInfo struct {
	ID           string   `json:"id"`
	Groups       []string `json:"groups"`
	RelayAllowed bool     `json:"relay_allowed"`
	ProxyCIDRs   []string `json:"proxy_cidrs"`
	Reusable     bool     `json:"reusable"`
	ExpiresAt    string   `json:"expires_at"`
}

type DNSRecordInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	TTL       uint32   `json:"ttl,omitempty"`
	ExpiresAt string   `json:"expires_at,omitempty"`
}

type DNSUpstreamInfo struct {
	Address     string `json:"address"`
	State       string `json:"state"`
	Queries     uint64 `json:"queries"`
	Successes   uint64 `json:"successes"`
	Failures    uint64 `json:"failures"`
	LastError   string `json:"last_error,omitempty"`
	LastChecked string `json:"last_checked,omitempty"`
}

type DNSStatus struct {
	Address         string            `json:"address"`
	Zone            string            `json:"zone"`
	TTL             uint32            `json:"ttl"`
	Serving         bool              `json:"serving"`
	Closed          bool              `json:"closed"`
	UpstreamTimeout string            `json:"upstream_timeout"`
	Upstreams       []DNSUpstreamInfo `json:"upstreams"`
}

type ForwardStatus struct {
	Bind              string `json:"bind"`
	Destination       string `json:"destination"`
	State             string `json:"state"`
	ActiveConnections uint64 `json:"active_connections"`
	Accepted          uint64 `json:"accepted"`
	Failed            uint64 `json:"failed"`
	BytesFromClient   uint64 `json:"bytes_from_client"`
	BytesToClient     uint64 `json:"bytes_to_client"`
}

type MappedListenerStatus struct {
	URL   string `json:"url"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

type VPNPortalInfo struct {
	VPNType          string   `json:"vpn_type"`
	ClientConfig     string   `json:"client_config"`
	ConnectedClients []string `json:"connected_clients"`
}

type ProxyEntry struct {
	Source        string `json:"src"`
	Destination   string `json:"dst"`
	StartTime     uint64 `json:"start_time"`
	State         string `json:"state"`
	TransportType string `json:"transport_type"`
}

type ProxyInfo struct {
	Entries []ProxyEntry `json:"entries"`
}

type PeerCenterInfo struct {
	GlobalPeerMap map[string]PeerCenterPeerGroup `json:"global_peer_map"`
	Digest        string                         `json:"digest,omitempty"`
}

type PeerCenterPeerGroup struct {
	DirectPeers map[string]PeerCenterDirectPeer `json:"direct_peers"`
}

type PeerCenterDirectPeer struct {
	LatencyMs int32 `json:"latency_ms"`
}

// MappedListenerStore is the interface for managing mapped listeners. It is
// implemented by the mapping.Manager. A nil store means mapped listeners are
// unsupported (backward compatible), while a non-nil store provides add/remove.
type MappedListenerStore interface {
	List() []MappedListenerStatus
	Add(url string) error
	Remove(url string) error
}

// ProxyProvider supplies TCP proxy entries for status/RPC. Implementations
// typically aggregate KCP and QUIC proxy states.
type ProxyProvider interface {
	ProxyEntries() []ProxyEntry
}

// VPNPortalProvider supplies WireGuard VPN portal status.
type VPNPortalProvider interface {
	ListClients() []string
}

// ServiceOptions wires optional, real runtime components into Service. A nil
// component means that its API is unavailable, not that it has fake data.
type ServiceOptions struct {
	NodeInfo        NodeInfo
	Counters        *stats.Counters
	Instances       *instance.InstanceManager
	Logger          *logging.Logger
	Config          *config.Config
	ConfigReadOnly  bool
	UpdateConfig    func(context.Context, config.Config) error
	Peers           *peer.PeerConnectionManager
	Routes          *route.Engine
	Connectors      []ConnectorInfo
	Forwards        *forward.Manager
	ACL             *acl.Policy
	Credentials     *credential.Manager
	DNS             *dns.Server
	WebClient       *webclient.Server
	MetricLabels    map[string]string
	MappedListeners MappedListenerStore
	ProxyProvider   ProxyProvider
	VPNPortal       VPNPortalProvider
}

// LoggerLevel is a supported logger verbosity level.
type LoggerLevel string

const (
	LoggerLevelTrace LoggerLevel = "trace"
	LoggerLevelDebug LoggerLevel = "debug"
	LoggerLevelInfo  LoggerLevel = "info"
	LoggerLevelWarn  LoggerLevel = "warn"
	LoggerLevelError LoggerLevel = "error"
)

// Valid reports whether level is a supported logger verbosity level.
func (level LoggerLevel) Valid() bool {
	switch level {
	case LoggerLevelTrace, LoggerLevelDebug, LoggerLevelInfo, LoggerLevelWarn, LoggerLevelError:
		return true
	default:
		return false
	}
}

type nodeInfoResponse struct {
	Node NodeInfo `json:"node"`
}

type prometheusResponse struct {
	Text string `json:"text"`
}

type loggerResponse struct {
	Level LoggerLevel `json:"level"`
}

type loggerSetRequest struct {
	Level LoggerLevel `json:"level"`
}

type configSetRequest struct {
	TOML   string         `json:"toml"`
	Config *config.Config `json:"config"`
}

type forwardRequest struct {
	Rule forward.Rule `json:"rule"`
}

type CredentialGenerateRequest struct {
	ID           string   `json:"id"`
	Groups       []string `json:"groups"`
	RelayAllowed bool     `json:"relay_allowed"`
	ProxyCIDRs   []string `json:"proxy_cidrs"`
	TTLSeconds   int64    `json:"ttl_seconds"`
	Reusable     *bool    `json:"reusable"`
}

type CredentialGenerateResponse struct {
	CredentialID     string `json:"credential_id"`
	CredentialSecret string `json:"credential_secret"`
}

type credentialRevokeRequest struct {
	ID string `json:"id"`
}

type dnsSetRequest struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

type dnsDeleteRequest struct {
	Name string `json:"name"`
}

type instanceRequest struct {
	Name string `json:"name"`
}

type instanceListResponse struct {
	Instances []InstanceInfo `json:"instances"`
}

// Service provides the concrete EasyTier management RPC methods.
type Service struct {
	nodeInfo  NodeInfo
	counters  *stats.Counters
	instances *instance.InstanceManager
	logger    *logging.Logger

	componentMu          sync.RWMutex
	config               config.Config
	configSet            bool
	configReadOnly       bool
	updateConfig         func(context.Context, config.Config) error
	peers                *peer.PeerConnectionManager
	routes               *route.Engine
	connectors           []ConnectorInfo
	connectorsFromConfig bool
	forwards             *forward.Manager
	acl                  *acl.Policy
	credentials          *credential.Manager
	dns                  *dns.Server
	webClient            *webclient.Server
	metricLabels         map[string]string
	mappedListeners      MappedListenerStore
	proxyProvider        ProxyProvider
	vpnPortal            VPNPortalProvider

	loggerMu    sync.RWMutex
	loggerLevel LoggerLevel
}

// NewService creates a management service. A nil counters value creates an
// empty counter set, and a nil instances value reports no instances.
func NewService(nodeInfo NodeInfo, counters *stats.Counters, instances *instance.InstanceManager) *Service {
	return NewServiceWithOptions(ServiceOptions{NodeInfo: nodeInfo, Counters: counters, Instances: instances})
}

// NewServiceWithOptions creates a management service over the supplied runtime
// components. It copies configuration and connector slices at construction.
func NewServiceWithOptions(options ServiceOptions) *Service {
	counters := options.Counters
	if counters == nil {
		counters = stats.New()
	}
	connectorsFromConfig := options.Config != nil && len(options.Connectors) == 0
	service := &Service{
		nodeInfo:             options.NodeInfo,
		counters:             counters,
		instances:            options.Instances,
		logger:               options.Logger,
		peers:                options.Peers,
		routes:               options.Routes,
		connectors:           append([]ConnectorInfo(nil), options.Connectors...),
		connectorsFromConfig: connectorsFromConfig,
		forwards:             options.Forwards,
		acl:                  options.ACL,
		credentials:          options.Credentials,
		dns:                  options.DNS,
		webClient:            options.WebClient,
		metricLabels:         cloneLabels(options.MetricLabels),
		configReadOnly:       options.ConfigReadOnly,
		updateConfig:         options.UpdateConfig,
		mappedListeners:      options.MappedListeners,
		proxyProvider:        options.ProxyProvider,
		vpnPortal:            options.VPNPortal,
		loggerLevel:          LoggerLevelInfo,
	}
	if options.Config != nil {
		cloned, err := cloneConfig(*options.Config)
		if err != nil {
			cloned = *options.Config
		}
		service.config, service.configSet = cloned, true
		if len(service.connectors) == 0 {
			service.connectors = connectorInfos(options.Config.Peers)
		}
	}
	if options.Logger != nil {
		service.loggerLevel = LoggerLevel(options.Logger.Level())
	}
	return service
}

// Handler processes one EasyTierManagement RPC request.
func (s *Service) Handler(ctx context.Context, request rpc.RpcPacket) (rpc.RpcPacket, error) {
	if s == nil {
		return rpc.RpcPacket{}, fmt.Errorf("management service is nil")
	}
	if !request.IsRequest {
		return rpc.RpcPacket{}, fmt.Errorf("management RPC packet is not a request")
	}
	if request.Descriptor == nil {
		return rpc.RpcPacket{}, fmt.Errorf("management RPC descriptor is missing")
	}
	if request.Descriptor.ServiceName != ServiceName {
		return rpc.RpcPacket{}, fmt.Errorf("management RPC service is %q, want %q", request.Descriptor.ServiceName, ServiceName)
	}

	var response any
	switch request.Descriptor.MethodIndex {
	case methodNodeInfo:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode node.info request: %w", err)
		}
		response = nodeInfoResponse{Node: s.nodeInfo}
	case methodStatsPrometheus:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode stats.prometheus request: %w", err)
		}
		text, err := s.counters.PrometheusWithLabels("EasyTier management counter", s.metricLabels)
		if err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("render Prometheus statistics: %w", err)
		}
		response = prometheusResponse{Text: text}
	case methodLoggerGet:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode logger.get request: %w", err)
		}
		response = loggerResponse{Level: s.LoggerLevel()}
	case methodLoggerSet:
		var body loggerSetRequest
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode logger.set request: %w", err)
		}
		if err := s.SetLoggerLevel(body.Level); err != nil {
			return rpc.RpcPacket{}, err
		}
		response = loggerResponse{Level: body.Level}
	case methodInstanceList:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode instance.list request: %w", err)
		}
		response = instanceListResponse{Instances: s.instanceList()}
	case methodInstanceStatus:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode instance.status request: %w", err)
		}
		response = struct {
			Instances []InstanceStatus `json:"instances"`
		}{Instances: s.InstanceStatuses()}
	case methodInstanceStart:
		var body instanceRequest
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode instance.start request: %w", err)
		}
		status, err := s.InstanceStart(ctx, body.Name)
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = status
	case methodInstanceStop:
		var body instanceRequest
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode instance.stop request: %w", err)
		}
		if err := s.InstanceStop(body.Name); err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Stopped bool `json:"stopped"`
		}{Stopped: true}
	case methodStatsSnapshot:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode stats.snapshot request: %w", err)
		}
		response = struct {
			Metrics []StatsInfo `json:"metrics"`
		}{Metrics: s.StatsSnapshot()}
	case methodForwardStatus:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode forward.status request: %w", err)
		}
		statuses, err := s.ForwardStatusList()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Forwards []ForwardStatus `json:"forwards"`
		}{Forwards: statuses}
	case methodConfigGet:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode config.get request: %w", err)
		}
		value, err := s.ConfigGet()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = value
	case methodConfigSet:
		var body configSetRequest
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode config.set request: %w", err)
		}
		value, err := s.ConfigSet(ctx, body.TOML, body.Config)
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = value
	case methodPeerList:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode peer.list request: %w", err)
		}
		peers, err := s.PeerList()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Peers []PeerInfo `json:"peers"`
		}{Peers: peers}
	case methodRouteList:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode route.list request: %w", err)
		}
		routes, err := s.RouteList()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Routes []route.Route `json:"routes"`
		}{Routes: routes}
	case methodConnectorList:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode connector.list request: %w", err)
		}
		connectors, err := s.ConnectorList()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Connectors []ConnectorInfo `json:"connectors"`
		}{Connectors: connectors}
	case methodForwardList:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode forward.list request: %w", err)
		}
		rules, err := s.ForwardList()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Rules []forward.Rule `json:"rules"`
		}{Rules: rules}
	case methodForwardAdd:
		var body forwardRequest
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode forward.add request: %w", err)
		}
		if err := s.ForwardAdd(body.Rule); err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Rule forward.Rule `json:"rule"`
		}{Rule: body.Rule}
	case methodForwardRemove:
		var body forwardRequest
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode forward.remove request: %w", err)
		}
		if err := s.ForwardRemove(body.Rule); err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Removed bool `json:"removed"`
		}{Removed: true}
	case methodACLGet:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode acl.get request: %w", err)
		}
		aclInfo, err := s.ACLGet()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = aclInfo
	case methodACLStats:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode acl.stats request: %w", err)
		}
		aclStats, err := s.ACLStats()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = aclStats
	case methodCredentialList:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode credential.list request: %w", err)
		}
		credentials, err := s.CredentialList()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Credentials []CredentialInfo `json:"credentials"`
		}{Credentials: credentials}
	case methodCredentialGenerate:
		var body CredentialGenerateRequest
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode credential.generate request: %w", err)
		}
		generated, err := s.CredentialGenerate(body)
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = generated
	case methodCredentialRevoke:
		var body credentialRevokeRequest
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode credential.revoke request: %w", err)
		}
		if err := s.CredentialRevoke(body.ID); err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Success bool `json:"success"`
		}{Success: true}
	case methodDNSList:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode dns.list request: %w", err)
		}
		records, err := s.DNSList()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Zone    string          `json:"zone"`
			Records []DNSRecordInfo `json:"records"`
		}{Zone: s.DNSZone(), Records: records}
	case methodDNSSet:
		var body dnsSetRequest
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode dns.set request: %w", err)
		}
		if err := s.DNSSet(body.Name, body.Addresses); err != nil {
			return rpc.RpcPacket{}, err
		}
		records, err := s.DNSList()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		record := DNSRecordInfo{Name: body.Name, Addresses: append([]string(nil), body.Addresses...)}
		for _, item := range records {
			if item.Name == strings.TrimSuffix(strings.ToLower(body.Name), ".") {
				record = item
				break
			}
		}
		response = struct {
			Record DNSRecordInfo `json:"record"`
		}{Record: record}
	case methodDNSDelete:
		var body dnsDeleteRequest
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode dns.delete request: %w", err)
		}
		if err := s.DNSDelete(body.Name); err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Removed bool `json:"removed"`
		}{Removed: true}
	case methodDNSStatus:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode dns.status request: %w", err)
		}
		status, err := s.DNSStatus()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = status
	case methodMappedListenerList:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode mapped-listener.list request: %w", err)
		}
		listeners, err := s.MappedListenerList()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Listeners []MappedListenerStatus `json:"mapped_listeners"`
		}{Listeners: listeners}
	case methodMappedListenerAdd:
		var body struct {
			URL string `json:"url"`
		}
		if err := decodeRequest(request.Body, &body); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode mapped-listener.add request: %w", err)
		}
		if err := s.MappedListenerAdd(body.URL); err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct{}{}
	case methodMappedListenerRemove:
		var body2 struct {
			URL string `json:"url"`
		}
		if err := decodeRequest(request.Body, &body2); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode mapped-listener.remove request: %w", err)
		}
		if err := s.MappedListenerRemove(body2.URL); err != nil {
			return rpc.RpcPacket{}, err
		}
		response = struct {
			Removed bool `json:"removed"`
		}{Removed: true}
	case methodVPNPortal:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode vpn-portal request: %w", err)
		}
		info, err := s.VPNPortalInfo()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = info
	case methodProxy:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode proxy request: %w", err)
		}
		info, err := s.ProxyList()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = info
	case methodPeerCenter:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode peer-center request: %w", err)
		}
		info, err := s.PeerCenterInfo()
		if err != nil {
			return rpc.RpcPacket{}, err
		}
		response = info
	case methodWebSessions:
		if err := decodeRequest(request.Body, &struct{}{}); err != nil {
			return rpc.RpcPacket{}, fmt.Errorf("decode web.sessions request: %w", err)
		}
		if s.webClient == nil {
			return rpc.RpcPacket{}, ErrUnsupported
		}
		response = struct {
			Sessions []webclient.Session `json:"sessions"`
		}{Sessions: s.webClient.Sessions()}
	default:
		return rpc.RpcPacket{}, fmt.Errorf("management RPC method index %d is unsupported", request.Descriptor.MethodIndex)
	}

	body, err := json.Marshal(response)
	if err != nil {
		return rpc.RpcPacket{}, fmt.Errorf("marshal management RPC response: %w", err)
	}
	descriptor := *request.Descriptor
	return rpc.RpcPacket{
		Descriptor:  &descriptor,
		Body:        body,
		TotalPieces: request.TotalPieces,
		PieceIdx:    request.PieceIdx,
		TraceID:     request.TraceID,
	}, nil
}

// LoggerLevel returns the current logger level.
func (s *Service) LoggerLevel() LoggerLevel {
	s.loggerMu.RLock()
	defer s.loggerMu.RUnlock()
	return s.loggerLevel
}

// SetLoggerLevel validates and atomically updates the current logger level.
func (s *Service) SetLoggerLevel(level LoggerLevel) error {
	if !level.Valid() {
		return fmt.Errorf("invalid logger level %q", level)
	}
	if s.logger != nil {
		if err := s.logger.SetLevel(logging.Level(level)); err != nil {
			return fmt.Errorf("set logger level: %w", err)
		}
	}
	s.loggerMu.Lock()
	s.loggerLevel = level
	s.loggerMu.Unlock()
	return nil
}

// NodeInfo returns the node information served by the management service.
func (s *Service) NodeInfo() NodeInfo {
	if s == nil {
		return NodeInfo{}
	}
	return s.nodeInfo
}

// StatsPrometheus returns counters in Prometheus text exposition format.
func (s *Service) StatsPrometheus() (string, error) {
	if s == nil {
		return "", fmt.Errorf("management service is nil")
	}
	return s.counters.PrometheusWithLabels("EasyTier management counter", s.metricLabels)
}

// InstanceList returns the managed instances sorted by name.
func (s *Service) InstanceList() []InstanceInfo {
	if s == nil {
		return []InstanceInfo{}
	}
	return s.instanceList()
}

func (s *Service) instanceList() []InstanceInfo {
	if s.instances == nil {
		return []InstanceInfo{}
	}
	instances := s.instances.List()
	result := make([]InstanceInfo, len(instances))
	for i, item := range instances {
		result[i] = InstanceInfo{ID: item.ID(), Name: item.Name()}
	}
	return result
}

// InstanceStatuses returns lifecycle information for all managed instances.
func (s *Service) InstanceStatuses() []InstanceStatus {
	if s == nil || s.instances == nil {
		return []InstanceStatus{}
	}
	statuses := s.instances.Statuses()
	result := make([]InstanceStatus, len(statuses))
	for i, status := range statuses {
		result[i] = InstanceStatus{ID: status.ID, Name: status.Name, State: status.State, Running: status.Running}
	}
	return result
}

// InstanceStart starts one registered instance and returns its resulting
// lifecycle snapshot.
func (s *Service) InstanceStart(ctx context.Context, name string) (InstanceStatus, error) {
	if s == nil || s.instances == nil {
		return InstanceStatus{}, ErrUnsupported
	}
	if strings.TrimSpace(name) == "" {
		return InstanceStatus{}, errors.New("instance name is required")
	}
	if ctx == nil {
		return InstanceStatus{}, errors.New("instance start context is nil")
	}
	if err := s.instances.Start(ctx, name); err != nil {
		return InstanceStatus{}, err
	}
	for _, status := range s.InstanceStatuses() {
		if status.Name == name {
			return status, nil
		}
	}
	return InstanceStatus{}, instance.ErrInstanceNotFound
}

// InstanceStop stops one registered instance.
func (s *Service) InstanceStop(name string) error {
	if s == nil || s.instances == nil {
		return ErrUnsupported
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("instance name is required")
	}
	return s.instances.Stop(name)
}

// StatsSnapshot returns the sorted counter snapshot.
func (s *Service) StatsSnapshot() []StatsInfo {
	if s == nil || s.counters == nil {
		return []StatsInfo{}
	}
	snapshot := s.counters.SnapshotWithLabels()
	result := make([]StatsInfo, len(snapshot))
	for i, counter := range snapshot {
		result[i] = StatsInfo{Name: counter.Name, Value: counter.Value, Labels: cloneLabels(counter.Labels)}
	}
	return result
}

// ConfigGet returns the current explicit configuration and canonical TOML.
func (s *Service) ConfigGet() (ConfigInfo, error) {
	if s == nil {
		return ConfigInfo{}, errors.New("management service is nil")
	}
	s.componentMu.RLock()
	cfg, configured, readOnly := s.config, s.configSet, s.configReadOnly
	s.componentMu.RUnlock()
	if !configured {
		return ConfigInfo{}, ErrUnsupported
	}
	cfg, err := cloneConfig(cfg)
	if err != nil {
		return ConfigInfo{}, fmt.Errorf("clone management configuration: %w", err)
	}
	data, err := cfg.Marshal()
	if err != nil {
		return ConfigInfo{}, fmt.Errorf("marshal management configuration: %w", err)
	}
	return ConfigInfo{Config: cfg, TOML: string(data), ReadOnly: readOnly}, nil
}

// ConfigSet validates and atomically publishes a configuration. A callback is
// invoked before publication so callers can persist or construct the runtime.
func (s *Service) ConfigSet(ctx context.Context, text string, value *config.Config) (ConfigInfo, error) {
	if s == nil {
		return ConfigInfo{}, errors.New("management service is nil")
	}
	if ctx == nil {
		return ConfigInfo{}, errors.New("configuration context is nil")
	}
	if text == "" && value == nil {
		return ConfigInfo{}, errors.New("configuration TOML or config object is required")
	}
	if text != "" && value != nil {
		return ConfigInfo{}, errors.New("configuration TOML and config object are mutually exclusive")
	}
	var cfg config.Config
	var err error
	if text != "" {
		cfg, err = config.ParseTOML([]byte(text))
	} else {
		cfg = *value
		err = cfg.Validate()
	}
	if err != nil {
		return ConfigInfo{}, err
	}
	s.componentMu.RLock()
	readOnly, update, current, configured := s.configReadOnly, s.updateConfig, s.config, s.configSet
	s.componentMu.RUnlock()
	if readOnly {
		return ConfigInfo{}, errors.New("configuration is read-only")
	}
	if update == nil {
		return ConfigInfo{}, ErrUnsupported
	}
	if configured && unsupportedConfigChanged(current, cfg) {
		return ConfigInfo{}, fmt.Errorf("%w: unsupported runtime configuration", ErrUnsupported)
	}
	if !configured && hasUnsupportedRuntimeConfig(cfg) {
		return ConfigInfo{}, fmt.Errorf("%w: unsupported runtime configuration", ErrUnsupported)
	}
	if err := update(ctx, cfg); err != nil {
		return ConfigInfo{}, fmt.Errorf("apply management configuration: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return ConfigInfo{}, err
	}
	cfg, err = cloneConfig(cfg)
	if err != nil {
		return ConfigInfo{}, fmt.Errorf("clone management configuration: %w", err)
	}
	s.componentMu.Lock()
	s.config, s.configSet = cfg, true
	if s.connectorsFromConfig {
		s.connectors = connectorInfos(cfg.Peers)
	}
	s.componentMu.Unlock()
	return s.ConfigGet()
}

func unsupportedConfigChanged(before, after config.Config) bool {
	return !reflect.DeepEqual(before.VPNPortalConfig, after.VPNPortalConfig) ||
		before.Socks5Proxy != after.Socks5Proxy
}

func hasUnsupportedRuntimeConfig(value config.Config) bool {
	return value.VPNPortalConfig != nil || value.Socks5Proxy != ""
}

func connectorInfos(peers []config.Peer) []ConnectorInfo {
	result := make([]ConnectorInfo, 0, len(peers))
	for _, item := range peers {
		result = append(result, ConnectorInfo{URL: item.URI, Status: "configured"})
	}
	return result
}

func cloneConfig(value config.Config) (config.Config, error) {
	return value.Clone()
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for name, value := range labels {
		result[name] = value
	}
	return result
}

// PeerList returns authenticated live sessions sorted by peer ID.
func (s *Service) PeerList() ([]PeerInfo, error) {
	if s == nil || s.peers == nil {
		return nil, ErrUnsupported
	}
	peers := s.peers.Peers()
	ids := make([]uint32, 0, len(peers))
	for id := range peers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	result := make([]PeerInfo, 0, len(ids))
	for _, id := range ids {
		result = append(result, PeerInfo{ID: id, PeerCount: 1})
	}
	return result, nil
}

// RouteList returns the deterministic route-engine snapshot.
func (s *Service) RouteList() ([]route.Route, error) {
	if s == nil || s.routes == nil {
		return nil, ErrUnsupported
	}
	return s.routes.Snapshot(), nil
}

// ConnectorList returns configured connector sources. Discovery state is only
// reported when an owning connector manager supplies it through options.
func (s *Service) ConnectorList() ([]ConnectorInfo, error) {
	if s == nil {
		return nil, errors.New("management service is nil")
	}
	s.componentMu.RLock()
	result := append([]ConnectorInfo(nil), s.connectors...)
	s.componentMu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].URL < result[j].URL })
	if len(result) == 0 {
		return nil, ErrUnsupported
	}
	return result, nil
}

func (s *Service) ForwardList() ([]forward.Rule, error) {
	if s == nil || s.forwards == nil {
		return nil, ErrUnsupported
	}
	return s.forwards.List(), nil
}

func (s *Service) ForwardAdd(rule forward.Rule) error {
	if s == nil || s.forwards == nil {
		return ErrUnsupported
	}
	return s.forwards.Add(rule)
}

func (s *Service) ForwardRemove(rule forward.Rule) error {
	if s == nil || s.forwards == nil {
		return ErrUnsupported
	}
	return s.forwards.Remove(rule)
}

// ForwardStatusList returns observed listener and connection counters.
func (s *Service) ForwardStatusList() ([]ForwardStatus, error) {
	if s == nil || s.forwards == nil {
		return nil, ErrUnsupported
	}
	items := s.forwards.Statuses()
	result := make([]ForwardStatus, len(items))
	for i, item := range items {
		result[i] = ForwardStatus{Bind: item.Rule.Bind, Destination: item.Rule.Destination, State: item.State, ActiveConnections: item.ActiveConnections, Accepted: item.Accepted, Failed: item.Failed, BytesFromClient: item.BytesFromClient, BytesToClient: item.BytesToClient}
	}
	return result, nil
}

func (s *Service) ACLGet() (ACLInfo, error) {
	if s == nil || s.acl == nil {
		return ACLInfo{}, ErrUnsupported
	}
	return ACLInfo{DefaultAction: s.acl.DefaultAction(), Rules: s.acl.Rules(), Stats: aclStats(s.acl.StatsSnapshot())}, nil
}

func (s *Service) ACLStats() (ACLStats, error) {
	if s == nil || s.acl == nil {
		return ACLStats{}, ErrUnsupported
	}
	return aclStats(s.acl.StatsSnapshot()), nil
}

func aclStats(snapshot acl.Stats) ACLStats {
	result := ACLStats{Evaluations: snapshot.Evaluations, DefaultAllows: snapshot.DefaultAllows, DefaultDrops: snapshot.DefaultDrops, Rules: make([]ACLRuleStats, len(snapshot.Rules))}
	for i, rule := range snapshot.Rules {
		result.Rules[i] = ACLRuleStats{Name: rule.Name, Priority: rule.Priority, Action: rule.Action, Matches: rule.Matches}
	}
	return result
}

func (s *Service) CredentialList() ([]CredentialInfo, error) {
	if s == nil || s.credentials == nil {
		return nil, ErrUnsupported
	}
	items := s.credentials.List(time.Now())
	result := make([]CredentialInfo, len(items))
	for i, item := range items {
		result[i] = credentialInfo(item)
	}
	return result, nil
}

func (s *Service) CredentialGenerate(request CredentialGenerateRequest) (CredentialGenerateResponse, error) {
	if s == nil || s.credentials == nil {
		return CredentialGenerateResponse{}, ErrUnsupported
	}
	if request.TTLSeconds <= 0 {
		return CredentialGenerateResponse{}, errors.New("credential TTL must be positive")
	}
	prefixes := make([]netip.Prefix, 0, len(request.ProxyCIDRs))
	for _, raw := range request.ProxyCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() {
			return CredentialGenerateResponse{}, fmt.Errorf("invalid credential proxy CIDR %q", raw)
		}
		prefixes = append(prefixes, prefix)
	}
	reusable := true
	if request.Reusable != nil {
		reusable = *request.Reusable
	}
	item, err := s.credentials.Generate(time.Duration(request.TTLSeconds)*time.Second, request.ID,
		credential.WithGroups(request.Groups...), credential.WithRelayPermission(request.RelayAllowed),
		credential.WithProxyCIDRs(prefixes...), credential.WithReusable(reusable))
	if err != nil {
		return CredentialGenerateResponse{}, err
	}
	if len(item.PrivateKey) == 0 {
		return CredentialGenerateResponse{}, errors.New("credential manager did not return generated secret")
	}
	return CredentialGenerateResponse{CredentialID: item.ID, CredentialSecret: base64.StdEncoding.EncodeToString(item.PrivateKey)}, nil
}

func (s *Service) CredentialRevoke(id string) error {
	if s == nil || s.credentials == nil {
		return ErrUnsupported
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("credential ID is required")
	}
	if !s.credentials.Revoke(id) {
		return credential.ErrNotFound
	}
	return nil
}

func credentialInfo(item credential.Credential) CredentialInfo {
	prefixes := make([]string, len(item.ProxyCIDRs))
	for i, prefix := range item.ProxyCIDRs {
		prefixes[i] = prefix.String()
	}
	sort.Strings(prefixes)
	return CredentialInfo{ID: item.ID, Groups: append([]string(nil), item.Groups...), RelayAllowed: item.RelayAllowed, ProxyCIDRs: prefixes, Reusable: item.Reusable, ExpiresAt: item.ExpiresAt.UTC().Format(time.RFC3339Nano)}
}

func (s *Service) DNSZone() string {
	if s == nil || s.dns == nil {
		return ""
	}
	return s.dns.Zone()
}

func (s *Service) DNSList() ([]DNSRecordInfo, error) {
	if s == nil || s.dns == nil {
		return nil, ErrUnsupported
	}
	records := s.dns.Records()
	result := make([]DNSRecordInfo, len(records))
	for i, record := range records {
		addresses := make([]string, len(record.Addresses))
		for j, address := range record.Addresses {
			addresses[j] = address.String()
		}
		sort.Strings(addresses)
		result[i] = DNSRecordInfo{Name: record.Name, Addresses: addresses, TTL: record.TTL, ExpiresAt: formatTime(record.ExpiresAt)}
	}
	return result, nil
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func (s *Service) DNSStatus() (DNSStatus, error) {
	if s == nil || s.dns == nil {
		return DNSStatus{}, ErrUnsupported
	}
	status := s.dns.Status()
	result := DNSStatus{Address: status.Address, Zone: status.Zone, TTL: status.TTL, Serving: status.Serving, Closed: status.Closed, UpstreamTimeout: status.UpstreamTimeout.String(), Upstreams: make([]DNSUpstreamInfo, len(status.Upstreams))}
	for i, upstream := range status.Upstreams {
		result.Upstreams[i] = DNSUpstreamInfo{Address: upstream.Address, State: upstream.State, Queries: upstream.Queries, Successes: upstream.Successes, Failures: upstream.Failures, LastError: upstream.LastError, LastChecked: formatTime(upstream.LastChecked)}
	}
	return result, nil
}

// MappedListenerList reports mapped listeners from the dedicated store when
// available, otherwise from configuration. When a store is configured, its
// status is authoritative; otherwise the configuration is listed as active.
func (s *Service) MappedListenerList() ([]MappedListenerStatus, error) {
	if s == nil {
		return nil, errors.New("management service is nil")
	}
	if s.mappedListeners != nil {
		list := s.mappedListeners.List()
		if list == nil {
			return []MappedListenerStatus{}, nil
		}
		return list, nil
	}
	s.componentMu.RLock()
	configured, ok := s.config, s.configSet
	s.componentMu.RUnlock()
	if !ok {
		return nil, ErrUnsupported
	}
	result := make([]MappedListenerStatus, len(configured.MappedListeners))
	for i, listener := range configured.MappedListeners {
		result[i] = MappedListenerStatus{URL: listener, State: "active"}
	}
	return result, nil
}

func (s *Service) MappedListenerAdd(url string) error {
	if s == nil {
		return errors.New("management service is nil")
	}
	if s.mappedListeners != nil {
		if err := s.mappedListeners.Add(url); err != nil {
			return err
		}
		// Also keep config in sync for ConfigGet visibility.
		s.componentMu.Lock()
		if s.configSet {
			found := false
			for _, u := range s.config.MappedListeners {
				if u == url {
					found = true
					break
				}
			}
			if !found {
				s.config.MappedListeners = append(s.config.MappedListeners, url)
			}
		}
		s.componentMu.Unlock()
		return nil
	}
	// Fallback to config-only store when no dedicated manager is configured.
	s.componentMu.Lock()
	defer s.componentMu.Unlock()
	if !s.configSet {
		return ErrUnsupported
	}
	for _, u := range s.config.MappedListeners {
		if u == url {
			return fmt.Errorf("mapped listener already exists: %q", url)
		}
	}
	if err := config.ValidateMappedListenerURL(url); err != nil {
		return err
	}
	s.config.MappedListeners = append(s.config.MappedListeners, url)
	return nil
}

func (s *Service) MappedListenerRemove(url string) error {
	if s == nil {
		return errors.New("management service is nil")
	}
	if s.mappedListeners != nil {
		if err := s.mappedListeners.Remove(url); err != nil {
			return err
		}
		s.componentMu.Lock()
		if s.configSet {
			filtered := s.config.MappedListeners[:0]
			for _, u := range s.config.MappedListeners {
				if u != url {
					filtered = append(filtered, u)
				}
			}
			s.config.MappedListeners = append([]string(nil), filtered...)
		}
		s.componentMu.Unlock()
		return nil
	}
	s.componentMu.Lock()
	defer s.componentMu.Unlock()
	if !s.configSet {
		return ErrUnsupported
	}
	found := false
	for _, u := range s.config.MappedListeners {
		if u == url {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("mapped listener not found: %q", url)
	}
	filtered := s.config.MappedListeners[:0]
	for _, u := range s.config.MappedListeners {
		if u != url {
			filtered = append(filtered, u)
		}
	}
	s.config.MappedListeners = append([]string(nil), filtered...)
	return nil
}

func (s *Service) DNSSet(name string, addresses []string) error {
	if s == nil || s.dns == nil {
		return ErrUnsupported
	}
	parsed := make([]netip.Addr, len(addresses))
	for i, raw := range addresses {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return fmt.Errorf("invalid DNS address %q", raw)
		}
		parsed[i] = address
	}
	return s.dns.SetRecord(name, parsed...)
}

func (s *Service) DNSDelete(name string) error {
	if s == nil || s.dns == nil {
		return ErrUnsupported
	}
	return s.dns.DeleteRecord(name)
}

// WebSessions returns configuration-server sessions when a webclient server
// is configured.
func (s *Service) WebSessions() ([]webclient.Session, error) {
	if s == nil || s.webClient == nil {
		return nil, ErrUnsupported
	}
	return s.webClient.Sessions(), nil
}

func (s *Service) VPNPortalInfo() (VPNPortalInfo, error) {
	if s == nil {
		return VPNPortalInfo{}, errors.New("management service is nil")
	}
	s.componentMu.RLock()
	cfg, ok := s.config, s.configSet
	portal := s.vpnPortal
	s.componentMu.RUnlock()
	if !ok || cfg.VPNPortalConfig == nil {
		return VPNPortalInfo{VPNType: "wireguard", ClientConfig: "ERROR: Wireguard VPN Portal Not Started", ConnectedClients: []string{}}, nil
	}
	// Use vpnportal package for deterministic config generation.
	clientPrivB64, serverPubB64, err := vpnPortalKeys(cfg.NetworkIdentity.NetworkName, cfg.NetworkIdentity.NetworkSecret)
	if err != nil {
		return VPNPortalInfo{}, err
	}
	allowIPs := []string{}
	for _, pn := range cfg.ProxyNetworks {
		allowIPs = append(allowIPs, pn.CIDR)
	}
	if cfg.IPv4 != "" {
		if prefix, ok, _ := cfg.IPv4Prefix(); ok {
			allowIPs = append(allowIPs, prefix.String())
		}
	}
	allowIPs = append(allowIPs, cfg.VPNPortalConfig.ClientCIDR)
	allowIPsStr := strings.Join(allowIPs, ",")
	listenAddr := cfg.VPNPortalConfig.WireGuardListen
	if portal != nil {
		if la, ok := portal.(interface{ ListenAddr() net.Addr }); ok {
			if addr := la.ListenAddr(); addr != nil {
				listenAddr = addr.String()
			}
		}
	}
	clientCIDR := cfg.VPNPortalConfig.ClientCIDR
	firstAddr := clientCIDR
	if prefix, err := netip.ParsePrefix(clientCIDR); err == nil {
		firstAddr = prefix.Addr().String() + "/32"
	}
	configStr := fmt.Sprintf("\n[Interface]\nPrivateKey = %s\nAddress = %s # should assign an ip from this cidr manually\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s # should be the public ip(or domain) of the vpn server\nPersistentKeepalive = 25\n", clientPrivB64, firstAddr, serverPubB64, allowIPsStr, listenAddr)
	clients := []string{}
	if portal != nil {
		clients = portal.ListClients()
		if clients == nil {
			clients = []string{}
		}
	}
	return VPNPortalInfo{VPNType: "wireguard", ClientConfig: configStr, ConnectedClients: clients}, nil
}

func vpnPortalKeys(networkName, networkSecret string) (string, string, error) {
	keySeed := networkName + networkSecret
	serverDigest := protocol.GenerateDigestFromStrings("server", keySeed)
	clientDigest := protocol.GenerateDigestFromStrings("client", keySeed)
	serverPub, err := deriveX25519PublicKey(serverDigest)
	if err != nil {
		return "", "", fmt.Errorf("derive WireGuard public key: %w", err)
	}
	clientPrivB64 := base64.StdEncoding.EncodeToString(clientDigest[:])
	serverPubB64 := base64.StdEncoding.EncodeToString(serverPub[:])
	return clientPrivB64, serverPubB64, nil
}

func deriveX25519PublicKey(privateKey [32]byte) ([32]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privateKey[:])
	if err != nil {
		return [32]byte{}, err
	}
	pub := priv.PublicKey()
	b := pub.Bytes()
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func (s *Service) ProxyList() (ProxyInfo, error) {
	if s == nil {
		return ProxyInfo{}, errors.New("management service is nil")
	}
	if s.proxyProvider != nil {
		entries := s.proxyProvider.ProxyEntries()
		if entries == nil {
			entries = []ProxyEntry{}
		}
		return ProxyInfo{Entries: entries}, nil
	}
	// No dedicated proxy manager yet; return empty list which is the Rust
	// behavior when no TCP proxy entries exist.
	return ProxyInfo{Entries: []ProxyEntry{}}, nil
}

// SetVPNPortal atomically updates the VPN portal provider.
func (s *Service) SetVPNPortal(provider VPNPortalProvider) {
	if s == nil {
		return
	}
	s.componentMu.Lock()
	s.vpnPortal = provider
	s.componentMu.Unlock()
}

func (s *Service) PeerCenterInfo() (PeerCenterInfo, error) {
	if s == nil {
		return PeerCenterInfo{}, errors.New("management service is nil")
	}
	m := make(map[string]PeerCenterPeerGroup)
	if s.peers != nil {
		peers := s.peers.Peers()
		for id := range peers {
			key := fmt.Sprintf("%d", id)
			m[key] = PeerCenterPeerGroup{DirectPeers: make(map[string]PeerCenterDirectPeer)}
		}
	}
	if m == nil {
		m = make(map[string]PeerCenterPeerGroup)
	}
	return PeerCenterInfo{GlobalPeerMap: m}, nil
}

func decodeRequest(body []byte, value any) error {
	if len(body) == 0 || !strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		return fmt.Errorf("request must be a JSON object")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request contains multiple JSON values")
		}
		return err
	}
	return nil
}

// Client calls an EasyTierManagement service at Address.
type Client struct {
	Address  string
	FromPeer uint32
	ToPeer   uint32

	nextTransaction atomic.Int64
}

// NewClient creates a client that sends requests between the supplied peer IDs.
func NewClient(address string, fromPeer, toPeer uint32) *Client {
	return &Client{Address: address, FromPeer: fromPeer, ToPeer: toPeer}
}

// NodeInfo gets node information from the service.
func (c *Client) NodeInfo(ctx context.Context) (NodeInfo, error) {
	var response nodeInfoResponse
	if err := c.call(ctx, methodNodeInfo, struct{}{}, &response); err != nil {
		return NodeInfo{}, err
	}
	return response.Node, nil
}

// StatsPrometheus gets counters in Prometheus text exposition format.
func (c *Client) StatsPrometheus(ctx context.Context) (string, error) {
	var response prometheusResponse
	if err := c.call(ctx, methodStatsPrometheus, struct{}{}, &response); err != nil {
		return "", err
	}
	return response.Text, nil
}

// LoggerGet gets the active logger level.
func (c *Client) LoggerGet(ctx context.Context) (LoggerLevel, error) {
	var response loggerResponse
	if err := c.call(ctx, methodLoggerGet, struct{}{}, &response); err != nil {
		return "", err
	}
	if !response.Level.Valid() {
		return "", fmt.Errorf("management RPC returned invalid logger level %q", response.Level)
	}
	return response.Level, nil
}

// LoggerSet validates and sets the active logger level.
func (c *Client) LoggerSet(ctx context.Context, level LoggerLevel) (LoggerLevel, error) {
	if !level.Valid() {
		return "", fmt.Errorf("invalid logger level %q", level)
	}
	var response loggerResponse
	if err := c.call(ctx, methodLoggerSet, loggerSetRequest{Level: level}, &response); err != nil {
		return "", err
	}
	if !response.Level.Valid() {
		return "", fmt.Errorf("management RPC returned invalid logger level %q", response.Level)
	}
	return response.Level, nil
}

// InstanceList gets managed instances sorted by name.
func (c *Client) InstanceList(ctx context.Context) ([]InstanceInfo, error) {
	var response instanceListResponse
	if err := c.call(ctx, methodInstanceList, struct{}{}, &response); err != nil {
		return nil, err
	}
	if response.Instances == nil {
		return []InstanceInfo{}, nil
	}
	return response.Instances, nil
}

// InstanceStatusList gets lifecycle states for managed instances.
func (c *Client) InstanceStatusList(ctx context.Context) ([]InstanceStatus, error) {
	var response struct {
		Instances []InstanceStatus `json:"instances"`
	}
	if err := c.call(ctx, methodInstanceStatus, struct{}{}, &response); err != nil {
		return nil, err
	}
	return response.Instances, nil
}

func (c *Client) InstanceStart(ctx context.Context, name string) (InstanceStatus, error) {
	var response InstanceStatus
	if err := c.call(ctx, methodInstanceStart, instanceRequest{Name: name}, &response); err != nil {
		return InstanceStatus{}, err
	}
	return response, nil
}

func (c *Client) InstanceStop(ctx context.Context, name string) error {
	var response struct {
		Stopped bool `json:"stopped"`
	}
	if err := c.call(ctx, methodInstanceStop, instanceRequest{Name: name}, &response); err != nil {
		return err
	}
	if !response.Stopped {
		return errors.New("instance was not stopped")
	}
	return nil
}

func (c *Client) StatsSnapshot(ctx context.Context) ([]StatsInfo, error) {
	var response struct {
		Metrics []StatsInfo `json:"metrics"`
	}
	if err := c.call(ctx, methodStatsSnapshot, struct{}{}, &response); err != nil {
		return nil, err
	}
	return response.Metrics, nil
}

func (c *Client) ForwardStatusList(ctx context.Context) ([]ForwardStatus, error) {
	var response struct {
		Forwards []ForwardStatus `json:"forwards"`
	}
	if err := c.call(ctx, methodForwardStatus, struct{}{}, &response); err != nil {
		return nil, err
	}
	return response.Forwards, nil
}

func (c *Client) ConfigGet(ctx context.Context) (ConfigInfo, error) {
	var response ConfigInfo
	if err := c.call(ctx, methodConfigGet, struct{}{}, &response); err != nil {
		return ConfigInfo{}, err
	}
	return response, nil
}

func (c *Client) ConfigSetTOML(ctx context.Context, text string) (ConfigInfo, error) {
	var response ConfigInfo
	if err := c.call(ctx, methodConfigSet, configSetRequest{TOML: text}, &response); err != nil {
		return ConfigInfo{}, err
	}
	return response, nil
}

// ConfigSet publishes a validated configuration object through the management
// service. Callers use this for focused configuration patches when the runtime
// has no separate patch RPC.
func (c *Client) ConfigSet(ctx context.Context, value config.Config) (ConfigInfo, error) {
	var response ConfigInfo
	if err := c.call(ctx, methodConfigSet, configSetRequest{Config: &value}, &response); err != nil {
		return ConfigInfo{}, err
	}
	return response, nil
}

func (c *Client) PeerList(ctx context.Context) ([]PeerInfo, error) {
	var response struct {
		Peers []PeerInfo `json:"peers"`
	}
	if err := c.call(ctx, methodPeerList, struct{}{}, &response); err != nil {
		return nil, err
	}
	return response.Peers, nil
}

func (c *Client) RouteList(ctx context.Context) ([]route.Route, error) {
	var response struct {
		Routes []route.Route `json:"routes"`
	}
	if err := c.call(ctx, methodRouteList, struct{}{}, &response); err != nil {
		return nil, err
	}
	return response.Routes, nil
}

func (c *Client) ConnectorList(ctx context.Context) ([]ConnectorInfo, error) {
	var response struct {
		Connectors []ConnectorInfo `json:"connectors"`
	}
	if err := c.call(ctx, methodConnectorList, struct{}{}, &response); err != nil {
		return nil, err
	}
	return response.Connectors, nil
}

func (c *Client) ForwardList(ctx context.Context) ([]forward.Rule, error) {
	var response struct {
		Rules []forward.Rule `json:"rules"`
	}
	if err := c.call(ctx, methodForwardList, struct{}{}, &response); err != nil {
		return nil, err
	}
	return response.Rules, nil
}

func (c *Client) ForwardAdd(ctx context.Context, rule forward.Rule) (forward.Rule, error) {
	var response struct {
		Rule forward.Rule `json:"rule"`
	}
	if err := c.call(ctx, methodForwardAdd, forwardRequest{Rule: rule}, &response); err != nil {
		return forward.Rule{}, err
	}
	return response.Rule, nil
}

func (c *Client) ForwardRemove(ctx context.Context, rule forward.Rule) error {
	var response struct {
		Removed bool `json:"removed"`
	}
	if err := c.call(ctx, methodForwardRemove, forwardRequest{Rule: rule}, &response); err != nil {
		return err
	}
	if !response.Removed {
		return errors.New("forwarding rule was not removed")
	}
	return nil
}

func (c *Client) ACLGet(ctx context.Context) (ACLInfo, error) {
	var response ACLInfo
	if err := c.call(ctx, methodACLGet, struct{}{}, &response); err != nil {
		return ACLInfo{}, err
	}
	return response, nil
}

func (c *Client) ACLStats(ctx context.Context) (ACLStats, error) {
	var response ACLStats
	if err := c.call(ctx, methodACLStats, struct{}{}, &response); err != nil {
		return ACLStats{}, err
	}
	return response, nil
}

func (c *Client) CredentialList(ctx context.Context) ([]CredentialInfo, error) {
	var response struct {
		Credentials []CredentialInfo `json:"credentials"`
	}
	if err := c.call(ctx, methodCredentialList, struct{}{}, &response); err != nil {
		return nil, err
	}
	return response.Credentials, nil
}

func (c *Client) CredentialGenerate(ctx context.Context, request CredentialGenerateRequest) (CredentialGenerateResponse, error) {
	var response CredentialGenerateResponse
	if err := c.call(ctx, methodCredentialGenerate, request, &response); err != nil {
		return CredentialGenerateResponse{}, err
	}
	return response, nil
}

func (c *Client) CredentialRevoke(ctx context.Context, id string) error {
	var response struct {
		Success bool `json:"success"`
	}
	if err := c.call(ctx, methodCredentialRevoke, credentialRevokeRequest{ID: id}, &response); err != nil {
		return err
	}
	if !response.Success {
		return errors.New("credential was not revoked")
	}
	return nil
}

func (c *Client) DNSList(ctx context.Context) (string, []DNSRecordInfo, error) {
	var response struct {
		Zone    string          `json:"zone"`
		Records []DNSRecordInfo `json:"records"`
	}
	if err := c.call(ctx, methodDNSList, struct{}{}, &response); err != nil {
		return "", nil, err
	}
	return response.Zone, response.Records, nil
}

func (c *Client) DNSSet(ctx context.Context, name string, addresses []string) (DNSRecordInfo, error) {
	var response struct {
		Record DNSRecordInfo `json:"record"`
	}
	if err := c.call(ctx, methodDNSSet, dnsSetRequest{Name: name, Addresses: addresses}, &response); err != nil {
		return DNSRecordInfo{}, err
	}
	return response.Record, nil
}

func (c *Client) DNSDelete(ctx context.Context, name string) error {
	var response struct {
		Removed bool `json:"removed"`
	}
	if err := c.call(ctx, methodDNSDelete, dnsDeleteRequest{Name: name}, &response); err != nil {
		return err
	}
	if !response.Removed {
		return errors.New("DNS record was not removed")
	}
	return nil
}

func (c *Client) DNSStatus(ctx context.Context) (DNSStatus, error) {
	var response DNSStatus
	if err := c.call(ctx, methodDNSStatus, struct{}{}, &response); err != nil {
		return DNSStatus{}, err
	}
	return response, nil
}

func (c *Client) MappedListenerList(ctx context.Context) ([]MappedListenerStatus, error) {
	var response struct {
		Listeners []MappedListenerStatus `json:"mapped_listeners"`
	}
	if err := c.call(ctx, methodMappedListenerList, struct{}{}, &response); err != nil {
		return nil, err
	}
	return response.Listeners, nil
}

func (c *Client) MappedListenerAdd(ctx context.Context, url string) error {
	return c.call(ctx, methodMappedListenerAdd, struct {
		URL string `json:"url"`
	}{URL: url}, &struct{}{})
}

func (c *Client) MappedListenerRemove(ctx context.Context, url string) error {
	var response struct {
		Removed bool `json:"removed"`
	}
	if err := c.call(ctx, methodMappedListenerRemove, struct {
		URL string `json:"url"`
	}{URL: url}, &response); err != nil {
		return err
	}
	if !response.Removed {
		return errors.New("mapped listener was not removed")
	}
	return nil
}

func (c *Client) VPNPortal(ctx context.Context) (VPNPortalInfo, error) {
	var response VPNPortalInfo
	if err := c.call(ctx, methodVPNPortal, struct{}{}, &response); err != nil {
		return VPNPortalInfo{}, err
	}
	return response, nil
}

func (c *Client) Proxy(ctx context.Context) (ProxyInfo, error) {
	var response ProxyInfo
	if err := c.call(ctx, methodProxy, struct{}{}, &response); err != nil {
		return ProxyInfo{}, err
	}
	if response.Entries == nil {
		response.Entries = []ProxyEntry{}
	}
	return response, nil
}

func (c *Client) PeerCenter(ctx context.Context) (PeerCenterInfo, error) {
	var response PeerCenterInfo
	if err := c.call(ctx, methodPeerCenter, struct{}{}, &response); err != nil {
		return PeerCenterInfo{}, err
	}
	if response.GlobalPeerMap == nil {
		response.GlobalPeerMap = make(map[string]PeerCenterPeerGroup)
	}
	return response, nil
}

func (c *Client) WebSessions(ctx context.Context) ([]webclient.Session, error) {
	var response struct {
		Sessions []webclient.Session `json:"sessions"`
	}
	if err := c.call(ctx, methodWebSessions, struct{}{}, &response); err != nil {
		return nil, err
	}
	return response.Sessions, nil
}

func (c *Client) call(ctx context.Context, method uint32, request, response any) error {
	if c == nil {
		return fmt.Errorf("management client is nil")
	}
	if c.Address == "" {
		return fmt.Errorf("management client address is empty")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal management request: %w", err)
	}
	packet := rpc.RpcPacket{
		FromPeer:      c.FromPeer,
		ToPeer:        c.ToPeer,
		TransactionID: c.nextTransaction.Add(1),
		Descriptor:    &rpc.RpcDescriptor{ServiceName: ServiceName, MethodIndex: method},
		Body:          body,
		IsRequest:     true,
		TotalPieces:   1,
	}
	packet, err = rpc.Call(ctx, c.Address, packet)
	if err != nil {
		return err
	}
	if packet.Descriptor == nil || packet.Descriptor.ServiceName != ServiceName || packet.Descriptor.MethodIndex != method {
		return fmt.Errorf("management RPC response descriptor does not match request")
	}
	var rpcError struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(packet.Body, &rpcError); err == nil && rpcError.Error != "" {
		if rpcError.Error == ErrUnsupported.Error() || strings.HasPrefix(rpcError.Error, ErrUnsupported.Error()+":") {
			return ErrUnsupported
		}
		return errors.New(rpcError.Error)
	}
	if err := decodeResponse(packet.Body, response); err != nil {
		return fmt.Errorf("decode management RPC response: %w", err)
	}
	return nil
}

func decodeResponse(body []byte, value any) error {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("response contains multiple JSON values")
		}
		return err
	}
	return nil
}

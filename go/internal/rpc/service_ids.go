// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Service registry: numeric service IDs and typed helpers.
//
// Rust reference: easytier/src/peer_center/instance.rs
// (SERVICE_ID = 50), easytier/src/peers/peer_ospf_route.rs (SERVICE_ID = 7),
// easytier/src/peers/foreign_network_manager.rs
// (FOREIGN_NETWORK_SERVICE_ID = 1), easytier/src/connector/direct.rs
// (DIRECT_CONNECTOR_SERVICE_ID = 1),
// easytier/src/common/constants.rs (UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID = 2).
// In Rust these IDs are declared next to each service; the on-wire RPC
// descriptor itself carries (domain, proto, service_name, method_index)
// (see easytier/src/proto/rpc_impl/service_registry.rs ServiceKey). The Go
// port mirrors both: each numeric ID is bound to its canonical service name
// so registries stay stable and auditable.
package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Numeric service IDs mirroring the Rust constants.
const (
	// ServiceIDForeignNetwork matches FOREIGN_NETWORK_SERVICE_ID.
	ServiceIDForeignNetwork uint32 = 1
	// ServiceIDDirectConnector matches DIRECT_CONNECTOR_SERVICE_ID.
	ServiceIDDirectConnector uint32 = 1
	// ServiceIDHolePunchConnector matches UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID.
	ServiceIDHolePunchConnector uint32 = 2
	// ServiceIDOSPFRoute matches peer_ospf_route SERVICE_ID.
	ServiceIDOSPFRoute uint32 = 7
	// ServiceIDPeerCenter matches peer_center SERVICE_ID.
	ServiceIDPeerCenter uint32 = 50
)

// Canonical service names used in RPC descriptors. These must match the
// reference proto service names byte-for-byte, because the reference
// registry keys services by (domain, service_name, proto_name).
const (
	ServiceNameForeignNetwork  = "foreign_network"
	ServiceNameDirectConnector = "direct_connector"
	ServiceNameHolePunch       = "hole_punch"
	ServiceNameOSPFRoute       = "OspfRouteRpc"
)

// ServiceBinding binds a numeric ID to its canonical service name.
type ServiceBinding struct {
	ID   uint32
	Name string
}

// WellKnownServices lists the numeric-to-name bindings above.
var WellKnownServices = []ServiceBinding{
	{ID: ServiceIDForeignNetwork, Name: ServiceNameForeignNetwork},
	{ID: ServiceIDDirectConnector, Name: ServiceNameDirectConnector},
	{ID: ServiceIDHolePunchConnector, Name: ServiceNameHolePunch},
	{ID: ServiceIDOSPFRoute, Name: ServiceNameOSPFRoute},
	{ID: ServiceIDPeerCenter, Name: "peer_center"},
}

// ServiceNameForID returns the canonical service name for a numeric ID.
func ServiceNameForID(id uint32) (string, bool) {
	for _, binding := range WellKnownServices {
		if binding.ID == id {
			return binding.Name, true
		}
	}
	return "", false
}

// MethodHandler handles one method invocation on a FuncService.
type MethodHandler func(ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error)

// FuncService is a programmable RpcService: methods are installed with
// OnMethod instead of code generation. It is the Go counterpart of Rust's
// rpc_server().registry().register(...) pattern.
type FuncService struct {
	name string

	mu       sync.RWMutex
	handlers map[uint32]MethodHandler
}

// NewFuncService creates a service published under name.
func NewFuncService(name string) *FuncService {
	return &FuncService{name: name, handlers: make(map[uint32]MethodHandler)}
}

// ServiceName implements RpcService.
func (s *FuncService) ServiceName() string { return s.name }

// OnMethod installs the handler for one method index.
func (s *FuncService) OnMethod(methodIndex uint32, handler MethodHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[methodIndex] = handler
}

// HandleMethod implements RpcService by dispatching to the installed handler.
func (s *FuncService) HandleMethod(methodIndex uint32, ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
	s.mu.RLock()
	handler := s.handlers[methodIndex]
	s.mu.RUnlock()
	if handler == nil {
		return nil, fmt.Errorf("service %q has no method %d", s.name, methodIndex)
	}
	return handler(ctx, fromPeerID, requestBody)
}

// CallJSON marshals req as JSON, invokes the remote method, and unmarshals
// the response envelope into Resp. It is the thin typed-call helper used by
// services (peercenter, OSPF, external clients) that encode bodies as JSON.
func CallJSON[Resp any](ctx context.Context, mgr *PeerRpcManager, dstPeerID uint32, domain, serviceName string, methodIndex uint32, req any) (Resp, error) {
	var zero Resp
	body, err := json.Marshal(req)
	if err != nil {
		return zero, fmt.Errorf("marshal rpc request: %w", err)
	}
	raw, err := mgr.Call(ctx, dstPeerID, domain, serviceName, methodIndex, body)
	if err != nil {
		return zero, err
	}
	if len(raw) == 0 {
		return zero, nil
	}
	var resp Resp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return zero, fmt.Errorf("decode rpc response: %w", err)
	}
	return resp, nil
}

// JSONMethod adapts a typed handler func into a MethodHandler.
func JSONMethod[Req any, Resp any](fn func(ctx context.Context, fromPeerID uint32, req Req) (Resp, error)) MethodHandler {
	return func(ctx context.Context, fromPeerID uint32, requestBody []byte) ([]byte, error) {
		var req Req
		if len(requestBody) > 0 {
			if err := json.Unmarshal(requestBody, &req); err != nil {
				return nil, fmt.Errorf("decode rpc request: %w", err)
			}
		}
		resp, err := fn(ctx, fromPeerID, req)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(resp)
		if err != nil {
			return nil, fmt.Errorf("encode rpc response: %w", err)
		}
		return raw, nil
	}
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webconsole

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"google.golang.org/protobuf/proto"
)

// Wire constants shared by every config-server session. The console tunnel is
// a two-endpoint link: both endpoints address each other as peer 1 inside the
// empty RPC domain, and the three services below are registered/consumed there.
const (
	// ConsolePeerID is the peer ID both tunnel endpoints use.
	ConsolePeerID uint32 = 1

	// ConsoleDomain is the RPC domain used by config-server sessions.
	ConsoleDomain = ""

	// ServiceWebServer is the console-side service (GetFeature, Heartbeat).
	ServiceWebServer = "WebServerService"
	// ServiceWebClient is the machine-side service the console drives.
	ServiceWebClient = "WebClientService"
	// ServiceConfigRPC is the machine-side live config service.
	ServiceConfigRPC = "ConfigRpc"

	// Method indices are 1-based, like the reference generator emits them
	// (`index = declaration_position + 1`; 0 is reserved for "unknown").
	//
	// WebServerService (web.proto declaration order: Heartbeat, GetFeature).
	MethodHeartbeat  uint32 = 1
	MethodGetFeature uint32 = 2

	// WebClientService (api_manage.proto declaration order).
	MethodValidateConfig           uint32 = 1
	MethodRunNetworkInstance       uint32 = 2
	MethodRetainNetworkInstance    uint32 = 3
	MethodCollectNetworkInfo       uint32 = 4
	MethodListNetworkInstance      uint32 = 5
	MethodDeleteNetworkInstance    uint32 = 6
	MethodGetNetworkInstanceConfig uint32 = 7
	MethodListNetworkInstanceMeta  uint32 = 8

	// ConfigRpc (api_config.proto declaration order: PatchConfig, GetConfig).
	MethodPatchConfig uint32 = 1
	MethodGetConfig   uint32 = 2
)

// channelTransport adapts a transport.PacketChannel to rpc.RpcTransport. The
// console link has exactly one remote endpoint, so the destination peer ID is
// ignored and the packet is written as-is.
type channelTransport struct {
	channel transport.PacketChannel
}

// MyPeerID implements rpc.RpcTransport.
func (t *channelTransport) MyPeerID() uint32 { return ConsolePeerID }

// Send implements rpc.RpcTransport.
func (t *channelTransport) Send(ctx context.Context, _ uint32, packet protocol.Packet) error {
	return t.channel.Send(ctx, packet)
}

// Session is one live RPC session over a config-server tunnel. It serves the
// local services and issues calls to the console side.
type Session struct {
	channel transport.PacketChannel
	manager *rpc.PeerRpcManager

	mu       sync.Mutex
	services []registeredService
	readErr  chan error
	done     chan struct{}

	closeOnce sync.Once
	cancel    context.CancelFunc
}

type registeredService struct {
	domain  string
	name    string
	service rpc.RpcService
}

// newSession starts the read loop that feeds packets into the RPC manager.
func newSession(ctx context.Context, channel transport.PacketChannel) (*Session, error) {
	if channel == nil {
		return nil, errors.New("webconsole session channel is nil")
	}
	if ctx == nil {
		return nil, errors.New("webconsole session context is nil")
	}
	manager, err := rpc.NewPeerRpcManager(&channelTransport{channel: channel})
	if err != nil {
		return nil, fmt.Errorf("create webconsole rpc manager: %w", err)
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	session := &Session{
		channel: channel,
		manager: manager,
		readErr: make(chan error, 1),
		done:    make(chan struct{}),
		cancel:  cancel,
	}
	go session.readLoop(sessionCtx)
	return session, nil
}

func (s *Session) readLoop(ctx context.Context) {
	defer close(s.done)
	for {
		packet, err := s.channel.Receive(ctx)
		if err != nil {
			s.finish(err)
			return
		}
		if packet.Header.PacketType != protocol.PacketTypeRPCRequest &&
			packet.Header.PacketType != protocol.PacketTypeRPCResponse {
			// Control packets (Noise handshake leftovers) carry no RPC body.
			continue
		}
		if err := s.manager.HandlePacket(ctx, packet); err != nil {
			s.finish(fmt.Errorf("handle webconsole rpc packet: %w", err))
			return
		}
	}
}

func (s *Session) finish(err error) {
	select {
	case s.readErr <- err:
	default:
	}
}

// Serve starts a session over an already-connected channel and registers the
// given services. It is the entry point for anything that plays the console
// side of the link (tests, tooling).
func Serve(ctx context.Context, channel transport.PacketChannel, services ...rpc.RpcService) (*Session, error) {
	session, err := newSession(ctx, channel)
	if err != nil {
		return nil, err
	}
	for _, service := range services {
		if err := session.Register(service); err != nil {
			_ = session.Close()
			return nil, err
		}
	}
	return session, nil
}

// Register installs one service on the console session. Services register in
// the empty domain, matching the reference registry.
func (s *Session) Register(service rpc.RpcService) error {
	if service == nil {
		return errors.New("webconsole service is nil")
	}
	if err := s.manager.Register(ConsoleDomain, service); err != nil {
		return err
	}
	s.mu.Lock()
	s.services = append(s.services, registeredService{domain: ConsoleDomain, name: service.ServiceName(), service: service})
	s.mu.Unlock()
	return nil
}

// Call invokes one console method and decodes the protobuf response.
func (s *Session) Call(ctx context.Context, serviceName string, method uint32, request, response proto.Message, timeout time.Duration) error {
	if ctx == nil {
		return errors.New("webconsole call context is nil")
	}
	if request == nil {
		return errors.New("webconsole call request is nil")
	}
	body, err := proto.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal %s request: %w", serviceName, err)
	}
	callCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	raw, err := s.manager.CallDescriptor(callCtx, ConsolePeerID, &rpc.RpcDescriptor{
		DomainName:  ConsoleDomain,
		ProtoName:   serviceName,
		ServiceName: serviceName,
		MethodIndex: method,
	}, body)
	if err != nil {
		return err
	}
	if response == nil || len(raw) == 0 {
		return nil
	}
	if err := proto.Unmarshal(raw, response); err != nil {
		return fmt.Errorf("decode %s response: %w", serviceName, err)
	}
	return nil
}

// Wait blocks until the session ends and reports why.
func (s *Session) Wait() error {
	select {
	case err := <-s.readErr:
		return err
	case <-s.done:
		select {
		case err := <-s.readErr:
			return err
		default:
			return nil
		}
	}
}

// Close stops the session and releases the tunnel.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.cancel()
		s.manager.Close()
		s.mu.Lock()
		for _, registered := range s.services {
			s.manager.Unregister(registered.domain, registered.name)
		}
		s.services = nil
		s.mu.Unlock()
	})
	if closer, ok := s.channel.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

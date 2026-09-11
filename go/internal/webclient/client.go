// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webclient

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

// ClientConfig configures a reconnecting configuration-server client.
type ClientConfig struct {
	Address             string
	MachineID           string
	MachineName         string
	Version             string
	HeartbeatInterval   time.Duration
	ReconnectMinBackoff time.Duration
	ReconnectMaxBackoff time.Duration
	MaxFrameSize        int
	NoiseUpgrader       NoiseUpgrader
	EnableNoise         bool
	RequireSecure       bool
	OnConfigUpdate      func(ConfigUpdate)
}

// Client maintains one machine's configuration-server session.
type Client struct {
	config ClientConfig

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
}

// NewClient validates and creates a configuration-server client.
func NewClient(config ClientConfig) (*Client, error) {
	if config.Address == "" {
		return nil, errors.New("webclient address is empty")
	}
	if config.MachineID == "" {
		return nil, errors.New("webclient machine ID is empty")
	}
	config = normalizeClientConfig(config)
	return &Client{config: config}, nil
}

// Run connects, registers, sends heartbeats, handles configuration updates,
// and reconnects with bounded exponential backoff until ctx is canceled.
func (c *Client) Run(ctx context.Context) error {
	if c == nil {
		return errors.New("webclient client is nil")
	}
	if ctx == nil {
		return errors.New("webclient client context is nil")
	}
	ctx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		cancel()
		return errors.New("webclient client is already running")
	}
	c.running, c.cancel = true, cancel
	c.mu.Unlock()
	defer func() {
		cancel()
		c.mu.Lock()
		c.running, c.cancel = false, nil
		c.mu.Unlock()
	}()

	backoff := c.config.ReconnectMinBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		channel, err := c.dialChannel(ctx)
		if err == nil {
			err = c.runConnection(ctx, channel)
			_ = closePacketChannel(channel)
		}
		if errors.Is(err, ErrNoiseUnsupported) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			backoff = c.config.ReconnectMinBackoff
		} else if waitContext(ctx, backoff) != nil {
			return nil
		} else {
			if backoff >= c.config.ReconnectMaxBackoff/2 {
				backoff = c.config.ReconnectMaxBackoff
			} else {
				backoff *= 2
			}
		}
	}
}

// Close stops Run and closes the active connection through its context.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

func (c *Client) dialChannel(ctx context.Context) (transport.PacketChannel, error) {
	endpoint, err := clientEndpoint(c.config.Address)
	if err != nil {
		return nil, err
	}
	if c.config.NoiseUpgrader != nil {
		// legacy NoiseUpgrader path now maps to web secure upgrade; keep compatibility for non-web tests
		// but web secure is handled via EnableNoise/RequireSecure.
	}
	address := endpoint.Address()
	if endpoint.Protocol == config.ProtocolWS || endpoint.Protocol == config.ProtocolWSS {
		address = endpoint.String()
	}
	channel, err := transport.DialPacketChannel(ctx, string(endpoint.Protocol), address, c.config.MaxFrameSize)
	if err != nil {
		return nil, err
	}
	if c.config.RequireSecure || c.config.EnableNoise {
		secureCh, err := UpgradeClientChannel(ctx, channel)
		if err != nil {
			_ = closePacketChannel(channel)
			if c.config.RequireSecure {
				return nil, fmt.Errorf("webclient %s Noise upgrade required: %w", endpoint.Protocol, err)
			}
			// downgrade: retry plain if optional and handshake failed
			plain, pErr := transport.DialPacketChannel(ctx, string(endpoint.Protocol), address, c.config.MaxFrameSize)
			if pErr != nil {
				return nil, pErr
			}
			return plain, nil
		}
		return secureCh, nil
	}
	if c.config.NoiseUpgrader != nil {
		return nil, fmt.Errorf("webclient %s Noise upgrade: %w", endpoint.Protocol, ErrNoiseUnsupported)
	}
	return channel, nil
}

func (c *Client) runConnection(ctx context.Context, channel transport.PacketChannel) error {
	if err := c.write(ctx, channel, NewRegistrationMessage(MachineRegistration{
		MachineID: c.config.MachineID,
		Name:      c.config.MachineName,
		Version:   c.config.Version,
	})); err != nil {
		return fmt.Errorf("send webclient registration: %w", err)
	}

	readResults := make(chan error, 1)
	go func() {
		for {
			message, err := readMessage(ctx, channel, c.config.MaxFrameSize)
			if err != nil {
				readResults <- err
				return
			}
			switch message.Type {
			case MessageTypeConfigUpdate:
				if c.config.OnConfigUpdate != nil {
					c.config.OnConfigUpdate(*message.ConfigUpdate)
				}
			default:
				readResults <- fmt.Errorf("unexpected webclient message type %q", message.Type)
				return
			}
		}
	}()

	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case err := <-readResults:
			return err
		case <-ticker.C:
			if err := c.write(ctx, channel, NewHeartbeatMessage(MachineHeartbeat{MachineID: c.config.MachineID})); err != nil {
				return fmt.Errorf("send webclient heartbeat: %w", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *Client) write(ctx context.Context, channel transport.PacketChannel, message Message) error {
	payload, err := MarshalMessage(message, c.config.MaxFrameSize)
	if err != nil {
		return err
	}
	return channel.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{PacketType: protocol.PacketTypeData},
		Payload: payload,
	})
}

func readMessage(ctx context.Context, channel transport.PacketChannel, maxFrameSize int) (Message, error) {
	packet, err := channel.Receive(ctx)
	if err != nil {
		return Message{}, err
	}
	maxFrameSize = normalizedMaxFrameSize(maxFrameSize)
	if len(packet.Payload) > maxFrameSize {
		return Message{}, fmt.Errorf("webclient message is %d bytes, maximum is %d", len(packet.Payload), maxFrameSize)
	}
	if packet.Header.PacketType != protocol.PacketTypeData {
		return Message{}, fmt.Errorf("unexpected webclient packet type %d", packet.Header.PacketType)
	}
	return UnmarshalMessage(packet.Payload)
}

func clientEndpoint(raw string) (config.Endpoint, error) {
	if raw == "" {
		return config.Endpoint{}, errors.New("webclient address is empty")
	}
	if len(raw) < 3 || !containsScheme(raw) {
		raw = "tcp://" + raw
	}
	endpoint, err := config.ParseEndpoint(raw)
	if err != nil {
		return config.Endpoint{}, fmt.Errorf("parse webclient address %q: %w", raw, err)
	}
	switch endpoint.Protocol {
	case config.ProtocolTCP, config.ProtocolUDP, config.ProtocolWS, config.ProtocolWSS:
		return endpoint, nil
	default:
		return config.Endpoint{}, fmt.Errorf("unsupported webclient transport %q", endpoint.Protocol)
	}
}

func containsScheme(address string) bool {
	for index := 0; index < len(address); index++ {
		if address[index] == ':' {
			return index+2 < len(address) && address[index+1:index+3] == "//"
		}
	}
	return false
}

func closePacketChannel(channel transport.PacketChannel) error {
	if closer, ok := channel.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func normalizeClientConfig(config ClientConfig) ClientConfig {
	if config.HeartbeatInterval <= 0 {
		config.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if config.ReconnectMinBackoff <= 0 {
		config.ReconnectMinBackoff = DefaultReconnectMinBackoff
	}
	if config.ReconnectMaxBackoff < config.ReconnectMinBackoff {
		config.ReconnectMaxBackoff = DefaultReconnectMaxBackoff
		if config.ReconnectMaxBackoff < config.ReconnectMinBackoff {
			config.ReconnectMaxBackoff = config.ReconnectMinBackoff
		}
	}
	config.MaxFrameSize = normalizedMaxFrameSize(config.MaxFrameSize)
	return config
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

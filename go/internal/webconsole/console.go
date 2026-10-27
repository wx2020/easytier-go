// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webconsole

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	commonpb "github.com/EasyTier/EasyTier/go/internal/proto/common"
	webpb "github.com/EasyTier/EasyTier/go/internal/proto/web"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"github.com/EasyTier/EasyTier/go/internal/webclient"
)

// Default timing used by the console client. They mirror the reference
// implementation: a 1s heartbeat, a 3s GetFeature probe, and a fixed 1s
// reconnect delay.
const (
	DefaultHeartbeatInterval = time.Second
	DefaultFeatureTimeout    = 10 * time.Second
	DefaultReconnectDelay    = time.Second
	DefaultReconnectMaxDelay = 30 * time.Second
	// sessionHealthyDuration is how long a session must live before its
	// reconnect delay is treated as a fresh start.
	sessionHealthyDuration = 30 * time.Second
	defaultMaxFrameSize    = 4 * 1024 * 1024
)

// Options configures a console client.
type Options struct {
	// ServerURL is the config-server URL, e.g. udp://host:22020/token.
	ServerURL string
	// MachineID identifies this machine; it is reported in every heartbeat.
	MachineID string
	// Hostname is reported in the heartbeat.
	Hostname string
	// Version is the EasyTier version string reported to the console.
	Version string
	// HeartbeatInterval defaults to DefaultHeartbeatInterval.
	HeartbeatInterval time.Duration
	// FeatureTimeout bounds the GetFeature probe; defaults to DefaultFeatureTimeout.
	FeatureTimeout time.Duration
	// ReconnectDelay is the base reconnect delay; defaults to
	// DefaultReconnectDelay.
	ReconnectDelay time.Duration
	// ReconnectMaxDelay caps the exponential reconnect backoff; defaults to
	// DefaultReconnectMaxDelay.
	ReconnectMaxDelay time.Duration
	// MaxFrameSize bounds one tunnel frame.
	MaxFrameSize int
	// RequireSecure refuses to talk to a console that does not offer the
	// Noise upgrade.
	RequireSecure bool
	// DisableNoise forces the legacy plaintext tunnel.
	DisableNoise bool
	// Backend serves the WebClientService/ConfigRpc methods the console calls.
	Backend Backend
	// DeviceOS is reported in the heartbeat; nil means "derive from runtime".
	DeviceOS *webpb.DeviceOsInfo
	// Logf receives human-readable progress lines; nil discards them.
	Logf func(format string, args ...any)
	// Dial overrides the tunnel dialer (tests).
	Dial func(ctx context.Context) (transport.PacketChannel, error)
	// Upgrade overrides the Noise upgrader (tests).
	Upgrade func(ctx context.Context, channel transport.PacketChannel) (transport.PacketChannel, error)
}

// Console maintains one machine's config-server session.
type Console struct {
	options Options
	server  *url.URL
	token   string

	logf func(string, ...any)
}

// NewConsole validates the options and creates the client. No connection is
// made until Run is called.
func NewConsole(options Options) (*Console, error) {
	if strings.TrimSpace(options.ServerURL) == "" {
		return nil, errors.New("webconsole server URL is empty")
	}
	if options.MachineID == "" {
		return nil, errors.New("webconsole machine ID is empty")
	}
	server, token, err := parseServerURL(options.ServerURL)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("webconsole server URL has an empty token")
	}
	options.ServerURL = server.String()
	if options.HeartbeatInterval <= 0 {
		options.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if options.FeatureTimeout <= 0 {
		options.FeatureTimeout = DefaultFeatureTimeout
	}
	if options.ReconnectDelay <= 0 {
		options.ReconnectDelay = DefaultReconnectDelay
	}
	if options.ReconnectMaxDelay < options.ReconnectDelay {
		options.ReconnectMaxDelay = DefaultReconnectMaxDelay
		if options.ReconnectMaxDelay < options.ReconnectDelay {
			options.ReconnectMaxDelay = options.ReconnectDelay
		}
	}
	if options.MaxFrameSize <= 0 {
		options.MaxFrameSize = defaultMaxFrameSize
	}
	if options.Logf == nil {
		options.Logf = func(string, ...any) {}
	}
	return &Console{options: options, server: server, token: token, logf: options.Logf}, nil
}

// Token returns the config-server token taken from the URL path.
func (c *Console) Token() string {
	if c == nil {
		return ""
	}
	return c.token
}

// Run keeps one console session alive until ctx is canceled. It dials, probes
// the console features, upgrades to a Noise tunnel when the console supports
// it, serves the local services, and heartbeats every heartbeat interval.
func (c *Console) Run(ctx context.Context) error {
	if c == nil {
		return errors.New("webconsole console is nil")
	}
	if ctx == nil {
		return errors.New("webconsole console context is nil")
	}
	backoff := &reconnectBackoff{base: c.options.ReconnectDelay, max: c.options.ReconnectMaxDelay}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		started := time.Now()
		err := c.runOnce(ctx)
		lived := time.Since(started)
		if err != nil && !errors.Is(err, context.Canceled) {
			c.logf("webconsole session ended: %v", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		// A session that stayed up long enough is treated as healthy, so the
		// next outage starts again from the short delay.
		if lived >= sessionHealthyDuration {
			backoff.reset()
		}
		delay := backoff.next()
		c.logf("webconsole reconnecting in %s", delay)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil
		}
	}
}

func (c *Console) runOnce(ctx context.Context) error {
	channel, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.options.ServerURL, err)
	}
	session, err := c.openSession(ctx, channel)
	if err != nil {
		return err
	}
	c.logf("webconsole tunnel up, probing console features")

	feature, featureErr := c.getFeature(ctx, session)
	if featureErr != nil {
		c.logf("webconsole GetFeature failed, using the plaintext tunnel: %v", featureErr)
	}
	supportEncryption := feature.GetSupportEncryption()
	c.logf("webconsole GetFeature: support_encryption=%v", supportEncryption)

	// The console only needs a second connection when the tunnel is upgraded;
	// reusing the probe session otherwise keeps one session per machine.
	if supportEncryption && !c.options.DisableNoise {
		_ = session.Close()
		c.logf("webconsole upgrading to the Noise tunnel")
		secureChannel, upgradeErr := c.upgradeToSecure(ctx)
		if upgradeErr != nil {
			if c.options.RequireSecure {
				return fmt.Errorf("webconsole noise upgrade required: %w", upgradeErr)
			}
			c.logf("webconsole noise upgrade failed, retrying plaintext: %v", upgradeErr)
			channel, err = c.dial(ctx)
			if err != nil {
				return fmt.Errorf("dial %s: %w", c.options.ServerURL, err)
			}
			session, err = c.openSession(ctx, channel)
			if err != nil {
				return err
			}
		} else {
			channel = secureChannel
			session, err = c.openSession(ctx, channel)
			if err != nil {
				return err
			}
			c.logf("webconsole secure tunnel established")
		}
	} else if c.options.RequireSecure {
		_ = session.Close()
		return errors.New("webconsole noise upgrade required but the console does not support encryption")
	}

	defer func() { _ = session.Close() }()
	c.logf("webconsole connected to %s", c.options.ServerURL)
	return c.serve(ctx, session)
}

// upgradeToSecure dials a fresh tunnel and upgrades it to the Noise session.
func (c *Console) upgradeToSecure(ctx context.Context) (transport.PacketChannel, error) {
	channel, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", c.options.ServerURL, err)
	}
	secureChannel, err := c.upgrade(ctx, channel)
	if err != nil {
		_ = closeChannel(channel)
		return nil, err
	}
	return secureChannel, nil
}

func (c *Console) dial(ctx context.Context) (transport.PacketChannel, error) {
	if c.options.Dial != nil {
		return c.options.Dial(ctx)
	}
	address := c.server.Host
	if scheme := c.server.Scheme; scheme == "ws" || scheme == "wss" {
		address = c.server.String()
	}
	return transport.DialPacketChannel(ctx, c.server.Scheme, address, c.options.MaxFrameSize)
}

func (c *Console) upgrade(ctx context.Context, channel transport.PacketChannel) (transport.PacketChannel, error) {
	if c.options.Upgrade != nil {
		return c.options.Upgrade(ctx, channel)
	}
	return webclient.UpgradeClientChannel(ctx, channel)
}

func (c *Console) openSession(ctx context.Context, channel transport.PacketChannel) (*Session, error) {
	session, err := newSession(ctx, channel)
	if err != nil {
		_ = closeChannel(channel)
		return nil, err
	}
	if c.options.Backend != nil {
		service := NewWebClientService(c.options.Backend, c.options.Logf)
		if err := session.Register(service); err != nil {
			_ = session.Close()
			return nil, err
		}
		if err := session.Register(NewConfigService(c.options.Backend, c.options.Logf)); err != nil {
			_ = session.Close()
			return nil, err
		}
	}
	return session, nil
}

// getFeature probes the console capabilities. Lossy links drop the first
// round trips often enough that a single attempt would push every session onto
// the plaintext tunnel, so it retries a few times before giving up.
func (c *Console) getFeature(ctx context.Context, session *Session) (*webpb.GetFeatureResponse, error) {
	const attempts = 3
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		response := &webpb.GetFeatureResponse{}
		err := session.Call(ctx, ServiceWebServer, MethodGetFeature, &webpb.GetFeatureRequest{}, response, c.options.FeatureTimeout)
		if err == nil {
			return response, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func (c *Console) serve(ctx context.Context, session *Session) error {
	servedCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	heartbeatErr := make(chan error, 1)
	go func() {
		heartbeatErr <- c.heartbeatLoop(servedCtx, session)
	}()

	sessionErr := make(chan error, 1)
	go func() { sessionErr <- session.Wait() }()

	select {
	case err := <-sessionErr:
		cancel()
		<-heartbeatErr
		if err == nil {
			return errors.New("webconsole session closed")
		}
		return err
	case err := <-heartbeatErr:
		cancel()
		return err
	case <-ctx.Done():
		return nil
	}
}

func (c *Console) heartbeatLoop(ctx context.Context, session *Session) error {
	instanceID := newUUIDString()
	var (
		mu       sync.Mutex
		failures int
		answered bool
		lastErr  error
	)
	send := func() {
		request := &webpb.HeartbeatRequest{
			InstId:                  uuidMessage(instanceID),
			UserToken:               c.token,
			EasytierVersion:         c.options.Version,
			ReportTime:              time.Now().Format(time.RFC3339),
			Hostname:                c.options.Hostname,
			MachineId:               uuidMessage(c.options.MachineID),
			DeviceOs:                c.deviceOS(),
			SupportConfigSource:     true,
			RunningNetworkInstances: c.runningInstanceIDs(),
		}
		response := &webpb.HeartbeatResponse{}
		callCtx, cancel := context.WithTimeout(ctx, c.heartbeatTimeout())
		err := session.Call(callCtx, ServiceWebServer, MethodHeartbeat, request, response, c.heartbeatTimeout())
		cancel()
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failures++
			lastErr = err
			return
		}
		failures = 0
		if !answered {
			answered = true
			c.logf("webconsole heartbeat accepted by the console")
		}
	}

	// Each heartbeat is sent on its own so one lost round trip never stalls the
	// loop; the console only needs some of them to arrive.
	ticker := time.NewTicker(c.options.HeartbeatInterval)
	defer ticker.Stop()
	send()
	for {
		select {
		case <-ticker.C:
			go send()
		case <-ctx.Done():
			return nil
		}
		mu.Lock()
		dead := failures >= 10
		err := lastErr
		mu.Unlock()
		if dead {
			return fmt.Errorf("webconsole heartbeat: %d consecutive failures: %w", 10, err)
		}
	}
}

// heartbeatTimeout bounds one heartbeat round trip.
func (c *Console) heartbeatTimeout() time.Duration {
	timeout := 5 * c.options.HeartbeatInterval
	if timeout < 20*time.Second {
		timeout = 20 * time.Second
	}
	return timeout
}

func (c *Console) runningInstanceIDs() []*commonpb.UUID {
	if c.options.Backend == nil {
		return nil
	}
	ids := c.options.Backend.InstanceIDs()
	out := make([]*commonpb.UUID, 0, len(ids))
	for _, id := range ids {
		out = append(out, uuidMessage(id))
	}
	return out
}

func (c *Console) deviceOS() *webpb.DeviceOsInfo {
	if c.options.DeviceOS != nil {
		return c.options.DeviceOS
	}
	return defaultDeviceOS()
}

// reconnectBackoff doubles the delay between failed sessions up to max and
// starts over once a session has been healthy.
type reconnectBackoff struct {
	base    time.Duration
	max     time.Duration
	current time.Duration
}

func (b *reconnectBackoff) next() time.Duration {
	if b.current == 0 {
		b.current = b.base
		return b.current
	}
	b.current *= 2
	if b.current > b.max {
		b.current = b.max
	}
	return b.current
}

func (b *reconnectBackoff) reset() { b.current = 0 }

// parseServerURL normalises the config-server URL and extracts the token. The
// token is the percent-decoded last path segment; the tunnel address drops the
// path for non-websocket schemes.
func parseServerURL(raw string) (*url.URL, string, error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.Contains(trimmed, "://") {
		trimmed = "udp://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, "", fmt.Errorf("parse webconsole server URL %q: %w", raw, err)
	}
	switch parsed.Scheme {
	case "udp", "tcp", "ws", "wss":
	default:
		return nil, "", fmt.Errorf("unsupported webconsole scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, "", fmt.Errorf("webconsole server URL %q has no host", raw)
	}
	token := ""
	// EscapedPath keeps %2F inside one segment; Path would split it.
	if segments := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/"); len(segments) > 0 {
		last := segments[len(segments)-1]
		if decoded, decodeErr := url.PathUnescape(last); decodeErr == nil {
			token = decoded
		} else {
			token = last
		}
	}
	if parsed.Scheme != "ws" && parsed.Scheme != "wss" {
		parsed.Path = ""
	}
	return parsed, token, nil
}

func newUUIDString() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

func closeChannel(channel transport.PacketChannel) error {
	if closer, ok := channel.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// rpcServiceNames documents the registry keys the console uses; it keeps the
// strings referenced from one place for tests.
var rpcServiceNames = []string{ServiceWebServer, ServiceWebClient, ServiceConfigRPC}

var _ rpc.RpcService = (*WebClientService)(nil)

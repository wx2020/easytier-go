// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package gui implements the Go-based GUI backend that replaces the embedded
// Rust core for GUI-01 and the platform integrations for GUI-02.
//
// It wires together the platform adapters (go/platform) for service/elevation,
// tray/autostart, logging, events, and config-source, exposing a Tauri-like
// command surface (RunNetworkInstance, CollectNetworkInfo, etc.) that the
// frontend can drive via RPC or local instance manager.
package gui

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/logging"
	"github.com/EasyTier/EasyTier/go/platform"
)

// ConfigSource re-exports platform source constants for GUI consumers.
type ConfigSource = platform.ConfigSource

const (
	ConfigSourceUser    = platform.ConfigSourceUser
	ConfigSourceWebhook = platform.ConfigSourceWebhook
	ConfigSourceLegacy  = platform.ConfigSourceLegacy
)

// NetworkConfig is a minimal representation used by the GUI backend.
// The real implementation delegates to proto.NetworkConfig; this stub keeps
// the package self-contained for tests and packaging validation.
type NetworkConfig struct {
	InstanceID string `json:"instance_id"`
	RawTOML    string `json:"raw_toml,omitempty"`
	NoTun      bool   `json:"no_tun,omitempty"`
	DHCP       bool   `json:"dhcp,omitempty"`
}

// StoredGuiConfig mirrors the persisted shape {config, source}.
type StoredGuiConfig struct {
	Config NetworkConfig `json:"config"`
	Source ConfigSource  `json:"source"`
}

// ServiceOptions is the GUI service install payload (mode.ts ServiceMode).
type ServiceOptions struct {
	ConfigDir    string  `json:"config_dir"`
	RPCPortal    string  `json:"rpc_portal"`
	FileLogLevel string  `json:"file_log_level"`
	FileLogDir   string  `json:"file_log_dir"`
	ConfigServer *string `json:"config_server,omitempty"`
}

// ServiceStatus enumerates install states.
type ServiceStatus = platform.ServiceStatus

const (
	ServiceRunning      = platform.ServiceStatusRunning
	ServiceStopped      = platform.ServiceStatusStopped
	ServiceNotInstalled = platform.ServiceStatusNotInstalled
)

// Backend is the Go GUI backend. It holds in-memory instance state, an
// event bus, logger, and service/autostart/tray models.
type Backend struct {
	mu sync.RWMutex

	// instance store mirrors Rust's GUIStorage (DashMap + enabled set)
	configs map[string]StoredGuiConfig
	enabled map[string]bool

	// event bus for frontend listeners
	bus *platform.EventBus

	// logger for GUI operations
	logger *logging.Logger

	// service state (mocked for dry-run; real impl queries OS)
	serviceStatus ServiceStatus

	// tray config
	tray platform.TrayConfig

	// autostart config
	autostart map[string]platform.AutostartConfig

	// log options
	logOpts platform.GUILogOptions
}

// New creates a Backend with sane defaults.
func New(logger *logging.Logger, version string) *Backend {
	if logger == nil {
		logger = logging.New(nil, logging.LevelInfo)
	}
	if version == "" {
		version = "2.6.4"
	}
	bus := platform.NewEventBus()
	return &Backend{
		configs:       make(map[string]StoredGuiConfig),
		enabled:       make(map[string]bool),
		bus:           bus,
		logger:        logger,
		serviceStatus: ServiceNotInstalled,
		tray:          platform.DefaultTrayConfig(version),
		autostart:     make(map[string]platform.AutostartConfig),
		logOpts: platform.GUILogOptions{
			Dir:   platform.ResolveGUILogDir("linux", "", ""),
			Level: platform.GUILogOff,
			File:  "easytier.log",
		},
	}
}

// EventBus returns the underlying event bus.
func (b *Backend) EventBus() *platform.EventBus { return b.bus }

// Logger returns the backend logger.
func (b *Backend) Logger() *logging.Logger { return b.logger }

// TrayConfig returns current tray config.
func (b *Backend) TrayConfig() platform.TrayConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.tray
}

// SetTrayRunState updates tray icon based on running state, matching TS.
func (b *Backend) SetTrayRunState(isRunning bool) {
	b.mu.Lock()
	b.tray = b.tray.ApplyTrayRunStateMapping(isRunning)
	b.mu.Unlock()
}

// SetTrayTooltip appends extra tooltip line.
func (b *Backend) SetTrayTooltip(extra string) {
	b.mu.Lock()
	b.tray = b.tray.WithExtraTooltip(extra)
	b.mu.Unlock()
}

// TrayAction returns plan for current OS; dry-run only.
func (b *Backend) PlanTray(osName string) (platform.Plan, error) {
	b.mu.RLock()
	cfg := b.tray
	b.mu.RUnlock()
	return platform.PlanTray(osName, cfg)
}

// ToggleVisibility models the toggle logic.
func (b *Backend) ToggleVisibility(state platform.TrayState) platform.TrayAction {
	return state.NextToggleTarget()
}

// Autostart handling

// SetAutostart configures autostart for an entry.
func (b *Backend) SetAutostart(cfg platform.AutostartConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	b.mu.Lock()
	b.autostart[cfg.Name] = cfg
	b.mu.Unlock()
	return nil
}

// GetAutostart returns autostart config if present.
func (b *Backend) GetAutostart(name string) (platform.AutostartConfig, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	c, ok := b.autostart[name]
	return c, ok
}

// PlanAutostart returns dry-run plan for autostart.
func (b *Backend) PlanAutostart(osName, name string) (platform.Plan, error) {
	b.mu.RLock()
	cfg, ok := b.autostart[name]
	b.mu.RUnlock()
	if !ok {
		return platform.Plan{}, fmt.Errorf("autostart %q not found", name)
	}
	return platform.PlanAutostart(osName, cfg)
}

// Log handling

// SetLoggingLevel updates the backend logger level and log options.
func (b *Backend) SetLoggingLevel(level string) error {
	lvl, err := platform.ParseGUILogLevel(level)
	if err != nil {
		// Try internal/logging parsing (trace/debug/info/warn/error) without off
		switch strings.ToLower(level) {
		case "trace", "debug", "info", "warn", "error":
			lvl = platform.GUILogLevel(strings.ToLower(level))
		default:
			return err
		}
	}
	// Map to internal logging level
	var internalLevel logging.Level
	switch strings.ToLower(string(lvl)) {
	case "trace":
		internalLevel = logging.LevelTrace
	case "debug":
		internalLevel = logging.LevelDebug
	case "info":
		internalLevel = logging.LevelInfo
	case "warn":
		internalLevel = logging.LevelWarn
	case "error":
		internalLevel = logging.LevelError
	default:
		// off -> do not change logger level but record
		b.mu.Lock()
		b.logOpts.Level = lvl
		b.mu.Unlock()
		return nil
	}
	if err := b.logger.SetLevel(internalLevel); err != nil {
		return err
	}
	b.mu.Lock()
	b.logOpts.Level = lvl
	b.mu.Unlock()
	return nil
}

// SetLogDir sets the log directory (validated).
func (b *Backend) SetLogDir(dir string) error {
	if strings.Contains(dir, "\x00") {
		return fmt.Errorf("log dir contains NUL")
	}
	b.mu.Lock()
	b.logOpts.Dir = dir
	b.mu.Unlock()
	return nil
}

// ResolveLogDir returns the OS-specific log directory.
func (b *Backend) ResolveLogDir(osName, appLogDir, cacheDir string) string {
	return platform.ResolveGUILogDir(osName, appLogDir, cacheDir)
}

// PlanLog returns dry-run plan for current log options.
func (b *Backend) PlanLog(osName string) (platform.Plan, error) {
	b.mu.RLock()
	opts := b.logOpts
	b.mu.RUnlock()
	return platform.PlanGUILog(osName, opts)
}

// GetLogDirPath mimics get_log_dir_path: ensures directory exists logically
// and returns it. For dry-run we just return resolved path.
func (b *Backend) GetLogDirPath(osName, appLogDir, cacheDir string) (string, error) {
	dir := platform.ResolveGUILogDir(osName, appLogDir, cacheDir)
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("log dir empty")
	}
	// In real backend we would mkdir -p; here we just return.
	clean := filepath.Clean(dir)
	return clean, nil
}

// Elevation

// IsElevated reports privilege.
func (b *Backend) IsElevated() bool { return platform.IsElevated() }

// PlanElevated returns dry-run elevation plan.
func (b *Backend) PlanElevated(osName string, cmd platform.ElevatedCommand) (platform.Plan, error) {
	return cmd.Plan(osName)
}

// Service handling

// InitService installs or uninstalls the GUI service.
// If opts is nil, it uninstalls.
func (b *Backend) InitService(osName string, opts *ServiceOptions, execPath string) error {
	plan, err := b.PlanService(osName, opts, execPath)
	if err != nil {
		return err
	}
	// Dry-run: just record status transition
	b.mu.Lock()
	defer b.mu.Unlock()
	if opts == nil {
		b.serviceStatus = ServiceNotInstalled
		_ = plan
		return nil
	}
	// emulate install -> stopped state (needs start)
	b.serviceStatus = ServiceStopped
	_ = plan
	return nil
}

// PlanService returns dry-run service plan.
func (b *Backend) PlanService(osName string, opts *ServiceOptions, execPath string) (platform.Plan, error) {
	if opts == nil {
		return platform.PlanGUIService(osName, nil, execPath)
	}
	// Validate and convert
	guiOpts := platform.GUIServiceOptions{
		ConfigDir:    opts.ConfigDir,
		RPCPortal:    opts.RPCPortal,
		FileLogLevel: opts.FileLogLevel,
		FileLogDir:   opts.FileLogDir,
		ConfigServer: opts.ConfigServer,
	}
	return platform.PlanGUIService(osName, &guiOpts, execPath)
}

// SetServiceStatus starts or stops the service (mock).
func (b *Backend) SetServiceStatus(enable bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.serviceStatus {
	case ServiceNotInstalled:
		return fmt.Errorf("service not installed")
	case ServiceRunning:
		if enable {
			return fmt.Errorf("service already running")
		}
		b.serviceStatus = ServiceStopped
		_ = b.bus.Emit(platform.EventVPNServiceStop, "")
	case ServiceStopped:
		if !enable {
			return fmt.Errorf("service already stopped")
		}
		b.serviceStatus = ServiceRunning
	default:
		return fmt.Errorf("unknown service status")
	}
	return nil
}

// GetServiceStatus returns current mocked status.
func (b *Backend) GetServiceStatus() ServiceStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.serviceStatus
}

// PlanServiceStatus returns plan for status query/toggle.
func (b *Backend) PlanServiceStatus(osName, action string) (platform.Plan, error) {
	b.mu.RLock()
	cur := b.serviceStatus
	b.mu.RUnlock()
	return platform.PlanServiceStatus(osName, action, cur)
}

// Config source & storage

// SaveNetworkConfig persists a config with source.
func (b *Backend) SaveNetworkConfig(cfg NetworkConfig, source ConfigSource) error {
	if strings.TrimSpace(cfg.InstanceID) == "" {
		return fmt.Errorf("instance_id required")
	}
	src := source
	if src == "" {
		src = ConfigSourceLegacy
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	existing, ok := b.configs[cfg.InstanceID]
	if ok {
		src = existing.Source.MergePersisted(src)
	}
	b.configs[cfg.InstanceID] = StoredGuiConfig{Config: cfg, Source: src}
	// emit save_configs
	payload := make([]StoredGuiConfig, 0, len(b.configs))
	for _, v := range b.configs {
		payload = append(payload, v)
	}
	_ = b.bus.Emit(platform.EventSaveConfigs, payload)
	return nil
}

// LoadConfigs replaces storage with provided configs and enabled list.
func (b *Backend) LoadConfigs(configs []StoredGuiConfig, enabledNetworks []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.configs = make(map[string]StoredGuiConfig)
	b.enabled = make(map[string]bool)
	for _, sc := range configs {
		if strings.TrimSpace(sc.Config.InstanceID) == "" {
			continue
		}
		b.configs[sc.Config.InstanceID] = sc
	}
	for _, id := range enabledNetworks {
		if _, ok := b.configs[id]; ok {
			b.enabled[id] = true
		}
	}
	_ = b.bus.Emit(platform.EventSaveEnabledNetworks, enabledNetworks)
	_ = b.bus.Emit(platform.EventSaveConfigs, configs)
	return nil
}

// ListNetworkInstanceIds returns instance ids grouped.
func (b *Backend) ListNetworkInstanceIds() (running []string, all []string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for id := range b.configs {
		all = append(all, id)
		if b.enabled[id] {
			running = append(running, id)
		}
	}
	return running, all
}

// GetConfig returns config by id.
func (b *Backend) GetConfig(instanceID string) (NetworkConfig, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	sc, ok := b.configs[instanceID]
	if !ok {
		return NetworkConfig{}, false
	}
	return sc.Config, true
}

// UpdateNetworkConfigState enables/disables a network.
func (b *Backend) UpdateNetworkConfigState(instanceID string, disabled bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.configs[instanceID]; !ok {
		return fmt.Errorf("instance %q not found", instanceID)
	}
	if disabled {
		delete(b.enabled, instanceID)
	} else {
		b.enabled[instanceID] = true
		_ = b.bus.Emit(platform.EventPostRunNetworkInstance, instanceID)
		return nil
	}
	// Notify vpn_service_stop if no tun networks remain (simplified)
	hasTun := false
	for id, enabled := range b.enabled {
		if enabled {
			if cfg, ok := b.configs[id]; ok && !cfg.Config.NoTun {
				hasTun = true
				break
			}
		}
	}
	if !hasTun {
		_ = b.bus.Emit(platform.EventVPNServiceStop, "")
	}
	return nil
}

// RemoveNetworkInstance deletes instances.
func (b *Backend) RemoveNetworkInstance(ids []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range ids {
		delete(b.configs, id)
		delete(b.enabled, id)
	}
	_ = b.bus.Emit(platform.EventSaveConfigs, b.configs)
	// vpn stop check
	hasTun := false
	for id, enabled := range b.enabled {
		if enabled {
			if cfg, ok := b.configs[id]; ok && !cfg.Config.NoTun {
				hasTun = true
				break
			}
		}
	}
	if !hasTun {
		_ = b.bus.Emit(platform.EventVPNServiceStop, "")
	}
	return nil
}

// PreRunHook emits pre_run and handles Android single-TUN policy (dry-run).
func (b *Backend) PreRunHook(instanceID string, source ConfigSource, osName string) error {
	if err := b.bus.Emit(platform.EventPreRunNetworkInstance, instanceID); err != nil {
		return err
	}
	// Android one-active-TUN check (simplified)
	if osName == "android" {
		b.mu.RLock()
		for id, enabled := range b.enabled {
			if enabled {
				if cfg, ok := b.configs[id]; ok && !cfg.Config.NoTun {
					// webhook vs user logic
					if source == ConfigSourceWebhook {
						// webhook can only run if no tun active
						b.mu.RUnlock()
						return fmt.Errorf("Android only supports one active TUN network; user-managed VPN remains active")
					}
				}
				_ = id
			}
		}
		b.mu.RUnlock()
	}
	return nil
}

// PostRunHook records enabled and emits post_run plus dhcp/proxy subscriptions.
func (b *Backend) PostRunHook(instanceID string) error {
	b.mu.Lock()
	b.enabled[instanceID] = true
	b.mu.Unlock()
	return b.bus.Emit(platform.EventPostRunNetworkInstance, instanceID)
}

// ValidateConfig is a stub that checks instance id.
func (b *Backend) ValidateConfig(cfg NetworkConfig) error {
	if strings.TrimSpace(cfg.InstanceID) == "" {
		return fmt.Errorf("instance_id required")
	}
	return nil
}

// CollectNetworkInfo stub.
func (b *Backend) CollectNetworkInfo(instanceID string) (map[string]any, error) {
	b.mu.RLock()
	_, ok := b.configs[instanceID]
	b.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("instance %q not found", instanceID)
	}
	return map[string]any{"instance_id": instanceID, "status": "running"}, nil
}

// Export helpers for serialization

// ExportConfigs returns JSON for persistence tests.
func (b *Backend) ExportConfigs() ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	list := make([]StoredGuiConfig, 0, len(b.configs))
	for _, v := range b.configs {
		list = append(list, v)
	}
	return json.Marshal(list)
}

// NormalizeStoredConfigs exposes platform helper.
func NormalizeStoredConfigs(raw string) ([]StoredGuiConfig, error) {
	rawPlatform, err := platform.NormalizeStoredConfigs(raw)
	if err != nil {
		return nil, err
	}
	out := make([]StoredGuiConfig, 0, len(rawPlatform))
	for _, p := range rawPlatform {
		var cfg NetworkConfig
		if err := json.Unmarshal(p.Config, &cfg); err != nil {
			// Keep raw but instance_id may be empty; still preserve
			cfg = NetworkConfig{InstanceID: "", RawTOML: string(p.Config)}
		}
		out = append(out, StoredGuiConfig{Config: cfg, Source: p.Source})
	}
	return out, nil
}

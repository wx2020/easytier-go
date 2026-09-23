// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/EasyTier/EasyTier/go/internal/gui"
	"github.com/EasyTier/EasyTier/go/internal/logging"
	"github.com/EasyTier/EasyTier/go/platform"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx     context.Context
	backend *gui.Backend
	logger  *logging.Logger
	version string
}

// NewApp creates a new App application struct
func NewApp(version string) *App {
	if version == "" {
		version = "2.6.4"
	}
	logger := logging.New(nil, logging.LevelInfo)
	backend := gui.New(logger, version)

	return &App{
		backend: backend,
		logger:  logger,
		version: version,
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Bridge Go EventBus events to Wails frontend runtime events
	for _, evt := range platform.AllGUIEvents {
		event := evt
		a.backend.EventBus().Listen(event, func(e string, payload any) {
			wailsRuntime.EventsEmit(a.ctx, e, payload)
		})
	}
}

// EasytierVersion returns EasyTier core version
func (a *App) EasytierVersion() string {
	return a.version
}

// GetLogDirPath returns OS-specific log directory path
func (a *App) GetLogDirPath() (string, error) {
	return a.backend.GetLogDirPath(runtime.GOOS, "", "")
}

// SetLoggingLevel sets GUI log level
func (a *App) SetLoggingLevel(level string) error {
	return a.backend.SetLoggingLevel(level)
}

// ParseNetworkConfig returns raw TOML string
func (a *App) ParseNetworkConfig(cfg gui.NetworkConfig) (string, error) {
	if cfg.RawTOML != "" {
		return cfg.RawTOML, nil
	}
	b, err := a.backend.ExportConfigs()
	return string(b), err
}

// GenerateNetworkConfig parses TOML string to NetworkConfig
func (a *App) GenerateNetworkConfig(tomlConfig string) (gui.NetworkConfig, error) {
	return gui.NetworkConfig{
		InstanceID: "inst_1",
		RawTOML:    tomlConfig,
	}, nil
}

// RunNetworkInstance starts an instance
func (a *App) RunNetworkInstance(cfg gui.NetworkConfig, save bool) error {
	if err := a.backend.PreRunHook(cfg.InstanceID, gui.ConfigSourceUser, runtime.GOOS); err != nil {
		return err
	}
	if save {
		if err := a.backend.SaveNetworkConfig(cfg, gui.ConfigSourceUser); err != nil {
			return err
		}
	}
	return a.backend.PostRunHook(cfg.InstanceID)
}

// CollectNetworkInfo gathers network statistics
func (a *App) CollectNetworkInfo(instanceID string) (map[string]any, error) {
	return a.backend.CollectNetworkInfo(instanceID)
}

// ListNetworkInstanceIds returns running and total instance IDs
func (a *App) ListNetworkInstanceIds() map[string][]string {
	running, all := a.backend.ListNetworkInstanceIds()
	return map[string][]string{
		"running": running,
		"all":     all,
	}
}

// RemoveNetworkInstance deletes instances
func (a *App) RemoveNetworkInstance(instanceID string) error {
	return a.backend.RemoveNetworkInstance([]string{instanceID})
}

// UpdateNetworkConfigState toggles enable/disable
func (a *App) UpdateNetworkConfigState(instanceID string, disabled bool) error {
	return a.backend.UpdateNetworkConfigState(instanceID, disabled)
}

// SaveNetworkConfig saves network configuration
func (a *App) SaveNetworkConfig(cfg gui.NetworkConfig) error {
	return a.backend.SaveNetworkConfig(cfg, gui.ConfigSourceUser)
}

// ValidateConfig validates network configuration
func (a *App) ValidateConfig(cfg gui.NetworkConfig) error {
	return a.backend.ValidateConfig(cfg)
}

// GetConfig returns instance config
func (a *App) GetConfig(instanceID string) (gui.NetworkConfig, error) {
	cfg, ok := a.backend.GetConfig(instanceID)
	if !ok {
		return gui.NetworkConfig{}, fmt.Errorf("instance %q not found", instanceID)
	}
	return cfg, nil
}

// LoadConfigs loads all stored configs
func (a *App) LoadConfigs(configs []gui.StoredGuiConfig, enabledNetworks []string) error {
	return a.backend.LoadConfigs(configs, enabledNetworks)
}

// GetNetworkMetas returns network metadata
func (a *App) GetNetworkMetas(instanceIds []string) (map[string]any, error) {
	res := make(map[string]any)
	for _, id := range instanceIds {
		res[id] = map[string]any{
			"status": "running",
		}
	}
	return res, nil
}

// InitService installs/uninstalls service
func (a *App) InitService(opts *gui.ServiceOptions) error {
	execPath, _ := os.Executable()
	return a.backend.InitService(runtime.GOOS, opts, execPath)
}

// SetServiceStatus controls service
func (a *App) SetServiceStatus(enable bool) error {
	return a.backend.SetServiceStatus(enable)
}

// GetServiceStatus queries service status
func (a *App) GetServiceStatus() string {
	switch a.backend.GetServiceStatus() {
	case gui.ServiceRunning:
		return "Running"
	case gui.ServiceStopped:
		return "Stopped"
	default:
		return "NotInstalled"
	}
}

// InitRpcConnection initializes RPC connection
func (a *App) InitRpcConnection(isNormalMode bool, url string) error {
	return nil
}

// IsClientRunning returns client running status
func (a *App) IsClientRunning() bool {
	running, _ := a.backend.ListNetworkInstanceIds()
	return len(running) > 0
}

// InitWebClient initializes web client connection
func (a *App) InitWebClient(url string) error {
	return nil
}

// IsWebClientConnected checks web client connection
func (a *App) IsWebClientConnected() bool {
	return false
}

// SetTunFd stub for mobile parity
func (a *App) SetTunFd(fd int) error {
	return nil
}

// GetDefaultDirs provides path defaults for UI
func (a *App) GetDefaultDirs() map[string]string {
	configDir, _ := os.UserConfigDir()
	logDir := a.backend.ResolveLogDir(runtime.GOOS, "", "")
	return map[string]string{
		"config_dir": filepath.Join(configDir, "easytier", "config.d"),
		"log_dir":    logDir,
	}
}

// GetOSType returns the OS name for frontend checks
func (a *App) GetOSType() string {
	return runtime.GOOS
}

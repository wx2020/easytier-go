// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// OHOSAdapter implements OpenHarmony N-API/HAR adapter (NTV-05).
// Mirrors easytier-contrib/easytier-ohrs: napi-ohos, config store, socket bridge, runtime snapshots.
type OHOSAdapter struct {
	BaseAdapter
	mu            sync.Mutex
	configStore   map[string]string // configId -> json
	tunAttached   bool
	tunFD         int
	activeConfigs map[string]bool
	socketServer  bool
}

func NewOHOSAdapter() *OHOSAdapter {
	return &OHOSAdapter{
		BaseAdapter:   BaseAdapter{os: "ohos"},
		configStore:   make(map[string]string),
		activeConfigs: make(map[string]bool),
		tunFD:         -1,
	}
}

func (a *OHOSAdapter) Supported() bool { return true }

// TunConfigOHOS extends TunConfig with OHOS socket bridge.
type TunConfigOHOS struct {
	TunConfig
	ConfigID string
}

// PlanTun handles OHOS TUN FD injection (similar to Android but via socket bridge).
func (a *OHOSAdapter) PlanTun(cfg TunConfig) (Plan, error) {
	if err := validateTunConfig(cfg, false); err != nil {
		return Plan{}, err
	}
	plan := newPlan("ohos")
	if cfg.FD >= 0 {
		plan.Add("validate OHOS TUN FD via socket bridge", []string{"ohos-socket-bridge", "validate", fmt.Sprintf("%d", cfg.FD)}, false, nil)
		plan.Add("attach TUN FD", []string{"ohos-attach-tun", fmt.Sprintf("%d", cfg.FD)}, false, []string{"ohos-detach-tun"})
	} else {
		name := cfg.Name
		if name == "" {
			name = "et_ohos"
		}
		mtu := cfg.MTU
		if mtu == 0 {
			mtu = 1380
		}
		plan.Add("create OHOS TUN via socket bridge", []string{"ohos-create-tun", name, fmt.Sprintf("mtu=%d", mtu)}, true, []string{"ohos-delete-tun", name})
	}
	plan.Add("ensure local socket server", []string{"ohos-local-socket", "ensure"}, false, nil)
	plan.Warnings = append(plan.Warnings, "OHOS TUN is bridged via NAPI local socket server; requires ohos.permission.USE_VPN")
	return plan, nil
}

func (a *OHOSAdapter) PlanRoutes(cfg RouteConfig) (Plan, error) {
	plan := newPlan("ohos")
	if len(cfg.Routes) == 0 {
		plan.Warnings = append(plan.Warnings, "no routes; OHOS route sync via NAPI will be no-op")
		return plan, nil
	}
	for _, r := range cfg.Routes {
		plan.Add(fmt.Sprintf("ohos route %s", r), []string{"ohos-route-add", r, cfg.IfName}, false, []string{"ohos-route-del", r})
	}
	return plan, nil
}

func (a *OHOSAdapter) PlanDNS(cfg DNSConfig) (Plan, error) {
	plan := newPlan("ohos")
	if len(cfg.Servers) == 0 {
		plan.Warnings = append(plan.Warnings, "no DNS servers")
		return plan, nil
	}
	for _, s := range cfg.Servers {
		plan.Add("ohos add DNS", []string{"ohos-dns-add", s}, false, nil)
	}
	return plan, nil
}

func (a *OHOSAdapter) PlanService(cfg ServiceConfig) (Plan, error) {
	if err := ValidateService(cfg); err != nil {
		return Plan{}, err
	}
	plan := newPlan("ohos")
	plan.Add("OHOS ability lifecycle: start", []string{"ohos-ability", "start", cfg.Name}, false, nil)
	plan.Add("OHOS socket bridge lifecycle", []string{"ohos-socket-bridge", "start"}, false, []string{"ohos-socket-bridge", "stop"})
	plan.Warnings = append(plan.Warnings, "OHOS service is managed by Ability, not systemd; HAR nativeComponents: libeasytier_ohrs.so")
	return plan, nil
}

func (a *OHOSAdapter) ApplyTun(cfg TunConfig) error {
	if _, err := a.PlanTun(cfg); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if cfg.FD >= 0 {
		a.tunFD = cfg.FD
		a.tunAttached = true
	} else {
		a.tunAttached = true
		a.tunFD = 300
	}
	a.socketServer = true
	return nil
}

func (a *OHOSAdapter) ApplyRoutes(cfg RouteConfig) error {
	_, err := a.PlanRoutes(cfg)
	return err
}
func (a *OHOSAdapter) ApplyDNS(cfg DNSConfig) error {
	_, err := a.PlanDNS(cfg)
	return err
}
func (a *OHOSAdapter) ApplyService(cfg ServiceConfig) error {
	_, err := a.PlanService(cfg)
	return err
}

// OHOS Config Store (mirrors ohrs config/storage)

func (a *OHOSAdapter) InitConfigStore(rootDir string) bool {
	if strings.TrimSpace(rootDir) == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// simulated success
	return true
}

func (a *OHOSAdapter) SaveConfig(configID, displayName, configJSON string) bool {
	if configID == "" || configJSON == "" {
		return false
	}
	if !json.Valid([]byte(configJSON)) {
		return false
	}
	a.mu.Lock()
	a.configStore[configID] = configJSON
	a.mu.Unlock()
	return true
}

func (a *OHOSAdapter) GetConfig(configID string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.configStore[configID]
	return v, ok
}

func (a *OHOSAdapter) DeleteConfig(configID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.configStore[configID]; !ok {
		return false
	}
	delete(a.configStore, configID)
	delete(a.activeConfigs, configID)
	return true
}

func (a *OHOSAdapter) ListConfigs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.configStore))
	for k := range a.configStore {
		out = append(out, k)
	}
	return out
}

// StartKernel / StopKernel mirrors ohrs runtime_api
func (a *OHOSAdapter) StartKernel(configID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.configStore[configID]; !ok {
		return false
	}
	if a.activeConfigs[configID] {
		return false // already running
	}
	// Enforce one-active like Magisk/VpnService: OHOS also single instance
	if len(a.activeConfigs) > 0 {
		return false
	}
	a.activeConfigs[configID] = true
	a.socketServer = true
	return true
}

func (a *OHOSAdapter) StopKernel(configID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.activeConfigs[configID] {
		return false
	}
	delete(a.activeConfigs, configID)
	if len(a.activeConfigs) == 0 {
		a.socketServer = false
	}
	return true
}

func (a *OHOSAdapter) IsSocketServerRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.socketServer
}

func (a *OHOSAdapter) SetTunFD(configID string, fd int) bool {
	if fd < 0 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.configStore[configID]; !ok {
		return false
	}
	a.tunFD = fd
	a.tunAttached = true
	return true
}

func (a *OHOSAdapter) IsTunAttached() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tunAttached
}

func (a *OHOSAdapter) ClearTunAttached() {
	a.mu.Lock()
	a.tunAttached = false
	a.tunFD = -1
	a.mu.Unlock()
}

// RuntimeSnapshot mirrors ohrs RuntimeAggregateState
type OHOSRuntimeSnapshot struct {
	Configs      int  `json:"configs"`
	ActiveKernels int `json:"active_kernels"`
	TunAttached  bool `json:"tun_attached"`
	TunFD        int  `json:"tun_fd"`
	SocketServer bool `json:"socket_server"`
}

func (a *OHOSAdapter) GetRuntimeSnapshot() OHOSRuntimeSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return OHOSRuntimeSnapshot{
		Configs:       len(a.configStore),
		ActiveKernels: len(a.activeConfigs),
		TunAttached:   a.tunAttached,
		TunFD:         a.tunFD,
		SocketServer:  a.socketServer,
	}
}

// HAR manifest for oh-package.json5
func (a *OHOSAdapter) HARManifest() string {
	return `{
  "name": "easytier-ohrs",
  "version": "0.0.1",
  "compatibleSdkVersion": "17",
  "compatibleSdkType": "OpenHarmony",
  "nativeComponents": [
    {
      "name": "libeasytier_ohrs.so",
      "compatibleSdkVersion": "17",
      "compatibleSdkType": "OpenHarmony"
    }
  ]
}`
}

// NAPIExports lists the napi-ohos exported functions (for validation).
func (a *OHOSAdapter) NAPIExports() []string {
	return []string{
		"init_config_store",
		"list_configs",
		"get_config_display_name_by_id",
		"save_config",
		"create_config",
		"delete_stored_config_meta",
		"get_config",
		"get_default_config",
		"get_config_field",
		"set_config_field",
		"import_toml",
		"export_toml",
		"start_kernel",
		"stop_kernel",
		"stop_network_instance",
		"easytier_version",
		"default_network_config",
		"convert_toml_to_network_config",
		"parse_network_config",
		"run_network_instance",
		"collect_network_infos",
		"set_tun_fd",
		"get_network_config_schema",
		"get_network_config_field_mappings",
		"get_runtime_snapshot",
		"build_config_share_link",
		"parse_config_share_link",
		"import_config_share_link",
	}
}

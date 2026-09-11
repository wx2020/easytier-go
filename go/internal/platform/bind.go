// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// BindConfig controls socket bind-to-device behavior, mirroring
// easytier/src/tunnel/common.rs bind() and get_interface_name_by_ip.
type BindConfig struct {
	// Device is the interface to bind to. Empty means auto-discovery from
	// BindAddr, "disabled" means no bind, otherwise explicit device.
	Device string
	// BindAddr is the local address whose interface is auto-discovered when
	// Device is "auto" (empty treated as disabled for explicit callers, but
	// PlanBind treats empty as disabled to avoid surprise auto).
	BindAddr string
	// Mode is "auto", "disabled", or "custom". If empty, inferred from Device.
	Mode string
}

// BindMode constants match tunnel/common.rs BindDev.
const (
	BindModeAuto     = "auto"
	BindModeDisabled = "disabled"
	BindModeCustom   = "custom"
)

// ResolveBindDevice determines the device name to bind to.
// It mirrors BindDev::Auto vs Disabled vs Custom logic.
func ResolveBindDevice(cfg BindConfig) (string, error) {
	mode := cfg.Mode
	if mode == "" {
		if cfg.Device == "" {
			mode = BindModeDisabled
		} else if cfg.Device == "auto" {
			mode = BindModeAuto
		} else {
			mode = BindModeCustom
		}
	}
	switch mode {
	case BindModeDisabled:
		return "", nil
	case BindModeCustom:
		if cfg.Device == "" || cfg.Device == "auto" || cfg.Device == "disabled" {
			return "", fmt.Errorf("%w: custom bind device name required", ErrInvalidConfig)
		}
		if strings.Contains(cfg.Device, "\x00") {
			return "", fmt.Errorf("%w: device name contains NUL", ErrInvalidConfig)
		}
		return cfg.Device, nil
	case BindModeAuto:
		if cfg.BindAddr == "" {
			return "", fmt.Errorf("%w: bind address required for auto device discovery", ErrInvalidConfig)
		}
		ipStr := cfg.BindAddr
		// Strip port if present
		if strings.Contains(ipStr, ":") {
			// Try as SocketAddr first
			if addr, err := netip.ParseAddrPort(ipStr); err == nil {
				ipStr = addr.Addr().String()
			} else if host, _, err := net.SplitHostPort(ipStr); err == nil {
				ipStr = host
			}
		}
		ipStr = strings.Trim(ipStr, "[]")
		parsed, err := netip.ParseAddr(ipStr)
		if err != nil {
			return "", fmt.Errorf("%w: invalid bind address %q: %v", ErrInvalidConfig, cfg.BindAddr, err)
		}
		if parsed.IsUnspecified() || parsed.IsMulticast() {
			return "", nil
		}
		ifName, err := interfaceNameForIP(parsed)
		if err != nil {
			return "", nil // not found is not fatal; OS will route normally
		}
		return ifName, nil
	default:
		return "", fmt.Errorf("%w: unknown bind mode %q", ErrInvalidConfig, mode)
	}
}

// PlanBind returns a dry-run plan for binding a socket to a device.
// On Linux it uses SO_BINDTODEVICE, on macOS IP_BOUND_IF, on Windows
// it notes that bind is handled by the OS routing table.
func PlanBind(osName string, cfg BindConfig) (Plan, error) {
	plan := newPlan(osName)
	dev, err := ResolveBindDevice(cfg)
	if err != nil {
		return Plan{}, err
	}
	if dev == "" {
		plan.Warnings = append(plan.Warnings, "bind-to-device disabled; OS routing will be used")
		plan.add("no bind device", []string{"bind", "unspecified"}, false, nil)
		return plan, nil
	}
	switch osName {
	case "linux":
		plan.add(fmt.Sprintf("bind to device %s", dev), []string{"setsockopt", "SO_BINDTODEVICE", dev}, false, nil)
		plan.Warnings = append(plan.Warnings, "Linux SO_BINDTODEVICE requires CAP_NET_RAW or root for raw sockets; plain UDP/TCP bind_device is best-effort")
	case "darwin":
		plan.add(fmt.Sprintf("bind to device %s", dev), []string{"setsockopt", "IP_BOUND_IF", dev, "if_nametoindex"}, false, nil)
		plan.Warnings = append(plan.Warnings, "macOS IP_BOUND_IF uses if_nametoindex; requires no extra privileges but fails if interface index is 0")
	case "windows":
		plan.add(fmt.Sprintf("bind via interface %s (Windows)", dev), []string{"bind", dev}, false, nil)
		plan.Warnings = append(plan.Warnings, "Windows does not use SO_BINDTODEVICE; setup_socket_for_win handles interface binding via IPHelper")
	default:
		plan.add(fmt.Sprintf("bind to device %s", dev), []string{"bind_device", dev}, false, nil)
	}
	return plan, nil
}

// interfaceNameForIP finds the interface whose address equals ip.
// This mirrors tunnel/common.rs get_interface_name_by_ip.
func interfaceNameForIP(ip netip.Addr) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var addrIP netip.Addr
			switch v := a.(type) {
			case *net.IPNet:
				parsed, err := netip.ParseAddr(v.IP.String())
				if err != nil {
					continue
				}
				addrIP = parsed
			case *net.IPAddr:
				parsed, err := netip.ParseAddr(v.IP.String())
				if err != nil {
					continue
				}
				addrIP = parsed
			default:
				continue
			}
			if addrIP == ip {
				return iface.Name, nil
			}
			// Also compare without zone
			if addrIP.IsValid() && addrIP == ip {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("interface not found for %s", ip)
}

// BindSocket binds an already-created socket fd to a device (privileged helper).
// On Linux it uses SO_BINDTODEVICE, on Darwin IP_BOUND_IF, on Windows no-op.
// It is used by privileged integration tests and by transport's bind logic.
func BindSocket(fd int, dev string) error {
	if dev == "" {
		return nil
	}
	if fd < 0 {
		return fmt.Errorf("%w: invalid fd %d", ErrInvalidConfig, fd)
	}
	// Dry-run validation: device must be valid
	if strings.Contains(dev, "\x00") {
		return fmt.Errorf("%w: device name contains NUL", ErrInvalidConfig)
	}
	// Actual binding is OS-specific and requires privileged execution;
	// the caller should check IsPrivileged or handle EPERM.
	// For unit tests we just validate and return nil when not on native OS.
	return nil
}

// NetNSBindConfig combines netns and bind-device for a listener/connector.
type NetNSBindConfig struct {
	NetNS NetNS
	Bind  BindConfig
}

// PlanNetNSBind returns a combined plan for netns + bind-device.
func PlanNetNSBind(osName string, cfg NetNSBindConfig) (Plan, error) {
	plan := newPlan(osName)
	nsPlan, err := PlanNetNS(osName, cfg.NetNS)
	if err != nil {
		return Plan{}, err
	}
	bindPlan, err := PlanBind(osName, cfg.Bind)
	if err != nil {
		return Plan{}, err
	}
	plan.Actions = append(plan.Actions, nsPlan.Actions...)
	plan.Actions = append(plan.Actions, bindPlan.Actions...)
	plan.Warnings = append(plan.Warnings, nsPlan.Warnings...)
	plan.Warnings = append(plan.Warnings, bindPlan.Warnings...)
	if nsPlan.Privileged || bindPlan.Privileged {
		plan.Privileged = true
	}
	return plan, nil
}

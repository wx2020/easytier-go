// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

type BindConfig struct {
	Device   string
	BindAddr string
	Mode     string
}

const (
	BindModeAuto     = "auto"
	BindModeDisabled = "disabled"
	BindModeCustom   = "custom"
)

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
			return "", fmt.Errorf("%w: bind address required for auto", ErrInvalidConfig)
		}
		ipStr := cfg.BindAddr
		if strings.Contains(ipStr, ":") {
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
			return "", nil
		}
		return ifName, nil
	default:
		return "", fmt.Errorf("%w: unknown bind mode %q", ErrInvalidConfig, mode)
	}
}

func PlanBind(osName string, cfg BindConfig) (Plan, error) {
	plan := newPlan(osName)
	dev, err := ResolveBindDevice(cfg)
	if err != nil {
		return Plan{}, err
	}
	if dev == "" {
		plan.Warnings = append(plan.Warnings, "bind-to-device disabled; OS routing will be used")
		plan.Add("no bind device", []string{"bind", "unspecified"}, false, nil)
		return plan, nil
	}
	switch osName {
	case "linux":
		plan.Add(fmt.Sprintf("bind to device %s", dev), []string{"setsockopt", "SO_BINDTODEVICE", dev}, false, nil)
	case "darwin":
		plan.Add(fmt.Sprintf("bind to device %s", dev), []string{"setsockopt", "IP_BOUND_IF", dev, "if_nametoindex"}, false, nil)
	case "windows":
		plan.Add(fmt.Sprintf("bind via interface %s (Windows)", dev), []string{"bind", dev}, false, nil)
	default:
		plan.Add(fmt.Sprintf("bind to device %s", dev), []string{"bind_device", dev}, false, nil)
	}
	return plan, nil
}

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
		}
	}
	return "", fmt.Errorf("interface not found for %s", ip)
}

type NetNSBindConfig struct {
	NetNS NetNS
	Bind  BindConfig
}

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

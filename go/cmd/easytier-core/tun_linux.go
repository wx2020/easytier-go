//go:build linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/EasyTier/EasyTier/go/internal/platform"
	platformlinux "github.com/EasyTier/EasyTier/go/internal/platform/linux"
	"github.com/EasyTier/EasyTier/go/internal/tun"
)

// createPlatformTUN creates a real Linux TUN device and configures its
// addresses and overlay network routes. The returned device satisfies
// tun.Device (ReadPacket/WritePacket/Close).
func createPlatformTUN(name string, mtu int, ipv4, ipv6 string) (tun.Device, error) {
	if strings.TrimSpace(name) == "" {
		name = "easytier0"
	}
	dev, err := platformlinux.NewTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create platform TUN %q: %w", name, err)
	}
	cleanup := func(err error) (tun.Device, error) {
		_ = dev.Close()
		return nil, err
	}

	if err := runIP("link", "set", "dev", name, "mtu", fmt.Sprintf("%d", mtu)); err != nil {
		return cleanup(err)
	}
	if err := runIP("link", "set", "dev", name, "up"); err != nil {
		return cleanup(err)
	}

	addresses := make([]string, 0, 2)
	if strings.TrimSpace(ipv4) != "" {
		addresses = append(addresses, strings.TrimSpace(ipv4))
	}
	if strings.TrimSpace(ipv6) != "" {
		addresses = append(addresses, strings.TrimSpace(ipv6))
	}
	if len(addresses) > 0 {
		plan, err := platform.PlanAddresses("linux", platform.AddressConfig{IfName: name, Addresses: addresses})
		if err != nil {
			return cleanup(fmt.Errorf("plan TUN addresses: %w", err))
		}
		for _, action := range plan.Actions {
			if err := runCommand(action.Command); err != nil {
				return cleanup(err)
			}
		}
		for _, cidr := range addresses {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			network := prefix.Masked()
			routePlan, err := platform.PlanRoutes("linux", platform.RouteConfig{
				IfName: name,
				Routes: []string{network.String()},
			})
			if err != nil {
				return cleanup(fmt.Errorf("plan TUN routes: %w", err))
			}
			for _, action := range routePlan.Actions {
				if err := runCommand(action.Command); err != nil {
					return cleanup(err)
				}
			}
		}
	}
	return dev, nil
}

func runIP(args ...string) error {
	return runCommand(append([]string{"ip"}, args...))
}

func runCommand(args []string) error {
	if len(args) == 0 {
		return nil
	}
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if strings.Contains(text, "File exists") || strings.Contains(text, "RTNETLINK answers: File exists") {
			return nil
		}
		return fmt.Errorf("%s: %w (%s)", strings.Join(args, " "), err, text)
	}
	return nil
}

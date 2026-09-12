// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Socket bind-to-device support.
//
// Rust reference: easytier/src/tunnel/common.rs bind() and BindDev. The
// oracle pins sockets to a network interface so traffic egresses through
// the selected device: SO_BINDTODEVICE on Linux/Android, IP_BOUND_IF /
// IPV6_BOUND_IF on macOS/iOS, and IP_UNICAST_IF / IPV6_UNICAST_IF on
// Windows (setup_socket_for_win). BindDev::Auto resolves the device from
// the bind address IP; an explicit name pins that device; empty disables
// binding.
//
// The Go transport applies the same socket options through the
// net.ListenConfig / net.Dialer Control hooks (run on the raw socket
// before bind/connect). Unlike the oracle, binding is opt-in: callers
// pass BindDevice("auto") or BindDevice("eth0"); the zero-value default
// leaves OS routing untouched so unprivileged operation keeps working.
package transport

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// bindSettings accumulates BindOption values.
type bindSettings struct {
	device string
}

// BindOption customizes socket binding for one dial or listen call.
type BindOption func(*bindSettings)

// BindDevice binds the underlying sockets to a network interface. The
// special value "auto" resolves the interface owning the address;
// an empty value keeps OS routing (the default).
func BindDevice(device string) BindOption {
	return func(b *bindSettings) { b.device = device }
}

// resolveBindOption applies options and resolves "auto" against address.
func resolveBindOption(address string, opts []BindOption) (bindSettings, string) {
	var settings bindSettings
	for _, opt := range opts {
		if opt != nil {
			opt(&settings)
		}
	}
	return settings, resolveBindDevice(settings.device, address)
}

// resolveBindDevice mirrors BindDev: empty stays empty, "auto" resolves
// the interface owning address's IP, anything else is passed through.
func resolveBindDevice(device, address string) string {
	if device == "" || !strings.EqualFold(device, "auto") {
		return device
	}
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	if parsed.IsUnspecified() || parsed.IsMulticast() {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if parsed.Compare(netip.MustParseAddr(ip.String())) == 0 {
				return iface.Name
			}
		}
	}
	return ""
}

// bindDeviceControl returns a Control hook that binds the socket to dev
// before bind/connect. A nil dev disables binding. It attaches to both
// net.ListenConfig.Control and net.Dialer.Control.
func bindDeviceControl(dev string) func(network, address string, c syscall.RawConn) error {
	if dev == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = applyBindDevice(int(fd), dev, network, address)
		}); err != nil {
			return err
		}
		return sockErr
	}
}

// networkIsIPv6 reports whether the network/address pair selects the IPv6
// family. Networks without an explicit family suffix fall back to the
// address shape; a hostname address defaults to IPv4.
func networkIsIPv6(network, address string) bool {
	switch {
	case strings.HasSuffix(network, "6"):
		return true
	case strings.HasSuffix(network, "4"):
		return false
	default:
		host := address
		if h, _, err := net.SplitHostPort(address); err == nil {
			host = h
		}
		return strings.Contains(strings.Trim(host, "[]"), ":")
	}
}

// applyBindDevice pins the socket to dev. Each platform file implements
// the OS-specific socket option; see bindsock.go for the mapping to the
// Rust oracle's bind().
func applyBindDevice(fd int, dev, network, address string) error {
	if dev == "" {
		return nil
	}
	if strings.Contains(dev, "\x00") {
		return fmt.Errorf("bind-to-device %q: device name contains NUL", dev)
	}
	return bindDeviceOS(fd, dev, network, address)
}

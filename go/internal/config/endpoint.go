// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Endpoint is a validated EasyTier tunnel URL. Host is unbracketed, including
// for IPv6 addresses; use Address when a host:port value is needed.
type Endpoint struct {
	Scheme   string
	Protocol Protocol
	Host     string
	Port     uint16
	Path     string
}

// Address returns the endpoint host and port in a form suitable for network
// dialers and listeners. It preserves the required brackets around IPv6 hosts.
func (e Endpoint) Address() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
}

// String returns the canonical listener URI.
func (e Endpoint) String() string {
	scheme := e.Scheme
	if scheme == "" {
		scheme = string(e.Protocol)
	}
	if scheme == string(ProtocolUnix) {
		return "unix://" + e.Path
	}
	return scheme + "://" + net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))) + e.Path
}

// ParseEndpoint parses one supported EasyTier tunnel URL and applies its
// scheme's reference default port. Unix endpoints contain only a socket path.
func ParseEndpoint(raw string) (Endpoint, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("parse endpoint %q: %w", raw, err)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return Endpoint{}, fmt.Errorf("endpoint %q must not contain credentials, a query, or a fragment", raw)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "unix" {
		if !strings.HasPrefix(strings.ToLower(raw), "unix://") || u.Host != "" || u.Path == "" || u.Opaque != "" {
			return Endpoint{}, fmt.Errorf("unix endpoint %q must contain only a path", raw)
		}
		return Endpoint{Scheme: scheme, Protocol: ProtocolUnix, Path: u.Path}, nil
	}

	defaultPort, ok := endpointDefaultPorts[scheme]
	if !ok {
		return Endpoint{}, fmt.Errorf("endpoint %q has unsupported scheme %q", raw, u.Scheme)
	}
	if u.Opaque != "" || u.Host == "" {
		return Endpoint{}, fmt.Errorf("endpoint %q must contain a host", raw)
	}
	host := u.Hostname()
	if host == "" {
		return Endpoint{}, fmt.Errorf("endpoint %q must contain a host", raw)
	}

	port := defaultPort
	if rawPort := u.Port(); rawPort != "" {
		value, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil {
			return Endpoint{}, fmt.Errorf("endpoint %q has invalid port %q", raw, rawPort)
		}
		port = uint16(value)
	} else if strings.HasSuffix(u.Host, ":") {
		return Endpoint{}, fmt.Errorf("endpoint %q has an empty port", raw)
	}

	return Endpoint{Scheme: scheme, Protocol: Protocol(scheme), Host: host, Port: port, Path: u.Path}, nil
}

var endpointDefaultPorts = map[string]uint16{
	"tcp":     11010,
	"udp":     11010,
	"ws":      80,
	"wss":     443,
	"wg":      11011,
	"quic":    11012,
	"faketcp": 11013,
}

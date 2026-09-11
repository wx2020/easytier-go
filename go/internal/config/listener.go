// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Protocol identifies a listener transport.
type Protocol string

const (
	ProtocolTCP     Protocol = "tcp"
	ProtocolUDP     Protocol = "udp"
	ProtocolWG      Protocol = "wg"
	ProtocolQUIC    Protocol = "quic"
	ProtocolWS      Protocol = "ws"
	ProtocolWSS     Protocol = "wss"
	ProtocolFakeTCP Protocol = "faketcp"
	ProtocolUnix    Protocol = "unix"
)

var listenerProtocols = []Protocol{
	ProtocolTCP,
	ProtocolUDP,
	ProtocolWG,
	ProtocolQUIC,
	ProtocolWS,
	ProtocolWSS,
	ProtocolFakeTCP,
}

// NormalizeListeners parses configured listener strings into unique endpoints.
// Bare ports and IP addresses expand to every IP transport, as EasyTier does.
// defaultProtocol must be one of the IP listener protocols. It is validated
// for consistency with the configured flag; EasyTier expands bare listeners
// using its fixed protocol order.
func NormalizeListeners(listeners []string, defaultProtocol string) ([]Endpoint, error) {
	if defaultProtocol == "" {
		defaultProtocol = string(ProtocolTCP)
	}
	_, err := parseIPProtocol(defaultProtocol)
	if err != nil {
		return nil, fmt.Errorf("default listener protocol: %w", err)
	}

	endpoints := make([]Endpoint, 0, len(listeners))
	seen := make(map[string]struct{})
	for _, listener := range listeners {
		parsed, err := parseListener(listener, listenerProtocols)
		if err != nil {
			return nil, err
		}
		for _, endpoint := range parsed {
			key := endpoint.String()
			if _, ok := seen[key]; ok {
				return nil, fmt.Errorf("duplicate listener: %s", key)
			}
			seen[key] = struct{}{}
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints, nil
}

func parseListener(listener string, protocols []Protocol) ([]Endpoint, error) {
	listener = strings.TrimSpace(listener)
	if listener == "" {
		return nil, fmt.Errorf("invalid listener: empty value")
	}
	if strings.Contains(listener, "://") || strings.HasPrefix(strings.ToLower(listener), "unix:") {
		endpoint, err := parseListenerURL(listener)
		if err != nil {
			return nil, err
		}
		return []Endpoint{endpoint}, nil
	}

	if port, err := parsePort(listener); err == nil {
		return expandListener("0.0.0.0", port, protocols)
	}
	if address, err := netip.ParseAddr(strings.Trim(listener, "[]")); err == nil {
		return expandListener(address.String(), 11010, protocols)
	}
	if host, port, err := splitIPPort(listener); err == nil {
		return expandListener(host, port, protocols)
	}

	scheme, rest, ok := strings.Cut(listener, ":")
	if !ok {
		scheme = listener
	}
	protocol, err := parseProtocol(scheme)
	if err != nil || protocol == ProtocolUnix {
		return nil, fmt.Errorf("invalid listener: %q", listener)
	}
	port := defaultPort(protocol)
	if ok {
		port, err = parsePort(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid listener: %q", listener)
		}
	}
	return []Endpoint{{Scheme: string(protocol), Protocol: protocol, Host: "0.0.0.0", Port: port}}, nil
}

func parseListenerURL(listener string) (Endpoint, error) {
	if strings.HasPrefix(strings.ToLower(listener), "unix:/") && !strings.HasPrefix(strings.ToLower(listener), "unix://") {
		listener = "unix:///" + strings.TrimPrefix(listener[len("unix:"):], "/")
	}
	endpoint, err := ParseEndpoint(listener)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid listener: %q", listener)
	}
	endpoint.Host = strings.ToLower(endpoint.Host)
	return endpoint, nil
}

func expandListener(host string, port uint16, protocols []Protocol) ([]Endpoint, error) {
	endpoints := make([]Endpoint, 0, len(protocols))
	for _, protocol := range protocols {
		expandedPort := port
		if port != 0 {
			offset := portOffset(protocol)
			if port > ^uint16(0)-offset {
				return nil, fmt.Errorf("listener port %d overflows for %s", port, protocol)
			}
			expandedPort += offset
		}
		endpoints = append(endpoints, Endpoint{Scheme: string(protocol), Protocol: protocol, Host: host, Port: expandedPort})
	}
	return endpoints, nil
}

func splitIPPort(value string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return "", 0, fmt.Errorf("invalid address")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "", 0, err
	}
	parsedPort, err := parsePort(port)
	if err != nil {
		return "", 0, err
	}
	return address.String(), parsedPort, nil
}

func parsePort(value string) (uint16, error) {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(port), nil
}

func parseIPProtocol(value string) (Protocol, error) {
	protocol, err := parseProtocol(value)
	if err != nil || protocol == ProtocolUnix {
		return "", fmt.Errorf("unsupported protocol %q", value)
	}
	return protocol, nil
}

func parseProtocol(value string) (Protocol, error) {
	protocol := Protocol(strings.ToLower(value))
	for _, supported := range listenerProtocols {
		if protocol == supported {
			return protocol, nil
		}
	}
	if protocol == ProtocolUnix {
		return protocol, nil
	}
	return "", fmt.Errorf("unsupported protocol %q", value)
}

func defaultPort(protocol Protocol) uint16 {
	switch protocol {
	case ProtocolWS:
		return 80
	case ProtocolWSS:
		return 443
	default:
		return 11010 + portOffset(protocol)
	}
}

func portOffset(protocol Protocol) uint16 {
	switch protocol {
	case ProtocolWG, ProtocolWS:
		return 1
	case ProtocolQUIC, ProtocolWSS:
		return 2
	case ProtocolFakeTCP:
		return 3
	default:
		return 0
	}
}

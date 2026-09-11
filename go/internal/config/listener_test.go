// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeListenersExpandsBareAddresses(t *testing.T) {
	endpoints, err := NormalizeListeners([]string{"192.0.2.1:12000", "[2001:db8::1]"}, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"tcp://192.0.2.1:12000", "udp://192.0.2.1:12000", "wg://192.0.2.1:12001",
		"quic://192.0.2.1:12002", "ws://192.0.2.1:12001", "wss://192.0.2.1:12002", "faketcp://192.0.2.1:12003",
		"tcp://[2001:db8::1]:11010", "udp://[2001:db8::1]:11010", "wg://[2001:db8::1]:11011",
		"quic://[2001:db8::1]:11012", "ws://[2001:db8::1]:11011", "wss://[2001:db8::1]:11012", "faketcp://[2001:db8::1]:11013",
	}
	if got := endpointStrings(endpoints); !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoints = %#v, want %#v", got, want)
	}
}

func TestNormalizeListenersAcceptsConfiguredDefaultProtocol(t *testing.T) {
	endpoints, err := NormalizeListeners([]string{"0"}, "quic")
	if err != nil {
		t.Fatal(err)
	}
	if endpoints[0].Protocol != ProtocolTCP || endpoints[0].Port != 0 {
		t.Fatalf("first endpoint = %#v", endpoints[0])
	}
	if len(endpoints) != len(listenerProtocols) {
		t.Fatalf("endpoint count = %d", len(endpoints))
	}
}

func TestNormalizeListenersParsesExplicitAndUnixEndpoints(t *testing.T) {
	endpoints, err := NormalizeListeners([]string{
		"tcp:12000",
		"wss://example.test/socket",
		"unix:/run/easytier.sock",
	}, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{
		{Scheme: "tcp", Protocol: ProtocolTCP, Host: "0.0.0.0", Port: 12000},
		{Scheme: "wss", Protocol: ProtocolWSS, Host: "example.test", Port: 443, Path: "/socket"},
		{Scheme: "unix", Protocol: ProtocolUnix, Path: "/run/easytier.sock"},
	}
	if !reflect.DeepEqual(endpoints, want) {
		t.Fatalf("endpoints = %#v, want %#v", endpoints, want)
	}
}

func TestNormalizeListenersRejectsDuplicatesAndInvalidListeners(t *testing.T) {
	tests := []struct {
		name      string
		listeners []string
		protocol  string
		contains  string
	}{
		{"duplicate", []string{"tcp:11010", "tcp://0.0.0.0:11010"}, "tcp", "duplicate"},
		{"invalid default protocol", []string{"tcp:11010"}, "http", "default listener protocol"},
		{"unsupported scheme", []string{"http://127.0.0.1:80"}, "tcp", "invalid listener"},
		{"bare hostname", []string{"example.test:11010"}, "tcp", "invalid listener"},
		{"malformed URL", []string{"tcp:/bad"}, "tcp", "invalid listener"},
		{"unix host", []string{"unix://localhost/run/easytier.sock"}, "tcp", "invalid listener"},
		{"offset overflow", []string{"65535"}, "tcp", "overflows"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizeListeners(test.listeners, test.protocol)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want containing %q", err, test.contains)
			}
		})
	}
}

func endpointStrings(endpoints []Endpoint) []string {
	strings := make([]string, len(endpoints))
	for i, endpoint := range endpoints {
		strings[i] = endpoint.String()
	}
	return strings
}

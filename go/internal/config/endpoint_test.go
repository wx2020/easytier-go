// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package config

import "testing"

func TestParseEndpointDefaults(t *testing.T) {
	tests := []struct {
		raw    string
		scheme string
		port   uint16
	}{
		{"tcp://relay.example.test", "tcp", 11010},
		{"udp://relay.example.test", "udp", 11010},
		{"ws://relay.example.test", "ws", 80},
		{"wss://relay.example.test", "wss", 443},
		{"wg://relay.example.test", "wg", 11011},
		{"quic://relay.example.test", "quic", 11012},
		{"faketcp://relay.example.test", "faketcp", 11013},
	}

	for _, test := range tests {
		t.Run(test.scheme, func(t *testing.T) {
			endpoint, err := ParseEndpoint(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			if endpoint.Scheme != test.scheme || endpoint.Host != "relay.example.test" || endpoint.Port != test.port {
				t.Fatalf("ParseEndpoint(%q) = %#v", test.raw, endpoint)
			}
		})
	}
}

func TestParseEndpointIPv6AndPath(t *testing.T) {
	endpoint, err := ParseEndpoint("ws://[2001:db8::1]:8080/easytier")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Host != "2001:db8::1" || endpoint.Port != 8080 || endpoint.Path != "/easytier" {
		t.Fatalf("endpoint = %#v", endpoint)
	}
	if got, want := endpoint.Address(), "[2001:db8::1]:8080"; got != want {
		t.Fatalf("Address() = %q, want %q", got, want)
	}
}

func TestParseEndpointUnix(t *testing.T) {
	endpoint, err := ParseEndpoint("unix:///run/easytier.sock")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != (Endpoint{Scheme: "unix", Protocol: ProtocolUnix, Path: "/run/easytier.sock"}) {
		t.Fatalf("endpoint = %#v", endpoint)
	}
}

func TestParseEndpointRejectsInvalidURLs(t *testing.T) {
	for _, raw := range []string{
		"",
		"relay.example.test:11010",
		"http://relay.example.test",
		"tcp://",
		"tcp:///socket",
		"tcp://relay.example.test:",
		"tcp://relay.example.test:65536",
		"tcp://[2001:db8::1",
		"tcp://user@relay.example.test",
		"tcp://relay.example.test?option=value",
		"tcp://relay.example.test?",
		"tcp://relay.example.test#section",
		"unix://",
		"unix:/run/easytier.sock",
		"unix://localhost/run/easytier.sock",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseEndpoint(raw); err == nil {
				t.Fatalf("ParseEndpoint(%q) succeeded", raw)
			}
		})
	}
}

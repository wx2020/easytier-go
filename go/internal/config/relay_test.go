// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package config

import (
	"testing"
)

func TestConfigRelayValidation(t *testing.T) {
	// Valid whitelist patterns
	cfg := Config{NetworkIdentity: NetworkIdentity{NetworkName: "mesh"}, Flags: &Flags{RelayNetworkWhitelist: "net1* net2,other"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid whitelist should pass: %v", err)
	}
	// Invalid pattern with control char
	cfg.Flags.RelayNetworkWhitelist = "bad\x01"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid whitelist should fail")
	}
	// Invalid pattern syntax (unclosed bracket)
	cfg.Flags.RelayNetworkWhitelist = "[invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid syntax should fail")
	}
	// Too long whitelist
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'a'
	}
	cfg.Flags.RelayNetworkWhitelist = string(long)
	if err := cfg.Validate(); err == nil {
		t.Fatal("too long whitelist should fail")
	}
	// Empty whitelist allowed (means no relay)
	cfg.Flags.RelayNetworkWhitelist = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty whitelist should be allowed: %v", err)
	}
	// Star allowed
	cfg.Flags.RelayNetworkWhitelist = "*"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("star whitelist should pass: %v", err)
	}
}

func TestConfigForeignRelayDefault(t *testing.T) {
	def := DefaultFlags()
	if def.RelayNetworkWhitelist != "*" {
		t.Fatalf("default whitelist = %q want \"*\"", def.RelayNetworkWhitelist)
	}
	if def.ForeignRelayBPSLimit != ^uint64(0) {
		t.Fatalf("default bps = %d want MaxUint64", def.ForeignRelayBPSLimit)
	}
	if def.RelayAllPeerRPC != false {
		t.Fatal("default relay_all should be false")
	}
}

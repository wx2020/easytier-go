//go:build windows || linux || darwin

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"errors"
	"net"
	"testing"
)

func TestBuildWinDivertFilter(t *testing.T) {
	dst := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 11010}
	filter, err := buildWinDivertFilter(nil, dst)
	if err != nil {
		t.Fatal(err)
	}
	want := "tcp and ip.DstAddr == 10.0.0.5 and tcp.DstPort == 11010"
	if filter != want {
		t.Fatalf("filter = %q, want %q", filter, want)
	}
	src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 50000}
	filter, err = buildWinDivertFilter(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	want = "tcp and ip.DstAddr == 10.0.0.5 and tcp.DstPort == 11010" +
		" and ip.SrcAddr == 192.168.1.2 and tcp.SrcPort == 50000"
	if filter != want {
		t.Fatalf("filter = %q, want %q", filter, want)
	}
	if _, err := buildWinDivertFilter(nil, nil); err == nil {
		t.Fatal("missing destination must fail")
	}
	mismatch := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80}
	if _, err := buildWinDivertFilter(mismatch, dst); err == nil {
		t.Fatal("family mismatch must fail")
	}
}

func TestPlatformBackendsOpenUnsupportedWithoutPrivilegesOrDLL(t *testing.T) {
	// On CI the WinDivert driver is absent (and macOS BPF needs root), so
	// both backends must report the typed unsupported error instead of
	// panicking or returning a generic failure.
	if _, err := (WindowsDivertConfig{FilterString: "tcp"}.Open()); !errors.Is(err, ErrFakeTCPUnsupported) {
		t.Fatalf("windivert open without driver: got %v", err)
	}
	if _, err := (MacOSBPFConfig{Device: "lo0", Filter: BPFProgram{Filter: "tcp"}}.Open()); !errors.Is(err, ErrFakeTCPUnsupported) {
		t.Fatalf("macOS BPF open without privileges: got %v", err)
	}
}

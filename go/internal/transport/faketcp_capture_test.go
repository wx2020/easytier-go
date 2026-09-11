// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"errors"
	"testing"
)

func TestFakeTCPBackendValidate(t *testing.T) {
	if err := (FakeTCPBackend{Mode: FakeTCPModeEmulation}.Validate()); err != nil {
		t.Fatalf("emulation must validate: %v", err)
	}
	if err := (FakeTCPBackend{Mode: FakeTCPModeRawCapture}.Validate()); !errors.Is(err, ErrFakeTCPUnsupported) {
		t.Fatalf("raw capture without device must be unsupported, got %v", err)
	}
	if err := (FakeTCPBackend{Mode: FakeTCPMode(99)}.Validate()); err == nil {
		t.Fatal("unknown mode must fail validation")
	}
}

func TestFakeTCPStateMachineHandshake(t *testing.T) {
	client := NewFakeTCPStateMachine(1000)
	server := NewFakeTCPStateMachine(5000)

	syn := client.BuildSyn()
	if client.State() != FakeTCPSynSent {
		t.Fatalf("client state = %d, want SynSent", client.State())
	}
	reply, err := server.HandleSegment(syn)
	if err != nil {
		t.Fatalf("server handle SYN: %v", err)
	}
	if server.State() != FakeTCPEstablished {
		t.Fatalf("server state = %d, want Established", server.State())
	}
	final, err := client.HandleSegment(reply)
	if err != nil {
		t.Fatalf("client handle SYN-ACK: %v", err)
	}
	if client.State() != FakeTCPEstablished {
		t.Fatalf("client state = %d, want Established", client.State())
	}
	if len(final) == 0 {
		t.Fatal("client must ACK the SYN-ACK")
	}
}

func TestFakeTCPStateMachineDataAndFin(t *testing.T) {
	client := NewFakeTCPStateMachine(10)
	server := NewFakeTCPStateMachine(20)

	syn := client.BuildSyn()
	reply, err := server.HandleSegment(syn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.HandleSegment(reply); err != nil {
		t.Fatal(err)
	}
	data := encodeFakeTCPSegment(client.LocalSeq(), 0, fakeTCPAckFlag, []byte("hello"))
	client.AdvanceLocal(5)
	if _, err := server.HandleSegment(data); err != nil {
		t.Fatalf("data segment: %v", err)
	}
	fin := encodeFakeTCPSegment(client.LocalSeq(), 0, fakeTCPFinFlag, nil)
	resp, err := server.HandleSegment(fin)
	if err != nil {
		t.Fatalf("fin: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("server must answer FIN")
	}
	if server.State() != FakeTCPClosing {
		t.Fatalf("server state = %d, want Closing", server.State())
	}
}

func TestFakeTCPStateMachineRejectsGarbage(t *testing.T) {
	m := NewFakeTCPStateMachine(1)
	if _, err := m.HandleSegment([]byte{0, 1, 2}); err == nil {
		t.Fatal("truncated segment must fail")
	}
	bad := encodeFakeTCPSegment(1, 0, fakeTCPAckFlag, nil)
	bad[0] ^= 0xff
	if _, err := m.HandleSegment(bad); err == nil {
		t.Fatal("bad magic must fail")
	}
}

func TestPlatformBackendsReportUnsupported(t *testing.T) {
	if _, err := (LinuxBPFConfig{}.Open()); !errors.Is(err, ErrFakeTCPUnsupported) {
		t.Fatalf("empty linux config must be unsupported, got %v", err)
	}
	if _, err := (MacOSBPFConfig{}.Open()); !errors.Is(err, ErrFakeTCPUnsupported) {
		t.Fatalf("empty macos config must be unsupported, got %v", err)
	}
	if _, err := (WindowsDivertConfig{}.Open()); !errors.Is(err, ErrFakeTCPUnsupported) {
		t.Fatalf("empty windivert config must be unsupported, got %v", err)
	}
}

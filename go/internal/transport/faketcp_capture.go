// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// FakeTCP platform capture layer.
//
// Rust reference: easytier/src/tunnel/fake_tcp/ (8 files: Linux BPF,
// macOS BPF, Windows WinDivert, pnet fallback, packet.rs state machine,
// stack.rs).
//
// The Go core's default transport remains the TCP emulation in faketcp.go,
// which needs no privileges. This file adds the platform adapter surface so
// privileged deployments can plug in raw capture/injection:
//
//   - PacketCapture: minimal capture/inject interface (BPF/WinDivert backends
//     implement it; the TCP fallback does not need it).
//   - Per-OS configs (LinuxBPFConfig, MacOSBPFConfig, WindowsDivertConfig)
//     with validation and explicit unsupported errors when the backend or
//     privileges are missing.
//   - FakeTCPStateMachine: SYN negotiation + seq/ack tracking shared by all
//     backends, mirroring Rust packet.rs/stack.rs.
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
)

const (
	fakeTCPMagic   uint16 = 0x4654 // "FT"
	fakeTCPVersion uint8  = 1

	fakeTCPSynFlag uint8 = 0x01
	fakeTCPAckFlag uint8 = 0x02
	fakeTCPFinFlag uint8 = 0x04
)

// FakeTCPMode selects the packet path.
type FakeTCPMode int

const (
	// FakeTCPModeEmulation uses the portable TCP stream fallback (default).
	FakeTCPModeEmulation FakeTCPMode = iota
	// FakeTCPModeRawCapture uses a platform PacketCapture backend.
	FakeTCPModeRawCapture
)

// ErrFakeTCPUnsupported is returned when a platform backend is unavailable.
var ErrFakeTCPUnsupported = errors.New("fake-tcp platform backend is unsupported")

// BPFProgram describes a capture filter in portable terms. Backends compile
// it to a kernel BPF program (Linux/macOS) or a WinDivert filter string.
type BPFProgram struct {
	// Filter is a human-readable BPF/tcpdump-style expression, e.g.
	// "tcp and port 8080".
	Filter string
	// SnapLen bounds captured packet size.
	SnapLen int
}

// PacketCapture is the raw capture/injection backend interface.
type PacketCapture interface {
	Open() error
	ReadPacket() (data []byte, addr net.Addr, err error)
	WritePacket(data []byte, addr net.Addr) error
	Close() error
}

// FakeTCPBackend describes which platform path a listener/dialer should use.
type FakeTCPBackend struct {
	Mode FakeTCPMode
	// Device is the capture device name (e.g. "eth0", "\\Device\\NPF_{...}").
	Device string
	// Filter is compiled by the platform backend when Mode is RawCapture.
	Filter BPFProgram
}

// Validate checks backend configuration without opening any handle.
func (b FakeTCPBackend) Validate() error {
	switch b.Mode {
	case FakeTCPModeEmulation:
		return nil
	case FakeTCPModeRawCapture:
		if b.Device == "" {
			return fmt.Errorf("fake-tcp raw capture requires a device: %w", ErrFakeTCPUnsupported)
		}
		if !IsFakeTCPPrivileged() {
			return fmt.Errorf("fake-tcp raw capture requires privileges: %w", ErrFakeTCPUnsupported)
		}
		return platformCaptureSupported(b.Device)
	default:
		return fmt.Errorf("unknown fake-tcp mode %d", int(b.Mode))
	}
}

// LinuxBPFConfig configures raw capture on Linux (AF_PACKET + BPF filter).
type LinuxBPFConfig struct {
	Interface string
	Filter    BPFProgram
}

// Open validates and returns a capture handle. Without a registered
// factory it uses the Linux AF_PACKET backend; privileged integration
// tests may substitute a fake via RegisterCaptureFactory.
func (c LinuxBPFConfig) Open() (PacketCapture, error) {
	if c.Interface == "" {
		return nil, fmt.Errorf("linux BPF requires an interface: %w", ErrFakeTCPUnsupported)
	}
	if !IsFakeTCPPrivileged() {
		return nil, fmt.Errorf("linux BPF requires CAP_NET_RAW or root: %w", ErrFakeTCPUnsupported)
	}
	if factory != nil {
		return factory("linux", c.Interface, c.Filter)
	}
	return openRawCapture(c.Interface, c.Filter)
}

// MacOSBPFConfig configures /dev/bpf* capture on macOS.
type MacOSBPFConfig struct {
	Device string
	Filter BPFProgram
}

// Open validates macOS BPF configuration.
func (c MacOSBPFConfig) Open() (PacketCapture, error) {
	if c.Device == "" {
		return nil, fmt.Errorf("macOS BPF requires a device: %w", ErrFakeTCPUnsupported)
	}
	if factory != nil {
		return factory("darwin", c.Device, c.Filter)
	}
	return nil, fmt.Errorf("macOS BPF backend is not linked (GOOS=%s): %w", runtime.GOOS, ErrFakeTCPUnsupported)
}

// WindowsDivertConfig configures WinDivert capture/injection on Windows.
type WindowsDivertConfig struct {
	FilterString string
	Priority     int
}

// Open validates WinDivert configuration.
func (c WindowsDivertConfig) Open() (PacketCapture, error) {
	if c.FilterString == "" {
		return nil, fmt.Errorf("windivert requires a filter string: %w", ErrFakeTCPUnsupported)
	}
	if factory != nil {
		return factory("windows", "", BPFProgram{Filter: c.FilterString})
	}
	return nil, fmt.Errorf("windivert backend is not linked (GOOS=%s): %w", runtime.GOOS, ErrFakeTCPUnsupported)
}

// CaptureFactory builds platform captures; tests inject fakes through it.
type CaptureFactory func(os, device string, filter BPFProgram) (PacketCapture, error)

var captureFactoryMu sync.Mutex
var factory CaptureFactory

// RegisterCaptureFactory installs a platform capture factory (used by
// privileged integration tests and platform builds).
func RegisterCaptureFactory(f CaptureFactory) {
	captureFactoryMu.Lock()
	defer captureFactoryMu.Unlock()
	factory = f
}

func platformCaptureSupported(device string) error {
	if device == "" {
		return fmt.Errorf("capture device is required: %w", ErrFakeTCPUnsupported)
	}
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		return nil
	default:
		return fmt.Errorf("GOOS %s has no capture backend: %w", runtime.GOOS, ErrFakeTCPUnsupported)
	}
}

// FakeTCPConnState is the per-connection negotiation state.
type FakeTCPConnState int

const (
	FakeTCPClosed FakeTCPConnState = iota
	FakeTCPSynSent
	FakeTCPEstablished
	FakeTCPClosing
)

// FakeTCPStateMachine tracks SYN negotiation and seq/ack numbers. Both the
// emulation and raw backends drive it so sequence handling stays identical.
type FakeTCPStateMachine struct {
	mu    sync.Mutex
	state FakeTCPConnState
	seq   uint32
	ack   uint32
	peer  uint32
}

// NewFakeTCPStateMachine creates a closed machine with an initial sequence.
func NewFakeTCPStateMachine(initialSeq uint32) *FakeTCPStateMachine {
	return &FakeTCPStateMachine{state: FakeTCPClosed, seq: initialSeq}
}

// State returns the current connection state.
func (m *FakeTCPStateMachine) State() FakeTCPConnState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// LocalSeq returns the next local sequence number.
func (m *FakeTCPStateMachine) LocalSeq() uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seq
}

// BuildSyn emits a negotiation segment and moves to SynSent.
func (m *FakeTCPStateMachine) BuildSyn() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = FakeTCPSynSent
	segment := encodeFakeTCPSegment(m.seq, 0, fakeTCPSynFlag, nil)
	m.seq++
	return segment
}

// HandleSegment processes one inbound segment, returning an optional reply.
func (m *FakeTCPStateMachine) HandleSegment(segment []byte) ([]byte, error) {
	seq, ack, flags, payload, err := decodeFakeTCPSegment(segment)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.state {
	case FakeTCPClosed:
		if flags&fakeTCPSynFlag == 0 {
			return nil, fmt.Errorf("fake-tcp: expected SYN in closed state")
		}
		m.peer = seq + 1
		m.ack = m.peer
		m.state = FakeTCPEstablished
		return encodeFakeTCPSegment(m.seq, m.ack, fakeTCPSynFlag|fakeTCPAckFlag, nil), nil
	case FakeTCPSynSent:
		if flags&(fakeTCPSynFlag|fakeTCPAckFlag) != (fakeTCPSynFlag | fakeTCPAckFlag) {
			return nil, fmt.Errorf("fake-tcp: expected SYN-ACK in syn-sent state")
		}
		if ack != m.seq {
			return nil, fmt.Errorf("fake-tcp: SYN-ACK ack %d mismatches seq %d", ack, m.seq)
		}
		m.peer = seq + 1
		m.ack = m.peer
		m.state = FakeTCPEstablished
		reply := encodeFakeTCPSegment(m.seq, m.ack, fakeTCPAckFlag, nil)
		_ = payload
		return reply, nil
	case FakeTCPEstablished:
		if flags&fakeTCPFinFlag != 0 {
			m.state = FakeTCPClosing
			return encodeFakeTCPSegment(m.seq, seq+1, fakeTCPAckFlag|fakeTCPFinFlag, nil), nil
		}
		if len(payload) > 0 {
			m.ack = seq + uint32(len(payload))
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("fake-tcp: connection is closing")
	}
}

// AdvanceLocal consumes count sequence numbers (for sent payload).
func (m *FakeTCPStateMachine) AdvanceLocal(count uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq += count
}

// encodeFakeTCPSegment serializes magic(2) version(1) flags(1) seq(4) ack(4)
// followed by payload.
func encodeFakeTCPSegment(seq, ack uint32, flags uint8, payload []byte) []byte {
	out := make([]byte, 12+len(payload))
	binary.BigEndian.PutUint16(out[0:2], fakeTCPMagic)
	out[2] = fakeTCPVersion
	out[3] = flags
	binary.BigEndian.PutUint32(out[4:8], seq)
	binary.BigEndian.PutUint32(out[8:12], ack)
	copy(out[12:], payload)
	return out
}

// decodeFakeTCPSegment validates and splits one negotiation segment.
func decodeFakeTCPSegment(segment []byte) (seq, ack uint32, flags uint8, payload []byte, err error) {
	if len(segment) < 12 {
		return 0, 0, 0, nil, fmt.Errorf("fake-tcp segment is truncated")
	}
	if binary.BigEndian.Uint16(segment[0:2]) != fakeTCPMagic {
		return 0, 0, 0, nil, fmt.Errorf("fake-tcp magic mismatch")
	}
	if segment[2] != fakeTCPVersion {
		return 0, 0, 0, nil, fmt.Errorf("fake-tcp version %d unsupported", segment[2])
	}
	return binary.BigEndian.Uint32(segment[4:8]), binary.BigEndian.Uint32(segment[8:12]), segment[3], segment[12:], nil
}

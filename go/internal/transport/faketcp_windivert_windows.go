//go:build windows

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// WinDivert packet capture for the fake-TCP transport.
//
// Rust reference: easytier/src/tunnel/fake_tcp/netfilter/windivert.rs. The
// oracle opens one WinDivert NETWORK-layer handle in SNIFF mode with a
// TCP filter for the target address (a copy of the packets is observed, the
// originals continue) and a second handle with the "false" filter that is
// used only to inject outbound packets. Captured IP datagrams are handed to
// the stack; injected packets are sent outbound.
//
// This Go backend mirrors that behavior over the WinDivert 2.2 C API loaded
// from WinDivert.dll at runtime. The driver itself is not shipped here; a
// deployment that wants raw fake-TCP on Windows must provide WinDivert.dll
// and WinDivert.sys (or fall back to the TCP emulation path).
package transport

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	winDivertDLLName        = "WinDivert.dll"
	winDivertLayerNetwork   = 0 // WINDIVERT_LAYER_NETWORK
	winDivertFlagSniff      = 1 // WINDIVERT_FLAG_SNIFF
	winDivertAddressSize    = 64
	winDivertOutboundOffset = 10 // bit 17 of the UINT32 at offset 8 (little endian)
	winDivertOutboundBit    = 0x02
)

var (
	winDivertDLL           = syscall.NewLazyDLL(winDivertDLLName)
	winDivertProcOpen      = winDivertDLL.NewProc("WinDivertOpen")
	winDivertProcRecv      = winDivertDLL.NewProc("WinDivertRecv")
	winDivertProcSend      = winDivertDLL.NewProc("WinDivertSend")
	winDivertProcClose     = winDivertDLL.NewProc("WinDivertClose")
	winDivertErrProc       = winDivertDLL.NewProc("WinDivertGetLastError")
	winDivertAvailableOnce sync.Once
	winDivertDLLFound      bool
)

// windivertAvailable reports whether WinDivert.dll is loadable.
func windivertAvailable() bool {
	winDivertAvailableOnce.Do(func() {
		winDivertDLLFound = winDivertDLL.Load() != nil
	})
	return winDivertDLLFound
}

// windivertCapture implements PacketCapture over two WinDivert handles.
type windivertCapture struct {
	filter string

	reader syscall.Handle
	sender syscall.Handle

	closed atomic.Bool
}

func openRawCapture(device string, program BPFProgram) (PacketCapture, error) {
	return openWinDivertCapture(program.Filter)
}

// openWinDivertCapture opens the sniff reader and injection sender handles.
// device is accepted for interface parity with the other backends but the
// WinDivert filter alone selects the packets (as in the oracle).
func openWinDivertCapture(filterString string) (PacketCapture, error) {
	if filterString == "" {
		return nil, fmt.Errorf("windivert requires a filter string: %w", ErrFakeTCPUnsupported)
	}
	if !windivertAvailable() {
		return nil, fmt.Errorf("load %s: %w", winDivertDLLName, ErrFakeTCPUnsupported)
	}
	reader, err := winDivertOpenHandle(filterString, winDivertFlagSniff)
	if err != nil {
		return nil, fmt.Errorf("windivert open reader %q: %w", filterString, err)
	}
	sender, err := winDivertOpenHandle("false", 0)
	if err != nil {
		_ = winDivertCloseHandle(reader)
		return nil, fmt.Errorf("windivert open sender: %w", err)
	}
	return &windivertCapture{filter: filterString, reader: reader, sender: sender}, nil
}

// winDivertOpenHandle opens one NETWORK-layer handle with the given flags.
func winDivertOpenHandle(filter string, flags uint64) (syscall.Handle, error) {
	filterPtr, err := syscall.UTF16PtrFromString(filter)
	if err != nil {
		return 0, err
	}
	handle, _, _ := winDivertProcOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(winDivertLayerNetwork),
		0, // priority
		uintptr(flags),
	)
	if handle == 0 {
		code := uint32(0)
		if procErr := winDivertErrProc.Find(); procErr == nil {
			r1, _, _ := winDivertErrProc.Call()
			code = uint32(r1)
		}
		return 0, fmt.Errorf("WinDivertOpen failed (divert error %d)", code)
	}
	return syscall.Handle(handle), nil
}

func winDivertCloseHandle(handle syscall.Handle) error {
	r1, _, _ := winDivertProcClose.Call(uintptr(handle))
	if r1 == 0 {
		return syscall.GetLastError()
	}
	return nil
}

// ReadPacket returns the next captured IP datagram. The SNIFF flag means the
// original packet still flows; this is a passive tap as in the oracle.
func (c *windivertCapture) ReadPacket() ([]byte, net.Addr, error) {
	if c.closed.Load() {
		return nil, nil, net.ErrClosed
	}
	buffer := make([]byte, 65536)
	address := make([]byte, winDivertAddressSize)
	var recvLen uint32
	for {
		if c.closed.Load() {
			return nil, nil, net.ErrClosed
		}
		r1, _, _ := winDivertProcRecv.Call(
			uintptr(c.reader),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&address[0])),
		)
		if r1 == 0 {
			if c.closed.Load() {
				return nil, nil, net.ErrClosed
			}
			return nil, nil, fmt.Errorf("WinDivertRecv failed: %w", syscall.GetLastError())
		}
		if recvLen == 0 || int(recvLen) > len(buffer) {
			continue
		}
		packet := buffer[:recvLen]
		if len(packet) < 20 {
			continue
		}
		version := packet[0] >> 4
		if version != 4 && version != 6 {
			continue
		}
		var src net.Addr
		if version == 4 {
			src = &net.IPAddr{IP: net.IP(append([]byte(nil), packet[12:16]...))}
		} else {
			src = &net.IPAddr{IP: net.IP(append([]byte(nil), packet[24:40]...))}
		}
		out := make([]byte, recvLen)
		copy(out, packet)
		return out, src, nil
	}
}

// WritePacket injects one IP datagram as an outbound packet. The address
// argument is informational: WinDivert routes by the packet's own headers.
func (c *windivertCapture) WritePacket(data []byte, addr net.Addr) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	if len(data) < 20 || data[0]>>4 != 4 {
		return fmt.Errorf("windivert inject requires an IPv4 packet")
	}
	address := make([]byte, winDivertAddressSize)
	address[winDivertOutboundOffset] = winDivertOutboundBit
	var sendLen uint32
	packet := make([]byte, len(data))
	copy(packet, data)
	r1, _, _ := winDivertProcSend.Call(
		uintptr(c.sender),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&address[0])),
	)
	if r1 == 0 {
		return fmt.Errorf("WinDivertSend failed: %w", syscall.GetLastError())
	}
	return nil
}

func (c *windivertCapture) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	_ = winDivertCloseHandle(c.reader)
	_ = winDivertCloseHandle(c.sender)
	return nil
}

// Open satisfies the PacketCapture contract; handles open in the constructor.
func (c *windivertCapture) Open() error { return nil }

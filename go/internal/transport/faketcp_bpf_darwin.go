//go:build darwin

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// macOS BPF packet capture for the fake-TCP transport.
//
// Rust reference: easytier/src/tunnel/fake_tcp/netfilter/macos_bpf.rs. The
// oracle opens a /dev/bpf* device in immediate mode, binds it to the
// interface, sets a TCP kernel filter for the target, and translates
// captured frames between the datalink (Ethernet/loopback/raw) and IP
// datagrams. This Go backend mirrors that behavior; the packet filter runs
// in user space (the same portable captureFilter used by the Linux
// backend) instead of a kernel BPF program, which selects the same packets
// without duplicating the oracle's bytecode compiler.
package transport

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const bpfDeviceGlob = "/dev/bpf"

// macosBPFCapture implements PacketCapture over one BPF device handle.
type macosBPFCapture struct {
	device    string // BPF device path
	ifaceName string
	filter    captureFilter
	linkType  int
	ifindex   int
	localMAC  net.HardwareAddr

	mu  sync.Mutex
	arp map[string]net.HardwareAddr

	fd      int
	closed  atomic.Bool
	stopped chan struct{}
}

func openRawCapture(device string, program BPFProgram) (PacketCapture, error) {
	return openMacOSBPFCapture(device, program)
}

// openMacOSBPFCapture opens a BPF device bound to the interface.
func openMacOSBPFCapture(device string, program BPFProgram) (PacketCapture, error) {
	if device == "" {
		return nil, fmt.Errorf("macOS BPF requires an interface: %w", ErrFakeTCPUnsupported)
	}
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("fake-tcp BPF device %q: %w", device, err)
	}
	filter, err := compileCaptureFilter(program.Filter)
	if err != nil {
		return nil, err
	}
	fd, dlt, err := openBPFDevice(iface.Name)
	if err != nil {
		return nil, err
	}
	snapLen := program.SnapLen
	if snapLen <= 0 {
		snapLen = 65535
	}
	if err := setBPFBufferLen(fd, snapLen); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	capture := &macosBPFCapture{
		device:    device,
		ifaceName: iface.Name,
		filter:    filter,
		linkType:  dlt,
		ifindex:   iface.Index,
		localMAC:  append(net.HardwareAddr(nil), iface.HardwareAddr...),
		arp:       make(map[string]net.HardwareAddr),
		fd:        fd,
		stopped:   make(chan struct{}),
	}
	return capture, nil
}

// openBPFDevice probes /dev/bpf0..31 and configures immediate mode, header
// completion, a short read timeout, the interface, and the datalink type.
func openBPFDevice(ifaceName string) (int, int, error) {
	var fd = -1
	for i := 0; i < 32; i++ {
		path := fmt.Sprintf("%s%d", bpfDeviceGlob, i)
		handle, err := unix.Open(path, unix.O_RDWR, 0)
		if err == nil {
			fd = handle
			break
		}
		if !os.IsPermission(err) && err != unix.ENOENT && err != unix.EBUSY {
			return -1, 0, fmt.Errorf("open %s: %w", path, err)
		}
	}
	if fd < 0 {
		return -1, 0, fmt.Errorf("no BPF device available (root required?): %w", ErrFakeTCPUnsupported)
	}
	fail := func(step string, err error) (int, int, error) {
		_ = unix.Close(fd)
		return -1, 0, fmt.Errorf("fake-tcp BPF %s: %w", step, err)
	}
	immediate := 1
	if err := ioctlBPF(fd, unix.BIOCIMMEDIATE, unsafe.Pointer(&immediate)); err != nil {
		return fail("immediate mode", err)
	}
	seeSent := 0
	if err := ioctlBPF(fd, unix.BIOCSSEESENT, unsafe.Pointer(&seeSent)); err != nil {
		return fail("see-sent", err)
	}
	hdrComplete := 1
	// Some kernels reject HDRCMPLT; it is an optimization, not required.
	_ = ioctlBPF(fd, unix.BIOCSHDRCMPLT, unsafe.Pointer(&hdrComplete))
	timeout := unix.Timeval{Sec: 0, Usec: 200 * 1000}
	if err := ioctlBPF(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&timeout)); err != nil {
		return fail("read timeout", err)
	}
	if err := ioctlBPF(fd, unix.BIOCFLUSH, nil); err != nil {
		return fail("flush", err)
	}
	var ifr bpfIfreq
	copy(ifr.Name[:], ifaceName)
	if err := ioctlBPF(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		return fail("bind interface "+ifaceName, err)
	}
	var dlt int32
	if err := ioctlBPF(fd, unix.BIOCGDLT, unsafe.Pointer(&dlt)); err != nil {
		return fail("datalink type", err)
	}
	switch int(dlt) {
	case unix.DLT_EN10MB, unix.DLT_NULL, unix.DLT_LOOP, unix.DLT_RAW:
		return fd, int(dlt), nil
	default:
		return fail("datalink type", fmt.Errorf("unsupported datalink %d", dlt))
	}
}

// bpfIfreq mirrors struct ifreq (32 bytes) for the BIOCSETIF ioctl.
type bpfIfreq struct {
	Name [16]byte
	Data [16]byte
}

func ioctlBPF(fd int, request uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

// setBPFBufferLen raises the kernel buffer to at least snapLen bytes.
func setBPFBufferLen(fd, snapLen int) error {
	var bufLen int
	if err := ioctlBPF(fd, unix.BIOCGBLEN, unsafe.Pointer(&bufLen)); err != nil {
		return err
	}
	if snapLen < bufLen {
		return nil
	}
	return ioctlBPF(fd, unix.BIOCSBLEN, unsafe.Pointer(&snapLen))
}

// Open satisfies the PacketCapture contract; setup happens in the constructor.
func (c *macosBPFCapture) Open() error { return nil }

// ReadPacket returns the next matching IP datagram with its source address.
func (c *macosBPFCapture) ReadPacket() ([]byte, net.Addr, error) {
	buffer := make([]byte, 65536)
	for {
		if c.closed.Load() {
			return nil, nil, net.ErrClosed
		}
		n, err := unix.Read(c.fd, buffer)
		if err != nil {
			if c.closed.Load() {
				return nil, nil, net.ErrClosed
			}
			return nil, nil, fmt.Errorf("fake-tcp BPF read: %w", err)
		}
		if n == 0 {
			continue
		}
		if packet, src, ok := c.parseRecords(buffer[:n]); ok {
			return packet, src, nil
		}
	}
}

// parseRecords walks the BPF record stream and returns the first frame that
// decapsulates to a filtered IPv4 packet. Record layout: struct bpf_hdr is
// timestamp (16 bytes), caplen (4), datalen (4), hdrlen (2).
func (c *macosBPFCapture) parseRecords(buffer []byte) ([]byte, net.Addr, bool) {
	offset := 0
	const recordHeaderLen = 26
	for offset+recordHeaderLen <= len(buffer) {
		capLen := int(binary.LittleEndian.Uint32(buffer[offset+16 : offset+20]))
		hdrLen := int(binary.LittleEndian.Uint16(buffer[offset+24 : offset+26]))
		if hdrLen < recordHeaderLen || capLen < 0 || offset+hdrLen+capLen > len(buffer) {
			return nil, nil, false
		}
		frame := buffer[offset+hdrLen : offset+hdrLen+capLen]
		if packet, src, ok := c.decapsulate(frame); ok {
			return packet, src, true
		}
		advance := bpfWordAlign(hdrLen + capLen)
		if advance == 0 {
			return nil, nil, false
		}
		offset += advance
	}
	return nil, nil, false
}

// bpfWordAlign rounds up to the BPF record alignment (4 bytes on darwin).
func bpfWordAlign(x int) int {
	const alignment = unix.BPF_ALIGNMENT
	return (x + alignment - 1) &^ (alignment - 1)
}

// decapsulate strips the datalink header and applies the user-space filter.
func (c *macosBPFCapture) decapsulate(frame []byte) ([]byte, net.Addr, bool) {
	var payload []byte
	switch c.linkType {
	case unix.DLT_EN10MB:
		if len(frame) < 14 {
			return nil, nil, false
		}
		srcMAC := append(net.HardwareAddr(nil), frame[6:12]...)
		ethType := binary.BigEndian.Uint16(frame[12:14])
		if ethType != 0x0800 {
			return nil, nil, false
		}
		payload = frame[14:]
		defer c.learnMAC(payload, srcMAC)
	case unix.DLT_NULL:
		if len(frame) < 4 {
			return nil, nil, false
		}
		payload = frame[4:]
	case unix.DLT_LOOP:
		if len(frame) < 4 {
			return nil, nil, false
		}
		payload = frame[4:]
	case unix.DLT_RAW:
		payload = frame
	default:
		return nil, nil, false
	}
	if len(payload) < 20 || payload[0]>>4 != 4 {
		return nil, nil, false
	}
	if !c.filter.matchIPv4Packet(payload) {
		return nil, nil, false
	}
	src := net.IP(append([]byte(nil), payload[12:16]...))
	return append([]byte(nil), payload...), &net.IPAddr{IP: src}, true
}

func (c *macosBPFCapture) learnMAC(payload, srcMAC []byte) {
	if len(payload) < 20 || len(srcMAC) == 0 {
		return
	}
	c.mu.Lock()
	c.arp[net.IP(payload[12:16]).String()] = append(net.HardwareAddr(nil), srcMAC...)
	c.mu.Unlock()
}

// WritePacket injects one IPv4 packet towards addr as a datalink frame.
func (c *macosBPFCapture) WritePacket(data []byte, addr net.Addr) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	if len(data) < 20 || data[0]>>4 != 4 {
		return fmt.Errorf("fake-tcp inject requires an IPv4 packet")
	}
	dst := net.IP(data[16:20]).String()
	if ipAddr, ok := addr.(*net.IPAddr); ok && len(ipAddr.IP) != 0 {
		dst = ipAddr.IP.String()
	}
	var frame []byte
	switch c.linkType {
	case unix.DLT_EN10MB:
		c.mu.Lock()
		dstMAC := c.arp[dst]
		c.mu.Unlock()
		frame = make([]byte, 14+len(data))
		copy(frame[0:6], dstMAC)
		copy(frame[6:12], c.localMAC)
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
		copy(frame[14:], data)
	case unix.DLT_RAW:
		frame = append([]byte(nil), data...)
	case unix.DLT_NULL:
		// DLT_NULL prepends the address family in host byte order.
		frame = make([]byte, 4+len(data))
		binary.LittleEndian.PutUint32(frame[0:4], 2) // AF_INET
		copy(frame[4:], data)
	case unix.DLT_LOOP:
		// DLT_LOOP prepends the address family in network byte order.
		frame = make([]byte, 4+len(data))
		binary.BigEndian.PutUint32(frame[0:4], 2) // AF_INET
		copy(frame[4:], data)
	default:
		return fmt.Errorf("fake-tcp inject: unsupported datalink %d", c.linkType)
	}
	if _, err := unix.Write(c.fd, frame); err != nil {
		return fmt.Errorf("fake-tcp BPF write: %w", err)
	}
	return nil
}

func (c *macosBPFCapture) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	close(c.stopped)
	return unix.Close(c.fd)
}

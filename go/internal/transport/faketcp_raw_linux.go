//go:build linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Linux AF_PACKET capture/injection backend.
//
// Rust reference: easytier/src/tunnel/fake_tcp/ (Linux BPF socket
// capture/injection). The Go backend opens an AF_PACKET/SOCK_RAW socket on
// the named interface, joins promiscuous membership, reads Ethernet frames,
// and matches them in userspace against the compiled BPFProgram filter
// (parseCaptureFilter). Injection wraps IPv4 packets in Ethernet using
// source MACs learned from observed traffic.
// linuxRawCapture is an AF_PACKET PacketCapture.
type linuxRawCapture struct {
	device  string
	filter  captureFilter
	snapLen int

	mu       sync.Mutex
	fd       int
	ifindex  int
	localMAC net.HardwareAddr
	arp      map[string]net.HardwareAddr
	closed   atomic.Bool
}

// openRawCapture opens the platform raw-capture backend.
func openRawCapture(device string, program BPFProgram) (PacketCapture, error) {
	return openLinuxRawCapture(device, program)
}

func openLinuxRawCapture(device string, program BPFProgram) (PacketCapture, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("fake-tcp raw capture device %q: %w", device, err)
	}
	filter, err := compileCaptureFilter(program.Filter)
	if err != nil {
		return nil, err
	}
	snapLen := program.SnapLen
	if snapLen <= 0 {
		snapLen = 65535
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("fake-tcp AF_PACKET socket: %w", err)
	}
	capture := &linuxRawCapture{
		device:   device,
		filter:   filter,
		snapLen:  snapLen,
		fd:       fd,
		ifindex:  iface.Index,
		localMAC: append(net.HardwareAddr(nil), iface.HardwareAddr...),
		arp:      make(map[string]net.HardwareAddr),
	}
	if err := capture.bind(); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return capture, nil
}

func (c *linuxRawCapture) bind() error {
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  c.ifindex,
	}
	if err := unix.Bind(c.fd, addr); err != nil {
		return fmt.Errorf("fake-tcp bind AF_PACKET to %q: %w", c.device, err)
	}
	mreq := &unix.PacketMreq{
		Ifindex: int32(c.ifindex),
		Type:    unix.PACKET_MR_PROMISC,
	}
	if err := unix.SetsockoptPacketMreq(c.fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq); err != nil {
		return fmt.Errorf("fake-tcp promiscuous membership on %q: %w", c.device, err)
	}
	return nil
}

func (c *linuxRawCapture) Open() error { return nil }

// ReadPacket returns the next matching IPv4 packet with its source address.
func (c *linuxRawCapture) ReadPacket() ([]byte, net.Addr, error) {
	buffer := make([]byte, c.snapLen)
	for {
		if c.closed.Load() {
			return nil, nil, net.ErrClosed
		}
		n, err := unix.Read(c.fd, buffer)
		if err != nil {
			if c.closed.Load() {
				return nil, nil, net.ErrClosed
			}
			return nil, nil, fmt.Errorf("fake-tcp AF_PACKET read: %w", err)
		}
		packet, src, ok := c.classify(buffer[:n])
		if !ok {
			continue
		}
		out := append([]byte(nil), packet...)
		return out, src, nil
	}
}

// classify strips L2, learns the source MAC, and applies the filter.
func (c *linuxRawCapture) classify(frame []byte) ([]byte, net.Addr, bool) {
	if len(frame) < captureEthHeaderLen {
		return nil, nil, false
	}
	srcMAC := append(net.HardwareAddr(nil), frame[6:12]...)
	payload, ethType, err := stripEthernet(frame)
	if err != nil || ethType != captureEthTypeIPv4 {
		return nil, nil, false
	}
	if len(payload) < 20 || payload[0]>>4 != 4 {
		return nil, nil, false
	}
	if !c.filter.matchIPv4Packet(payload) {
		return nil, nil, false
	}
	src := net.IP(append([]byte(nil), payload[12:16]...))
	c.mu.Lock()
	c.arp[src.String()] = srcMAC
	c.mu.Unlock()
	return payload, &net.IPAddr{IP: src}, true
}

// WritePacket injects one IPv4 packet towards addr using the learned
// destination MAC.
func (c *linuxRawCapture) WritePacket(data []byte, addr net.Addr) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	if len(data) < 20 || data[0]>>4 != 4 {
		return errors.New("fake-tcp inject requires an IPv4 packet")
	}
	dst := net.IP(data[16:20]).String()
	if ipAddr, ok := addr.(*net.IPAddr); ok && len(ipAddr.IP) != 0 {
		dst = ipAddr.IP.String()
	} else if udpAddr, ok := addr.(*net.UDPAddr); ok && len(udpAddr.IP) != 0 {
		dst = udpAddr.IP.String()
	}
	c.mu.Lock()
	dstMAC, ok := c.arp[dst]
	srcMAC := append(net.HardwareAddr(nil), c.localMAC...)
	c.mu.Unlock()
	if !ok {
		return fmt.Errorf("fake-tcp inject to %s: no learned L2 address: %w", dst, ErrFakeTCPUnsupported)
	}
	frame := make([]byte, captureEthHeaderLen+len(data))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMACOrZero(srcMAC))
	binary.BigEndian.PutUint16(frame[12:14], captureEthTypeIPv4)
	copy(frame[captureEthHeaderLen:], data)
	dest := &unix.SockaddrLinklayer{Ifindex: c.ifindex}
	if err := unix.Sendto(c.fd, frame, 0, dest); err != nil {
		return fmt.Errorf("fake-tcp AF_PACKET inject: %w", err)
	}
	return nil
}

// Close leaves promiscuous membership (bound to the socket) and closes it,
// unblocking any in-flight ReadPacket.
func (c *linuxRawCapture) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.mu.Lock()
	fd := c.fd
	c.fd = -1
	c.mu.Unlock()
	if fd >= 0 {
		return unix.Close(fd)
	}
	return nil
}

// htons converts a 16-bit value to network byte order for AF_PACKET use.
func htons(value uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], value)
	return binary.LittleEndian.Uint16(buf[:])
}

func srcMACOrZero(mac net.HardwareAddr) net.HardwareAddr {
	if len(mac) == 6 {
		return mac
	}
	return net.HardwareAddr{0, 0, 0, 0, 0, 0}
}

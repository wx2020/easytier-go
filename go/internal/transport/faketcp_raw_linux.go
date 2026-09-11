//go:build linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
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
const (
	linuxEthHeaderLen = 14
	linuxEthTypeIPv4  = 0x0800
	linuxEthTypeVLAN  = 0x8100
	linuxProtoTCP     = 6
	linuxProtoUDP     = 17
)

// captureFilter is a compiled userspace equivalent of a BPFProgram filter
// expression. Only the documented subset is supported; anything else is
// rejected at Open so callers get an explicit error instead of silent
// over-capture.
type captureFilter struct {
	proto   int // 0 = any, else IP protocol number
	srcPort int // -1 = any
	dstPort int // -1 = any
	srcHost string
	dstHost string
	anyHost string
}

func compileCaptureFilter(expression string) (captureFilter, error) {
	filter := captureFilter{srcPort: -1, dstPort: -1}
	expression = strings.ToLower(strings.TrimSpace(expression))
	if expression == "" {
		return filter, nil
	}
	tokens := strings.Fields(expression)
	i := 0
	expectPrim := true
	for i < len(tokens) {
		token := tokens[i]
		if token == "and" {
			if expectPrim {
				return filter, fmt.Errorf("fake-tcp filter %q: dangling and", expression)
			}
			expectPrim = true
			i++
			continue
		}
		if token == "or" || token == "(" || token == ")" {
			return filter, fmt.Errorf("fake-tcp filter %q: %q is not supported", expression, token)
		}
		if !expectPrim {
			return filter, fmt.Errorf("fake-tcp filter %q: expected and between primitives", expression)
		}
		switch token {
		case "tcp":
			filter.proto = linuxProtoTCP
			i++
		case "udp":
			filter.proto = linuxProtoUDP
			i++
		case "ip":
			i++
		case "port", "src", "dst", "host":
			consumed, err := parseFilterPrim(tokens, i, expression, &filter)
			if err != nil {
				return filter, err
			}
			i += consumed
		default:
			return filter, fmt.Errorf("fake-tcp filter %q: unknown primitive %q", expression, token)
		}
		expectPrim = false
	}
	if expectPrim && len(tokens) > 0 {
		return filter, fmt.Errorf("fake-tcp filter %q: trailing and", expression)
	}
	return filter, nil
}

func parseFilterPrim(tokens []string, i int, expression string, filter *captureFilter) (int, error) {
	token := tokens[i]
	direction := ""
	if token == "src" || token == "dst" {
		if i+1 >= len(tokens) {
			return 0, fmt.Errorf("fake-tcp filter %q: %q needs a primitive", expression, token)
		}
		direction = token
		token = tokens[i+1]
	}
	offset := 1
	if direction != "" {
		offset = 2
	}
	switch token {
	case "port":
		if i+offset >= len(tokens) {
			return 0, fmt.Errorf("fake-tcp filter %q: port needs a number", expression)
		}
		port, err := strconv.Atoi(tokens[i+offset])
		if err != nil || port < 0 || port > 65535 {
			return 0, fmt.Errorf("fake-tcp filter %q: bad port %q", expression, tokens[i+offset])
		}
		if direction == "src" {
			filter.srcPort = port
		} else if direction == "dst" {
			filter.dstPort = port
		} else {
			filter.srcPort = port
			filter.dstPort = port
		}
		return offset + 1, nil
	case "host":
		if i+offset >= len(tokens) {
			return 0, fmt.Errorf("fake-tcp filter %q: host needs an address", expression)
		}
		host := tokens[i+offset]
		if _, err := netip.ParseAddr(host); err != nil {
			return 0, fmt.Errorf("fake-tcp filter %q: bad host %q", expression, host)
		}
		switch direction {
		case "src":
			filter.srcHost = host
		case "dst":
			filter.dstHost = host
		default:
			filter.anyHost = host
		}
		return offset + 1, nil
	default:
		return 0, fmt.Errorf("fake-tcp filter %q: unknown primitive %q", expression, tokens[i])
	}
}

// matchIPv4Packet reports whether an IPv4 packet matches the filter.
func (f captureFilter) matchIPv4Packet(packet []byte) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return false
	}
	proto := packet[9]
	if f.proto != 0 && int(proto) != f.proto {
		return false
	}
	src := net.IP(packet[12:16]).String()
	dst := net.IP(packet[16:20]).String()
	if f.srcHost != "" && src != f.srcHost {
		return false
	}
	if f.dstHost != "" && dst != f.dstHost {
		return false
	}
	if f.anyHost != "" && src != f.anyHost && dst != f.anyHost {
		return false
	}
	if f.srcPort >= 0 || f.dstPort >= 0 {
		if proto != linuxProtoTCP && proto != linuxProtoUDP {
			return false
		}
		if len(packet) < ihl+4 {
			return false
		}
		sport := int(binary.BigEndian.Uint16(packet[ihl : ihl+2]))
		dport := int(binary.BigEndian.Uint16(packet[ihl+2 : ihl+4]))
		// A bare "port N" sets both; match either side.
		if f.srcPort >= 0 && f.dstPort >= 0 && f.srcPort == f.dstPort {
			if sport != f.srcPort && dport != f.dstPort {
				return false
			}
		} else {
			if f.srcPort >= 0 && sport != f.srcPort {
				return false
			}
			if f.dstPort >= 0 && dport != f.dstPort {
				return false
			}
		}
	}
	return true
}

// stripEthernet removes one Ethernet header (plus a single 802.1Q tag).
func stripEthernet(frame []byte) ([]byte, uint16, error) {
	if len(frame) < linuxEthHeaderLen {
		return nil, 0, errors.New("fake-tcp frame is shorter than an ethernet header")
	}
	ethType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[linuxEthHeaderLen:]
	if ethType == linuxEthTypeVLAN {
		if len(payload) < 4 {
			return nil, 0, errors.New("fake-tcp vlan tag is truncated")
		}
		ethType = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}
	return payload, ethType, nil
}

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
	if len(frame) < linuxEthHeaderLen {
		return nil, nil, false
	}
	srcMAC := append(net.HardwareAddr(nil), frame[6:12]...)
	payload, ethType, err := stripEthernet(frame)
	if err != nil || ethType != linuxEthTypeIPv4 {
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
	frame := make([]byte, linuxEthHeaderLen+len(data))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMACOrZero(srcMAC))
	binary.BigEndian.PutUint16(frame[12:14], linuxEthTypeIPv4)
	copy(frame[linuxEthHeaderLen:], data)
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

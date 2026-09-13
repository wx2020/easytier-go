// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Userspace packet-filter compiler shared by the fake-TCP capture backends.
// The Linux AF_PACKET, macOS BPF, and Windows test paths all match captured
// datagrams against this portable filter instead of shipping kernel BPF
// bytecode; the accepted expression subset matches the backend's filter
// strings (tcp/udp, src/dst host, src/dst port).
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	captureEthHeaderLen = 14
	captureEthTypeIPv4  = 0x0800
	captureEthTypeVLAN  = 0x8100
	captureProtoTCP     = 6
	captureProtoUDP     = 17
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
			filter.proto = captureProtoTCP
			i++
		case "udp":
			filter.proto = captureProtoUDP
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
		if proto != captureProtoTCP && proto != captureProtoUDP {
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
	if len(frame) < captureEthHeaderLen {
		return nil, 0, errors.New("fake-tcp frame is shorter than an ethernet header")
	}
	ethType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[captureEthHeaderLen:]
	if ethType == captureEthTypeVLAN {
		if len(payload) < 4 {
			return nil, 0, errors.New("fake-tcp vlan tag is truncated")
		}
		ethType = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}
	return payload, ethType, nil
}

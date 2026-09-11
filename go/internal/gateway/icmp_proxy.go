// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
	icmpProtoNumber = 1

	natTableCleanupInterval = 1 * time.Second
	natEntryTTL             = 20 * time.Second
	ipReassemblerTimeout    = 10 * time.Second
	icmpPacketBufSize       = 8192
	icmpProxyPayloadMTU     = 1200
)

var (
	ErrICMPProxyClosed    = errors.New("icmp proxy is closed")
	ErrICMPSocketFailed   = errors.New("icmp socket creation failed")
	ErrICMPInvalidPacket  = errors.New("invalid icmp packet")
	ErrICMPNotIPv4        = errors.New("icmp packet is not ipv4")
	ErrICMPUnsupportedType = errors.New("unsupported icmp type")
)

type IcmpNatKey struct {
	RealDstIP [4]byte
	IcmpID    uint16
	IcmpSeq   uint16
}

type IcmpNatEntry struct {
	SrcPeerID  uint32
	MyPeerID   uint32
	SrcIP      [4]byte
	StartTime  time.Time
	MappedDstIP [4]byte
}

func newIcmpNatEntry(srcPeerID, myPeerID uint32, srcIP, mappedDstIP [4]byte) IcmpNatEntry {
	return IcmpNatEntry{
		SrcPeerID:   srcPeerID,
		MyPeerID:    myPeerID,
		SrcIP:       srcIP,
		MappedDstIP: mappedDstIP,
		StartTime:   time.Now(),
	}
}

type IcmpProxyConfig struct {
	MyPeerID    uint32
	IPv4Addr    [4]byte
	CIDRMappings []CIDRMapping
	ExitNode    bool
	NoTUN       bool
	SendPacket  func(ctx context.Context, peerID uint32, packet protocol.Packet) error
}

type IcmpProxy struct {
	config    IcmpProxyConfig
	natTable  map[IcmpNatKey]IcmpNatEntry
	natMu     sync.RWMutex
	reasm     *IPReassembler
	closed    atomic.Bool
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func NewIcmpProxy(config IcmpProxyConfig) (*IcmpProxy, error) {
	if config.SendPacket == nil {
		return nil, errors.New("icmp proxy send packet callback is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &IcmpProxy{
		config:   config,
		natTable: make(map[IcmpNatKey]IcmpNatEntry),
		reasm:    NewIPReassembler(ipReassemblerTimeout),
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

func (p *IcmpProxy) Start() {
	p.wg.Add(2)
	go p.natTableCleaner()
	go p.ipReassemblerCleaner()
}

func (p *IcmpProxy) Stop() {
	if p.closed.Swap(true) {
		return
	}
	p.cancel()
	p.wg.Wait()
}

func (p *IcmpProxy) natTableCleaner() {
	defer p.wg.Done()
	ticker := time.NewTicker(natTableCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.natMu.Lock()
			now := time.Now()
			for key, entry := range p.natTable {
				if now.Sub(entry.StartTime) > natEntryTTL {
					delete(p.natTable, key)
				}
			}
			p.natMu.Unlock()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *IcmpProxy) ipReassemblerCleaner() {
	defer p.wg.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.reasm.RemoveExpiredPackets()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *IcmpProxy) TryProcessPacketFromPeer(packet protocol.Packet) (protocol.Packet, bool) {
	if p.closed.Load() {
		return packet, false
	}

	if packet.Header.PacketType != protocol.PacketTypeData {
		return packet, false
	}
	if packet.Header.Flags&protocol.FlagNoProxy != 0 {
		return packet, false
	}

	if len(packet.Payload) < ipv4HeaderMinLen {
		return packet, false
	}

	payload := packet.Payload

	if payload[0]>>4 != ipv4Version {
		return packet, false
	}

	nextProto := payload[9]
	if nextProto != icmpProtoNumber {
		return packet, false
	}

	if !p.shouldProxy(payload, packet.Header.Flags&protocol.FlagExitNode != 0) {
		return packet, false
	}

	handled := p.handlePeerPacket(packet)
	if handled {
		return protocol.Packet{}, true
	}
	return packet, false
}

func (p *IcmpProxy) shouldProxy(ipv4Payload []byte, isExitNode bool) bool {
	if len(p.config.CIDRMappings) > 0 || isExitNode || p.config.NoTUN {
		return true
	}
	return false
}

func (p *IcmpProxy) handlePeerPacket(packet protocol.Packet) bool {
	payload := packet.Payload
	if len(payload) < ipv4HeaderMinLen {
		return false
	}

	dstIP := IPv4Destination(payload)
	srcIP := IPv4Source(payload)
	if dstIP == nil || srcIP == nil {
		return false
	}

	var icmpData []byte
	if IsPacketFragmented(payload) {
		reassembled := p.reasm.AddFragment(srcIP, dstIP, payload)
		if reassembled == nil {
			return true
		}
		icmpData = reassembled
	} else {
		icmpData = IPv4Payload(payload)
	}

	if len(icmpData) < 8 {
		return false
	}

	icmpType := icmpData[0]
	if icmpType != icmpEchoRequest {
		return false
	}

	icmpID := binary.BigEndian.Uint16(icmpData[4:6])
	icmpSeq := binary.BigEndian.Uint16(icmpData[6:8])

	var realDstIP [4]byte
	copy(realDstIP[:], dstIP.To4())

	for _, mapping := range p.config.CIDRMappings {
		addr, ok := netip.AddrFromSlice(dstIP.To4())
		if ok {
			if translated, found := mapping.Translate(addr); found {
				translatedV4 := translated.As4()
				copy(realDstIP[:], translatedV4[:])
				break
			}
		}
	}

	if p.config.NoTUN {
		var myIP [4]byte
		copy(myIP[:], p.config.IPv4Addr[:])
		var srcIP4 [4]byte
		copy(srcIP4[:], srcIP.To4())

		if realDstIP == myIP {
			p.sendICMPReplyToPeer(
				myIP, srcIP4,
				packet.Header.ToPeerID, packet.Header.FromPeerID,
				icmpData,
			)
			return true
		}
	}

	var srcIP4 [4]byte
	copy(srcIP4[:], srcIP.To4())
	var mappedDstIP [4]byte
	copy(mappedDstIP[:], dstIP.To4())

	key := IcmpNatKey{
		RealDstIP: realDstIP,
		IcmpID:    icmpID,
		IcmpSeq:   icmpSeq,
	}

	entry := newIcmpNatEntry(
		packet.Header.FromPeerID,
		packet.Header.ToPeerID,
		srcIP4,
		mappedDstIP,
	)

	p.natMu.Lock()
	p.natTable[key] = entry
	p.natMu.Unlock()

	p.sendICMPEchoRequest(realDstIP, icmpData)

	return true
}

func (p *IcmpProxy) sendICMPEchoRequest(dstIP [4]byte, icmpData []byte) {
	addr := &net.IPAddr{IP: dstIP[:]}
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return
	}
	defer conn.Close()

	_, err = conn.WriteTo(icmpData, addr)
	if err != nil {
		return
	}
}

func (p *IcmpProxy) HandleICMPReplyFromNetwork(ipv4Packet []byte) bool {
	if len(ipv4Packet) < ipv4HeaderMinLen {
		return false
	}

	srcIP := IPv4Source(ipv4Packet)
	if srcIP == nil {
		return false
	}

	icmpData := IPv4Payload(ipv4Packet)
	if len(icmpData) < 8 {
		return false
	}

	icmpType := icmpData[0]
	if icmpType != icmpEchoReply {
		return false
	}

	icmpID := binary.BigEndian.Uint16(icmpData[4:6])
	icmpSeq := binary.BigEndian.Uint16(icmpData[6:8])

	var srcIP4 [4]byte
	copy(srcIP4[:], srcIP.To4())

	key := IcmpNatKey{
		RealDstIP: srcIP4,
		IcmpID:    icmpID,
		IcmpSeq:   icmpSeq,
	}

	p.natMu.Lock()
	entry, exists := p.natTable[key]
	if exists {
		delete(p.natTable, key)
	}
	p.natMu.Unlock()

	if !exists {
		return false
	}

	payloadLen := len(ipv4Packet) - IPv4HeaderLength(ipv4Packet)
	ipID := IPv4Identification(ipv4Packet)

	var srcIPNet, dstIPNet [4]byte
	srcIPNet = entry.MappedDstIP
	dstIPNet = entry.SrcIP

	err := ComposeIPv4Packet(
		srcIPNet[:], dstIPNet[:],
		icmpProtoNumber,
		icmpData[:payloadLen],
		icmpProxyPayloadMTU,
		ipID,
		func(buf []byte) error {
			pkt := protocol.Packet{
				Header: protocol.PeerManagerHeader{
					FromPeerID: entry.MyPeerID,
					ToPeerID:   entry.SrcPeerID,
					PacketType: protocol.PacketTypeData,
				},
				Payload: buf,
			}
			pkt.Header.Flags |= protocol.FlagNoProxy
			return p.config.SendPacket(p.ctx, entry.SrcPeerID, pkt)
		},
	)

	return err == nil
}

func (p *IcmpProxy) sendICMPReplyToPeer(
	srcIP, dstIP [4]byte,
	srcPeerID, dstPeerID uint32,
	requestData []byte,
) {
	if len(requestData) < 8 {
		return
	}

	replyData := make([]byte, len(requestData))
	copy(replyData, requestData)
	replyData[0] = icmpEchoReply
	replyData[1] = 0

	replyData[2] = 0
	replyData[3] = 0
	checksum := icmpChecksum(replyData)
	binary.BigEndian.PutUint16(replyData[2:4], checksum)

	ipID := uint16(time.Now().UnixNano() & 0xFFFF)

	_ = ComposeIPv4Packet(
		srcIP[:], dstIP[:],
		icmpProtoNumber,
		replyData,
		icmpProxyPayloadMTU,
		ipID,
		func(buf []byte) error {
			pkt := protocol.Packet{
				Header: protocol.PeerManagerHeader{
					FromPeerID: srcPeerID,
					ToPeerID:   dstPeerID,
					PacketType: protocol.PacketTypeData,
				},
				Payload: buf,
			}
			return p.config.SendPacket(p.ctx, dstPeerID, pkt)
		},
	)
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

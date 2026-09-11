// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package nat provides UDP NAT traversal primitives.
package nat

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

const (
	V4HolePunchPayloadSize = net.IPv4len + 2
	V6HolePunchPayloadSize = net.IPv6len + 2

	// MaxPredictedPorts bounds a prediction to the complete valid UDP port
	// space, rather than allowing arithmetic to wrap around.
	MaxPredictedPorts = 1<<16 - 1
)

// EncodeV4HolePunchPayload encodes an IPv4 destination as address bytes
// followed by its little-endian port.
func EncodeV4HolePunchPayload(destination netip.AddrPort) ([]byte, error) {
	if !destination.IsValid() || !destination.Addr().Is4() || destination.Addr().Zone() != "" {
		return nil, fmt.Errorf("hole punch destination is not an IPv4 address")
	}

	payload := make([]byte, V4HolePunchPayloadSize)
	address := destination.Addr().As4()
	copy(payload, address[:])
	binary.LittleEndian.PutUint16(payload[net.IPv4len:], destination.Port())
	return payload, nil
}

// DecodeV4HolePunchPayload decodes an IPv4 hole punch destination.
func DecodeV4HolePunchPayload(payload []byte) (netip.AddrPort, error) {
	if len(payload) != V4HolePunchPayloadSize {
		return netip.AddrPort{}, fmt.Errorf("IPv4 hole punch payload has length %d, want %d", len(payload), V4HolePunchPayloadSize)
	}

	var address [net.IPv4len]byte
	copy(address[:], payload[:net.IPv4len])
	return netip.AddrPortFrom(netip.AddrFrom4(address), binary.LittleEndian.Uint16(payload[net.IPv4len:])), nil
}

// EncodeV6HolePunchPayload encodes an IPv6 destination as address bytes
// followed by its little-endian port.
func EncodeV6HolePunchPayload(destination netip.AddrPort) ([]byte, error) {
	if !destination.IsValid() || !destination.Addr().Is6() || destination.Addr().Zone() != "" {
		return nil, fmt.Errorf("hole punch destination is not an IPv6 address")
	}

	payload := make([]byte, V6HolePunchPayloadSize)
	address := destination.Addr().As16()
	copy(payload, address[:])
	binary.LittleEndian.PutUint16(payload[net.IPv6len:], destination.Port())
	return payload, nil
}

// DecodeV6HolePunchPayload decodes an IPv6 hole punch destination.
func DecodeV6HolePunchPayload(payload []byte) (netip.AddrPort, error) {
	if len(payload) != V6HolePunchPayloadSize {
		return netip.AddrPort{}, fmt.Errorf("IPv6 hole punch payload has length %d, want %d", len(payload), V6HolePunchPayloadSize)
	}

	var address [net.IPv6len]byte
	copy(address[:], payload[:net.IPv6len])
	return netip.AddrPortFrom(netip.AddrFrom16(address), binary.LittleEndian.Uint16(payload[net.IPv6len:])), nil
}

// SendBurst sends packet count times to target, waiting interval between
// sends. The first packet is sent immediately.
func SendBurst(ctx context.Context, conn *net.UDPConn, target *net.UDPAddr, packet []byte, count int, interval time.Duration) error {
	if ctx == nil {
		return fmt.Errorf("UDP burst context is nil")
	}
	if conn == nil {
		return fmt.Errorf("UDP burst connection is nil")
	}
	if target == nil {
		return fmt.Errorf("UDP burst target is nil")
	}
	if count < 0 {
		return fmt.Errorf("UDP burst count is negative: %d", count)
	}
	if interval < 0 {
		return fmt.Errorf("UDP burst interval is negative: %s", interval)
	}

	for sent := 0; sent < count; sent++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := conn.WriteToUDP(packet, target); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("send UDP burst packet: %w", err)
		}
		if sent+1 == count || interval == 0 {
			continue
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

// SendHolePunchBurst sends EasyTier UDP hole-punch datagrams to target.
func SendHolePunchBurst(ctx context.Context, conn *net.UDPConn, target *net.UDPAddr, count int, interval time.Duration) error {
	packet, err := (protocol.UDPDatagram{
		Header:  protocol.UDPTunnelHeader{MessageType: protocol.UDPPacketTypeHolePunch},
		Payload: make([]byte, 32),
	}).Marshal()
	if err != nil {
		return fmt.Errorf("marshal UDP hole punch packet: %w", err)
	}
	return SendBurst(ctx, conn, target, packet, count, interval)
}

// PredictPorts returns ports immediately after or before base, bounded to the
// valid UDP port range. base itself is not included.
func PredictPorts(base, span uint16, increasing bool) []uint16 {
	if base == 0 || span == 0 {
		return nil
	}

	var first, last uint32
	if increasing {
		first = uint32(base) + 1
		last = uint32(base) + uint32(span)
		if first > MaxPredictedPorts {
			return nil
		}
		if last > MaxPredictedPorts {
			last = MaxPredictedPorts
		}
	} else {
		if base <= 1 {
			return nil
		}
		first = 1
		if uint32(span) < uint32(base)-1 {
			first = uint32(base) - uint32(span)
		}
		last = uint32(base) - 1
	}

	ports := make([]uint16, 0, last-first+1)
	for port := first; port <= last; port++ {
		ports = append(ports, uint16(port))
	}
	return ports
}

// Listener receives V4/V6 hole-punch control datagrams. A control datagram
// is accepted only from the matching loopback family and when its payload is
// exactly the configured target address.
type Listener struct {
	conn   *net.UDPConn
	target netip.AddrPort
}

// NewListener creates a control listener over conn for target.
func NewListener(conn *net.UDPConn, target netip.AddrPort) (*Listener, error) {
	if conn == nil {
		return nil, fmt.Errorf("UDP hole punch listener connection is nil")
	}
	if !target.IsValid() || target.Addr().Zone() != "" {
		return nil, fmt.Errorf("UDP hole punch listener target is invalid")
	}
	return &Listener{conn: conn, target: target}, nil
}

// Accept waits for and validates one loopback control datagram. Invalid or
// unrelated datagrams are ignored.
func (l *Listener) Accept(ctx context.Context) (netip.AddrPort, error) {
	if l == nil || l.conn == nil {
		return netip.AddrPort{}, fmt.Errorf("UDP hole punch listener is nil")
	}
	if ctx == nil {
		return netip.AddrPort{}, fmt.Errorf("UDP hole punch listener context is nil")
	}
	if err := ctx.Err(); err != nil {
		return netip.AddrPort{}, err
	}

	stopDeadline := context.AfterFunc(ctx, func() {
		_ = l.conn.SetReadDeadline(time.Now())
	})
	defer func() {
		stopDeadline()
		_ = l.conn.SetReadDeadline(time.Time{})
	}()

	buffer := make([]byte, protocol.UDPTunnelHeaderSize+protocol.UDPMaxPayloadSize+1)
	for {
		n, source, err := l.conn.ReadFromUDP(buffer)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return netip.AddrPort{}, ctxErr
			}
			return netip.AddrPort{}, fmt.Errorf("read UDP hole punch control: %w", err)
		}
		if !source.IP.IsLoopback() {
			continue
		}

		datagram, err := protocol.ParseUDPDatagram(buffer[:n])
		if err != nil {
			continue
		}
		switch datagram.Header.MessageType {
		case protocol.UDPPacketTypeV4HolePunch:
			if source.IP.To4() == nil || !l.target.Addr().Is4() {
				continue
			}
			decoded, err := DecodeV4HolePunchPayload(datagram.Payload)
			if err == nil && decoded == l.target {
				return decoded, nil
			}
		case protocol.UDPPacketTypeV6HolePunch:
			if source.IP.To4() != nil || !l.target.Addr().Is6() {
				continue
			}
			decoded, err := DecodeV6HolePunchPayload(datagram.Payload)
			if err == nil && decoded == l.target {
				return decoded, nil
			}
		}
	}
}

// Serve handles loopback controls and sends one hole-punch response for each
// accepted target until ctx is canceled.
func (l *Listener) Serve(ctx context.Context) error {
	if l == nil {
		return fmt.Errorf("UDP hole punch listener is nil")
	}
	for {
		target, err := l.Accept(ctx)
		if err != nil {
			return err
		}
		if err := SendHolePunchBurst(ctx, l.conn, udpAddr(target), 1, 0); err != nil {
			return err
		}
	}
}

// Listen handles loopback controls and sends one hole-punch response for each
// accepted target until ctx is canceled.
func Listen(ctx context.Context, conn *net.UDPConn, target netip.AddrPort) error {
	listener, err := NewListener(conn, target)
	if err != nil {
		return err
	}
	return listener.Serve(ctx)
}

func udpAddr(address netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IP(address.Addr().AsSlice()), Port: int(address.Port())}
}

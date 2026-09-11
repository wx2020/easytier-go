// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package tun provides platform-independent virtual network devices.
package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
)

var (
	ErrClosed           = errors.New("virtual NIC is closed")
	ErrInvalidQueueSize = errors.New("invalid virtual NIC queue size")
	ErrInvalidMTU       = errors.New("invalid virtual NIC MTU")
	ErrInvalidPacket    = errors.New("invalid IP packet")
	ErrPacketTooLarge   = errors.New("IP packet exceeds MTU")
	ErrNilDevice        = errors.New("virtual NIC device is nil")
	ErrNilIngress       = errors.New("virtual NIC ingress handler is nil")
	ErrNilEgress        = errors.New("virtual NIC egress source is nil")
	ErrNoAvailableIP    = errors.New("no available DHCP address")
	ErrInvalidCIDR      = errors.New("invalid CIDR")
	ErrNoTUN            = errors.New("TUN is disabled (no-tun mode)")
)

// Device exchanges complete IP packets with a virtual network interface.
// Implementations must unblock pending operations when ctx is canceled or the
// device is closed.
type Device interface {
	ReadPacket(ctx context.Context) ([]byte, error)
	WritePacket(ctx context.Context, packet []byte) error
	Close() error
}

// DHCP and assignment constants. The Go pool mirrors the Rust DHCP subnet
// (10.144.144.0/24 per GWY-01 requirement, with fallback to 10.126.126.0/24 for
// Rust compatibility). The first and last addresses are reserved.
const (
	DHCPPoolCIDR         = "10.144.144.0/24"
	DHCPPoolFallbackCIDR = "10.126.126.0/24"
	DefaultMTU           = 1380
	MaxMTU               = 65535
	MinMTU               = 1280
	EncryptionOverhead   = 20
)

var (
	DHCPPool         = netip.MustParsePrefix(DHCPPoolCIDR)
	DHCPPoolFallback = netip.MustParsePrefix(DHCPPoolFallbackCIDR)
)

// TunConfig describes desired TUN addressing and TUN options.
type TunConfig struct {
	IPv4             string
	IPv6             string
	DHCP             bool
	NoTUN            bool
	MTU              uint32
	EnableEncryption bool
}

// AssignedAddresses holds the concrete addresses applied to a TUN device.
type AssignedAddresses struct {
	IPv4  *netip.Prefix
	IPv6  *netip.Prefix
	MTU   int
	NoTUN bool
	DHCP  bool
}

// EffectiveMTU returns the MTU to program on the TUN device. When encryption
// is enabled, 20 bytes are reserved for the wire overhead, matching
// easytier/src/instance/virtual_nic.rs (mtu_in_config - 20).
func EffectiveMTU(mtu uint32, encryption bool) int {
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if int(mtu) > MaxMTU {
		mtu = MaxMTU
	}
	if int(mtu) < MinMTU {
		mtu = MinMTU
	}
	effective := int(mtu)
	if encryption {
		effective -= EncryptionOverhead
		if effective < MinMTU {
			effective = MinMTU
		}
	}
	return effective
}

// ShouldCreateTUN reports whether a TUN device should be created. When NoTUN is
// true the device is skipped but management remains available.
func ShouldCreateTUN(cfg TunConfig) bool {
	return !cfg.NoTUN
}

// ParseIPv4Prefix parses an IPv4 address or CIDR, applying /24 when no prefix
// is supplied, matching config.Config.IPv4Prefix and Rust's default.
func ParseIPv4Prefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("%w: empty IPv4", ErrInvalidCIDR)
	}
	if !strings.Contains(s, "/") {
		s += "/24"
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil || !pfx.Addr().Is4() || !pfx.IsValid() {
		return netip.Prefix{}, fmt.Errorf("%w: %q", ErrInvalidCIDR, s)
	}
	return pfx, nil
}

// ParseIPv6Prefix parses an IPv6 CIDR. IPv6 always requires an explicit prefix.
func ParseIPv6Prefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("%w: empty IPv6", ErrInvalidCIDR)
	}
	if !strings.Contains(s, "/") {
		return netip.Prefix{}, fmt.Errorf("%w: IPv6 CIDR %q missing prefix length", ErrInvalidCIDR, s)
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil || !pfx.Addr().Is6() || !pfx.IsValid() {
		return netip.Prefix{}, fmt.Errorf("%w: %q", ErrInvalidCIDR, s)
	}
	return pfx, nil
}

// ParsePrefixes parses optional static IPv4/IPv6 strings into prefixes.
func ParsePrefixes(ipv4, ipv6 string) (*netip.Prefix, *netip.Prefix, error) {
	var v4 *netip.Prefix
	var v6 *netip.Prefix
	if strings.TrimSpace(ipv4) != "" {
		pfx, err := ParseIPv4Prefix(ipv4)
		if err != nil {
			return nil, nil, err
		}
		v4 = &pfx
	}
	if strings.TrimSpace(ipv6) != "" {
		pfx, err := ParseIPv6Prefix(ipv6)
		if err != nil {
			return nil, nil, err
		}
		v6 = &pfx
	}
	return v4, v6, nil
}

// AllocateDHCP picks an available IPv4 address from pool avoiding used.
// It skips the network and broadcast addresses, matching Rust's
// dhcp_inet.network().iter().find(|ip| ip != first && ip != last && !used).
// Pool defaults to DHCPPool (10.144.144.0/24) when zero.
func AllocateDHCP(pool netip.Prefix, used []netip.Addr) (netip.Prefix, error) {
	if !pool.IsValid() {
		pool = DHCPPool
	}
	if !pool.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%w: DHCP pool must be IPv4 %q", ErrInvalidCIDR, pool)
	}
	usedSet := make(map[netip.Addr]bool, len(used))
	for _, u := range used {
		if !u.IsValid() {
			continue
		}
		// Normalize to unmapped v4
		if u.Is4() {
			usedSet[u] = true
		}
	}
	network := pool.Masked()
	first := network.Addr()
	last := prefixLast(pool)
	// Iterate host addresses .1 .. .254 for /24, generically using pool iteration
	// We walk all addresses in the prefix's range via address increment, skipping first/last.
	for addr := nextAddr(first); addr.IsValid() && addr != last; addr = nextAddr(addr) {
		if !pool.Contains(addr) {
			break
		}
		if usedSet[addr] {
			continue
		}
		return netip.PrefixFrom(addr, pool.Bits()), nil
	}
	return netip.Prefix{}, ErrNoAvailableIP
}

// AllocateDHCPWithCurrent implements Rust's keep-current-if-still-valid logic.
// If current is set and belongs to the same network as the chosen DHCP subnet
// and not conflicting, it is reused.
func AllocateDHCPWithCurrent(pool netip.Prefix, used []netip.Addr, current *netip.Prefix) (netip.Prefix, error) {
	if !pool.IsValid() {
		pool = DHCPPool
	}
	// Determine dhcp_inet subnet: first used's network or default pool
	dhcpNetwork := pool
	if len(used) > 0 {
		for _, u := range used {
			if u.Is4() && u.IsValid() {
				dhcpNetwork = netip.PrefixFrom(u, pool.Bits()).Masked()
				// Prefer the network of the first valid used addr; normalize to pool's bits length if possible
				// For /24 pool, this yields same subnet. If used are already in same pool, keep it.
				if dhcpNetwork.Bits() != pool.Bits() {
					dhcpNetwork = netip.PrefixFrom(dhcpNetwork.Addr(), pool.Bits()).Masked()
				}
				break
			}
		}
	}
	// If current is valid, in same network and not used, reuse it.
	if current != nil && current.IsValid() && current.Addr().Is4() {
		curAddr := current.Addr()
		if dhcpNetwork.Contains(curAddr) && !containsAddr(used, curAddr) {
			// Ensure not network/broadcast
			if curAddr != dhcpNetwork.Addr() && curAddr != prefixLast(dhcpNetwork) {
				return *current, nil
			}
		}
	}
	// Otherwise find available in dhcpNetwork
	usedSet := make(map[netip.Addr]bool, len(used))
	for _, u := range used {
		if u.Is4() {
			usedSet[u] = true
		}
	}
	first := dhcpNetwork.Addr()
	last := prefixLast(dhcpNetwork)
	for addr := nextAddr(first); addr.IsValid() && addr != last; addr = nextAddr(addr) {
		if !dhcpNetwork.Contains(addr) {
			break
		}
		if usedSet[addr] {
			continue
		}
		return netip.PrefixFrom(addr, dhcpNetwork.Bits()), nil
	}
	return netip.Prefix{}, ErrNoAvailableIP
}

func containsAddr(addrs []netip.Addr, target netip.Addr) bool {
	for _, a := range addrs {
		if a == target {
			return true
		}
	}
	return false
}

func nextAddr(addr netip.Addr) netip.Addr {
	if !addr.Is4() {
		return netip.Addr{}
	}
	b := addr.As4()
	// increment as uint32 big-endian
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v++
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func prefixLast(p netip.Prefix) netip.Addr {
	if !p.IsValid() {
		return netip.Addr{}
	}
	// For IPv4, last address is network | host mask
	addr := p.Addr()
	if !addr.Is4() {
		return netip.Addr{}
	}
	b := addr.As4()
	bits := p.Bits()
	hostBits := 32 - bits
	if hostBits <= 0 {
		return addr
	}
	// Calculate last by setting host bits to 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	mask := ^uint32(0) >> bits
	v |= mask
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// ResolveAssigned resolves TunConfig into concrete addresses and MTU, handling
// DHCP, static assignments, and no-TUN. When NoTUN is true, TUN creation is
// skipped but management remains available. When DHCP is true, an IP is chosen
// from pool avoiding used.
func ResolveAssigned(cfg TunConfig, used []netip.Addr) (AssignedAddresses, error) {
	if cfg.NoTUN {
		return AssignedAddresses{NoTUN: true, DHCP: cfg.DHCP}, nil
	}
	mtu := EffectiveMTU(cfg.MTU, cfg.EnableEncryption)
	assigned := AssignedAddresses{MTU: mtu, NoTUN: false, DHCP: cfg.DHCP}
	if cfg.DHCP {
		pool := DHCPPool
		pfx, err := AllocateDHCPWithCurrent(pool, used, nil)
		if err != nil {
			return AssignedAddresses{}, err
		}
		assigned.IPv4 = &pfx
	}
	if strings.TrimSpace(cfg.IPv4) != "" {
		// Static IPv4 overrides DHCP when both are set? Rust's check_for_static_ip runs separately
		// but we prioritize static when DHCP is false. When DHCP true, static is ignored for IPv4.
		if !cfg.DHCP {
			pfx, err := ParseIPv4Prefix(cfg.IPv4)
			if err != nil {
				return AssignedAddresses{}, err
			}
			assigned.IPv4 = &pfx
		}
	}
	if strings.TrimSpace(cfg.IPv6) != "" {
		pfx, err := ParseIPv6Prefix(cfg.IPv6)
		if err != nil {
			return AssignedAddresses{}, err
		}
		assigned.IPv6 = &pfx
	}
	if assigned.IPv4 == nil && assigned.IPv6 == nil && !cfg.DHCP {
		// No address assigned but TUN requested; still valid (TUN exists but no IP yet)
		// Caller may create TUN without addresses.
	}
	return assigned, nil
}

// MemoryDevice is one end of an in-memory virtual NIC pair.
type MemoryDevice struct {
	link     *memoryLink
	incoming *packetQueue
	outgoing *packetQueue

	mu           sync.RWMutex
	assignedIPv4 *netip.Prefix
	assignedIPv6 *netip.Prefix
	mtu          int
	noTun        bool
}

type memoryLink struct {
	done      chan struct{}
	closeOnce sync.Once
}

type packetQueue struct {
	mu       sync.Mutex
	packets  [][]byte
	capacity int
	changed  chan struct{}
}

// NewMemoryDevicePair creates two connected devices. Packets written to one
// device can be read from the other. queueSize limits each direction.
func NewMemoryDevicePair(queueSize int) (*MemoryDevice, *MemoryDevice, error) {
	if queueSize <= 0 {
		return nil, nil, fmt.Errorf("%w: %d", ErrInvalidQueueSize, queueSize)
	}

	link := &memoryLink{done: make(chan struct{})}
	firstIncoming := newPacketQueue(queueSize)
	secondIncoming := newPacketQueue(queueSize)
	return &MemoryDevice{link: link, incoming: firstIncoming, outgoing: secondIncoming, mtu: DefaultMTU},
		&MemoryDevice{link: link, incoming: secondIncoming, outgoing: firstIncoming, mtu: DefaultMTU}, nil
}

func newPacketQueue(capacity int) *packetQueue {
	return &packetQueue{capacity: capacity, changed: make(chan struct{})}
}

// NewMemoryDevicePairWithMTU creates a pair with an explicit MTU for both ends.
func NewMemoryDevicePairWithMTU(queueSize, mtu int) (*MemoryDevice, *MemoryDevice, error) {
	if mtu <= 0 {
		return nil, nil, fmt.Errorf("%w: %d", ErrInvalidMTU, mtu)
	}
	a, b, err := NewMemoryDevicePair(queueSize)
	if err != nil {
		return nil, nil, err
	}
	a.mu.Lock()
	a.mtu = mtu
	a.mu.Unlock()
	b.mu.Lock()
	b.mtu = mtu
	b.mu.Unlock()
	return a, b, nil
}

// AssignIPv4 assigns a static or DHCP-derived IPv4 prefix to the device.
func (d *MemoryDevice) AssignIPv4(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is4() {
		return fmt.Errorf("%w: %q", ErrInvalidCIDR, p)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.assignedIPv4 = &p
	return nil
}

// AssignedIPv4 returns the currently assigned IPv4 prefix if any.
func (d *MemoryDevice) AssignedIPv4() (netip.Prefix, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.assignedIPv4 == nil {
		return netip.Prefix{}, false
	}
	return *d.assignedIPv4, true
}

// AssignIPv6 assigns an IPv6 prefix to the device.
func (d *MemoryDevice) AssignIPv6(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is6() {
		return fmt.Errorf("%w: %q", ErrInvalidCIDR, p)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.assignedIPv6 = &p
	return nil
}

// AssignedIPv6 returns the currently assigned IPv6 prefix if any.
func (d *MemoryDevice) AssignedIPv6() (netip.Prefix, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.assignedIPv6 == nil {
		return netip.Prefix{}, false
	}
	return *d.assignedIPv6, true
}

// SetMTU updates the device MTU, enforcing bounds.
func (d *MemoryDevice) SetMTU(mtu int) error {
	if mtu <= 0 || mtu > MaxMTU {
		return fmt.Errorf("%w: %d", ErrInvalidMTU, mtu)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mtu = mtu
	return nil
}

// MTU returns the device's current MTU.
func (d *MemoryDevice) MTU() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.mtu == 0 {
		return DefaultMTU
	}
	return d.mtu
}

// SetNoTUN marks the device as no-TUN mode (no packet I/O expected).
func (d *MemoryDevice) SetNoTUN(noTun bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.noTun = noTun
}

// IsNoTUN reports whether no-TUN mode is active.
func (d *MemoryDevice) IsNoTUN() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.noTun
}

// ReadPacket waits for the next packet sent by the paired device.
func (d *MemoryDevice) ReadPacket(ctx context.Context) ([]byte, error) {
	if err := d.valid(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return d.incoming.read(ctx, d.link.done)
}

// WritePacket queues packet for the paired device. It waits for queue space
// when the bounded queue is full.
func (d *MemoryDevice) WritePacket(ctx context.Context, packet []byte) error {
	if err := d.valid(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	copyPacket := append([]byte(nil), packet...)
	return d.outgoing.write(ctx, d.link.done, copyPacket)
}

// Close closes both ends of the in-memory link. It is idempotent.
func (d *MemoryDevice) Close() error {
	if err := d.valid(); err != nil {
		return err
	}
	d.link.closeOnce.Do(func() { close(d.link.done) })
	return nil
}

func (d *MemoryDevice) valid() error {
	if d == nil || d.link == nil || d.incoming == nil || d.outgoing == nil {
		return ErrClosed
	}
	return nil
}

func (q *packetQueue) read(ctx context.Context, done <-chan struct{}) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
			return nil, ErrClosed
		default:
		}

		q.mu.Lock()
		if len(q.packets) != 0 {
			packet := q.packets[0]
			q.packets[0] = nil
			q.packets = q.packets[1:]
			q.signalLocked()
			q.mu.Unlock()
			return packet, nil
		}
		changed := q.changed
		q.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
			return nil, ErrClosed
		case <-changed:
		}
	}
}

func (q *packetQueue) write(ctx context.Context, done <-chan struct{}, packet []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return ErrClosed
		default:
		}

		q.mu.Lock()
		if len(q.packets) < q.capacity {
			q.packets = append(q.packets, packet)
			q.signalLocked()
			q.mu.Unlock()
			return nil
		}
		changed := q.changed
		q.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return ErrClosed
		case <-changed:
		}
	}
}

func (q *packetQueue) signalLocked() {
	close(q.changed)
	q.changed = make(chan struct{})
}

// PacketHandler receives a validated packet read from a Device.
type PacketHandler func(context.Context, []byte) error

// PacketSource returns a packet to write to a Device. Returning io.EOF stops a
// Runner successfully.
type PacketSource func(context.Context) ([]byte, error)

// Runner connects a Device to ingress and egress packet callbacks.
type Runner struct {
	device  Device
	mtu     int
	ingress PacketHandler
	egress  PacketSource
}

// NewRunner creates a Runner that enforces mtu on packets in both directions.
func NewRunner(device Device, mtu int, ingress PacketHandler, egress PacketSource) (*Runner, error) {
	if device == nil {
		return nil, ErrNilDevice
	}
	if mtu <= 0 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidMTU, mtu)
	}
	if ingress == nil {
		return nil, ErrNilIngress
	}
	if egress == nil {
		return nil, ErrNilEgress
	}
	return &Runner{device: device, mtu: mtu, ingress: ingress, egress: egress}, nil
}

// Run handles device ingress and egress until the context is canceled, a
// callback ends with io.EOF, or either direction returns an error.
func (r *Runner) Run(ctx context.Context) error {
	if r == nil || r.device == nil {
		return ErrNilDevice
	}
	if r.mtu <= 0 {
		return fmt.Errorf("%w: %d", ErrInvalidMTU, r.mtu)
	}
	if r.ingress == nil {
		return ErrNilIngress
	}
	if r.egress == nil {
		return ErrNilEgress
	}
	if ctx == nil {
		ctx = context.Background()
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- r.runIngress(runCtx) }()
	go func() { results <- r.runEgress(runCtx) }()

	first := <-results
	cancel()
	<-results
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(first, io.EOF) {
		return nil
	}
	return first
}

func (r *Runner) runIngress(ctx context.Context) error {
	for {
		packet, err := r.device.ReadPacket(ctx)
		if err != nil {
			return err
		}
		if err := ValidatePacket(packet, r.mtu); err != nil {
			return err
		}
		if err := r.ingress(ctx, packet); err != nil {
			return err
		}
	}
}

func (r *Runner) runEgress(ctx context.Context) error {
	for {
		packet, err := r.egress(ctx)
		if err != nil {
			return err
		}
		if err := ValidatePacket(packet, r.mtu); err != nil {
			return err
		}
		if err := r.device.WritePacket(ctx, packet); err != nil {
			return err
		}
	}
}

// ValidatePacket verifies that packet is IPv4 or IPv6 and fits mtu. Packet
// version validation deliberately examines only the first header nibble.
func ValidatePacket(packet []byte, mtu int) error {
	if mtu <= 0 {
		return fmt.Errorf("%w: %d", ErrInvalidMTU, mtu)
	}
	if len(packet) > mtu {
		return fmt.Errorf("%w: packet size %d, MTU %d", ErrPacketTooLarge, len(packet), mtu)
	}
	if len(packet) == 0 || packet[0]>>4 != 4 && packet[0]>>4 != 6 {
		return fmt.Errorf("%w: IP version %d", ErrInvalidPacket, packetVersion(packet))
	}
	return nil
}

func packetVersion(packet []byte) byte {
	if len(packet) == 0 {
		return 0
	}
	return packet[0] >> 4
}

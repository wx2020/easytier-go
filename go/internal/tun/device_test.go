// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestMemoryDevicePairTransfersCopiedPackets(t *testing.T) {
	first, second := newMemoryPair(t, 1)
	packet := []byte{0x45, 1}
	if err := first.WritePacket(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	packet[1] = 2

	got, err := second.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string([]byte{0x45, 1}) {
		t.Fatalf("ReadPacket() = %v, want [69 1]", got)
	}
}

func TestMemoryDevicePairBoundsAndCancellation(t *testing.T) {
	first, second := newMemoryPair(t, 1)
	if err := first.WritePacket(context.Background(), []byte{0x45, 1}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	writeResult := make(chan error, 1)
	go func() { writeResult <- first.WritePacket(ctx, []byte{0x45, 2}) }()
	assertPending(t, writeResult)
	cancel()
	if err := <-writeResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked WritePacket() error = %v, want context canceled", err)
	}

	packet, err := second.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(packet) != string([]byte{0x45, 1}) {
		t.Fatalf("queued packet = %v, want [69 1]", packet)
	}

	readCtx, readCancel := context.WithCancel(context.Background())
	readResult := make(chan error, 1)
	go func() {
		_, err := second.ReadPacket(readCtx)
		readResult <- err
	}()
	assertPending(t, readResult)
	readCancel()
	if err := <-readResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked ReadPacket() error = %v, want context canceled", err)
	}
}

func TestMemoryDevicePairCloseUnblocksBothEnds(t *testing.T) {
	first, second := newMemoryPair(t, 1)
	if err := first.WritePacket(context.Background(), []byte{0x45}); err != nil {
		t.Fatal(err)
	}
	writeResult := make(chan error, 1)
	readResult := make(chan error, 1)
	go func() { writeResult <- first.WritePacket(context.Background(), []byte{0x46}) }()
	go func() {
		_, err := first.ReadPacket(context.Background())
		readResult <- err
	}()
	assertPending(t, writeResult)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
	if err := <-writeResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("blocked WritePacket() error = %v, want closed", err)
	}
	if err := <-readResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("blocked ReadPacket() error = %v, want closed", err)
	}
	if err := second.WritePacket(context.Background(), []byte{0x45}); !errors.Is(err, ErrClosed) {
		t.Fatalf("WritePacket after Close() error = %v, want closed", err)
	}
}

func TestNewMemoryDevicePairRejectsInvalidQueueSize(t *testing.T) {
	for _, size := range []int{0, -1} {
		if _, _, err := NewMemoryDevicePair(size); !errors.Is(err, ErrInvalidQueueSize) {
			t.Errorf("NewMemoryDevicePair(%d) error = %v, want invalid queue size", size, err)
		}
	}
}

func TestValidatePacket(t *testing.T) {
	for _, test := range []struct {
		name   string
		packet []byte
		mtu    int
		want   error
	}{
		{name: "IPv4", packet: []byte{0x4f}, mtu: 1},
		{name: "IPv6", packet: []byte{0x60}, mtu: 1},
		{name: "empty", mtu: 1, want: ErrInvalidPacket},
		{name: "unsupported version", packet: []byte{0x50}, mtu: 1, want: ErrInvalidPacket},
		{name: "over MTU", packet: []byte{0x45, 1}, mtu: 1, want: ErrPacketTooLarge},
		{name: "invalid MTU", packet: []byte{0x45}, mtu: 0, want: ErrInvalidMTU},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePacket(test.packet, test.mtu)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidatePacket(%v, %d) error = %v, want %v", test.packet, test.mtu, err, test.want)
			}
		})
	}
}

func TestRunnerConnectsIngressAndEgress(t *testing.T) {
	device, peer := newMemoryPair(t, 2)
	ingressPacket := []byte{0x45, 1}
	egressPacket := []byte{0x60, 2}
	if err := peer.WritePacket(context.Background(), ingressPacket); err != nil {
		t.Fatal(err)
	}

	ingressReceived := make(chan []byte, 1)
	releaseEgress := make(chan struct{})
	var sourceCalls int
	runner, err := NewRunner(device, 2, func(_ context.Context, packet []byte) error {
		ingressReceived <- append([]byte(nil), packet...)
		return nil
	}, func(ctx context.Context) ([]byte, error) {
		sourceCalls++
		if sourceCalls == 1 {
			select {
			case <-releaseEgress:
				return egressPacket, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return nil, io.EOF
	})
	if err != nil {
		t.Fatal(err)
	}

	runResult := make(chan error, 1)
	go func() { runResult <- runner.Run(context.Background()) }()
	if got := <-ingressReceived; string(got) != string(ingressPacket) {
		t.Fatalf("ingress callback packet = %v, want %v", got, ingressPacket)
	}
	close(releaseEgress)
	got, err := peer.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(egressPacket) {
		t.Fatalf("egress packet = %v, want %v", got, egressPacket)
	}
	if err := <-runResult; err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
}

func TestRunnerStopsBothDirectionsOnError(t *testing.T) {
	device, peer := newMemoryPair(t, 1)
	want := errors.New("ingress failed")
	ingressStarted := make(chan struct{})
	egressStopped := make(chan struct{})
	runner, err := NewRunner(device, 1, func(context.Context, []byte) error {
		close(ingressStarted)
		return want
	}, func(ctx context.Context) ([]byte, error) {
		<-ctx.Done()
		close(egressStopped)
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.WritePacket(context.Background(), []byte{0x45}); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Run() error = %v, want %v", err, want)
	}
	select {
	case <-ingressStarted:
	case <-time.After(time.Second):
		t.Fatal("ingress callback did not run")
	}
	select {
	case <-egressStopped:
	case <-time.After(time.Second):
		t.Fatal("egress callback did not stop")
	}
}

func TestRunnerValidatesBothDirectionsAndContext(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, device, peer *MemoryDevice) *Runner
		want  error
	}{
		{
			name: "invalid ingress version",
			setup: func(t *testing.T, device, peer *MemoryDevice) *Runner {
				t.Helper()
				if err := peer.WritePacket(context.Background(), []byte{0x50}); err != nil {
					t.Fatal(err)
				}
				runner, err := NewRunner(device, 1, func(context.Context, []byte) error { return nil }, waitForCancelSource)
				if err != nil {
					t.Fatal(err)
				}
				return runner
			},
			want: ErrInvalidPacket,
		},
		{
			name: "over MTU egress",
			setup: func(t *testing.T, device, peer *MemoryDevice) *Runner {
				t.Helper()
				var once sync.Once
				runner, err := NewRunner(device, 1, func(context.Context, []byte) error { return nil }, func(context.Context) ([]byte, error) {
					var packet []byte
					once.Do(func() { packet = []byte{0x45, 1} })
					if packet != nil {
						return packet, nil
					}
					return nil, io.EOF
				})
				if err != nil {
					t.Fatal(err)
				}
				return runner
			},
			want: ErrPacketTooLarge,
		},
		{
			name: "over MTU ingress",
			setup: func(t *testing.T, device, peer *MemoryDevice) *Runner {
				t.Helper()
				if err := peer.WritePacket(context.Background(), []byte{0x45, 1}); err != nil {
					t.Fatal(err)
				}
				runner, err := NewRunner(device, 1, func(context.Context, []byte) error { return nil }, waitForCancelSource)
				if err != nil {
					t.Fatal(err)
				}
				return runner
			},
			want: ErrPacketTooLarge,
		},
		{
			name: "invalid egress version",
			setup: func(t *testing.T, device, peer *MemoryDevice) *Runner {
				t.Helper()
				runner, err := NewRunner(device, 1, func(context.Context, []byte) error { return nil }, func(context.Context) ([]byte, error) {
					return []byte{0x50}, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				return runner
			},
			want: ErrInvalidPacket,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			device, peer := newMemoryPair(t, 1)
			runner := test.setup(t, device, peer)
			if err := runner.Run(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("Run() error = %v, want %v", err, test.want)
			}
		})
	}

	device, _ := newMemoryPair(t, 1)
	runner, err := NewRunner(device, 1, func(context.Context, []byte) error { return nil }, waitForCancelSource)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runner.Run(ctx) }()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run after cancellation = %v, want context canceled", err)
	}
}

func TestRunnerStopsWhenDeviceCloses(t *testing.T) {
	device, _ := newMemoryPair(t, 1)
	runner, err := NewRunner(device, 1, func(context.Context, []byte) error { return nil }, waitForCancelSource)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- runner.Run(context.Background()) }()
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrClosed) {
		t.Fatalf("Run after device close = %v, want closed", err)
	}
}

func TestNewRunnerRejectsInvalidConfiguration(t *testing.T) {
	device, _ := newMemoryPair(t, 1)
	if _, err := NewRunner(nil, 1, func(context.Context, []byte) error { return nil }, waitForCancelSource); !errors.Is(err, ErrNilDevice) {
		t.Fatalf("nil device error = %v", err)
	}
	if _, err := NewRunner(device, 0, func(context.Context, []byte) error { return nil }, waitForCancelSource); !errors.Is(err, ErrInvalidMTU) {
		t.Fatalf("invalid MTU error = %v", err)
	}
	if _, err := NewRunner(device, 1, nil, waitForCancelSource); !errors.Is(err, ErrNilIngress) {
		t.Fatalf("nil ingress error = %v", err)
	}
	if _, err := NewRunner(device, 1, func(context.Context, []byte) error { return nil }, nil); !errors.Is(err, ErrNilEgress) {
		t.Fatalf("nil egress error = %v", err)
	}
}

func newMemoryPair(t *testing.T, queueSize int) (*MemoryDevice, *MemoryDevice) {
	t.Helper()
	first, second, err := NewMemoryDevicePair(queueSize)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	return first, second
}

func waitForCancelSource(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDHCPAllocationAvoidsConflictsAndReservesNetworkBroadcast(t *testing.T) {
	usedStr := []string{"10.144.144.1", "10.144.144.2", "10.144.144.255"}
	addrs := parseAddrs(t, usedStr)
	pfx, err := AllocateDHCP(DHCPPool, addrs)
	if err != nil {
		t.Fatal(err)
	}
	if pfx.String() != "10.144.144.3/24" {
		t.Fatalf("AllocateDHCP = %v, want 10.144.144.3/24", pfx)
	}
	// Ensure network .0 and broadcast .255 are not allocated
	usedEmpty := []netip.Addr{}
	pfx, err = AllocateDHCP(DHCPPool, usedEmpty)
	if err != nil {
		t.Fatal(err)
	}
	if pfx.Addr().String() == "10.144.144.0" || pfx.Addr().String() == "10.144.144.255" {
		t.Fatalf("DHCP allocated reserved address %v", pfx)
	}
	// All hosts used except one should return the free one
	var many []netip.Addr
	for i := 1; i <= 253; i++ {
		many = append(many, netip.MustParseAddr(fmt.Sprintf("10.144.144.%d", i)))
	}
	// only .254 free
	pfx, err = AllocateDHCP(DHCPPool, many[:253])
	if err != nil {
		t.Fatal(err)
	}
	if pfx.Addr().String() != "10.144.144.254" {
		t.Fatalf("DHCP full pool allocation = %v, want 10.144.144.254/24", pfx)
	}
	// No available
	many = append(many, netip.MustParseAddr("10.144.144.254"))
	if _, err := AllocateDHCP(DHCPPool, many); !errors.Is(err, ErrNoAvailableIP) {
		t.Fatalf("AllocateDHCP full pool error = %v, want no available", err)
	}
}

func TestAllocateDHCPWithCurrentRetainsValidIP(t *testing.T) {
	current := netip.MustParsePrefix("10.144.144.10/24")
	used := parseAddrs(t, []string{"10.144.144.1", "10.144.144.2"})
	pfx, err := AllocateDHCPWithCurrent(DHCPPool, used, &current)
	if err != nil {
		t.Fatal(err)
	}
	if pfx != current {
		t.Fatalf("AllocateDHCPWithCurrent retained = %v, want %v", pfx, current)
	}
	// Current conflicts -> allocate next free
	current = netip.MustParsePrefix("10.144.144.1/24")
	pfx, err = AllocateDHCPWithCurrent(DHCPPool, used, &current)
	if err != nil {
		t.Fatal(err)
	}
	if pfx.String() == "10.144.144.1/24" {
		t.Fatalf("conflicted current was reused")
	}
	if pfx.String() != "10.144.144.3/24" {
		t.Fatalf("AllocateDHCPWithCurrent conflict = %v, want 10.144.144.3/24", pfx)
	}
}

func TestStaticIPv4AndIPv6Assignment(t *testing.T) {
	dev, _ := newMemoryPair(t, 1)
	v4, err := ParseIPv4Prefix("10.144.144.5/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.AssignIPv4(v4); err != nil {
		t.Fatal(err)
	}
	if got, ok := dev.AssignedIPv4(); !ok || got != v4 {
		t.Fatalf("AssignedIPv4 = %v, %t, want %v", got, ok, v4)
	}
	// IPv4 without prefix defaults to /24
	v4b, err := ParseIPv4Prefix("10.144.144.6")
	if err != nil || v4b.Bits() != 24 {
		t.Fatalf("ParseIPv4Prefix default /24 = %v, %v", v4b, err)
	}
	v6, err := ParseIPv6Prefix("fd00::1/64")
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.AssignIPv6(v6); err != nil {
		t.Fatal(err)
	}
	if got, ok := dev.AssignedIPv6(); !ok || got != v6 {
		t.Fatalf("AssignedIPv6 = %v, %t, want %v", got, ok, v6)
	}
	// Invalid IPv6 without prefix should fail
	if _, err := ParseIPv6Prefix("fd00::1"); err == nil {
		t.Fatal("ParseIPv6Prefix without CIDR succeeded")
	}
}

func TestEffectiveMTUHandlesEncryptionOverhead(t *testing.T) {
	if got := EffectiveMTU(1380, false); got != 1380 {
		t.Fatalf("EffectiveMTU no encryption = %d, want 1380", got)
	}
	if got := EffectiveMTU(1380, true); got != 1360 {
		t.Fatalf("EffectiveMTU encryption = %d, want 1360", got)
	}
	if got := EffectiveMTU(0, false); got != DefaultMTU {
		t.Fatalf("EffectiveMTU zero = %d, want %d", got, DefaultMTU)
	}
	if got := EffectiveMTU(1280, true); got != 1280 {
		// min 1280 after subtract clamps to 1280
		t.Fatalf("EffectiveMTU min clamp = %d", got)
	}
}

func TestShouldCreateTUNRespectsNoTUN(t *testing.T) {
	if !ShouldCreateTUN(TunConfig{NoTUN: false}) {
		t.Fatal("ShouldCreateTUN false without noTun")
	}
	if ShouldCreateTUN(TunConfig{NoTUN: true}) {
		t.Fatal("ShouldCreateTUN true with noTun")
	}
}

func TestResolveAssignedDHCPAndStatic(t *testing.T) {
	used := parseAddrs(t, []string{"10.144.144.1"})
	assigned, err := ResolveAssigned(TunConfig{DHCP: true, MTU: 1380}, used)
	if err != nil {
		t.Fatal(err)
	}
	if assigned.IPv4 == nil || assigned.IPv4.Addr().String() == "10.144.144.1" {
		t.Fatalf("ResolveAssigned DHCP conflict not avoided: %v", assigned.IPv4)
	}
	if assigned.MTU != 1380 {
		t.Fatalf("MTU = %d, want 1380", assigned.MTU)
	}
	assigned, err = ResolveAssigned(TunConfig{IPv4: "10.144.144.10/24", IPv6: "fd00::10/64", MTU: 1500, EnableEncryption: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if assigned.IPv4.String() != "10.144.144.10/24" {
		t.Fatalf("static IPv4 = %v", assigned.IPv4)
	}
	if assigned.IPv6.String() != "fd00::10/64" {
		t.Fatalf("static IPv6 = %v", assigned.IPv6)
	}
	if assigned.MTU != 1480 { // 1500-20
		t.Fatalf("effective MTU = %d, want 1480", assigned.MTU)
	}
	// NoTUN returns NoTUN flag and no addresses
	assigned, err = ResolveAssigned(TunConfig{NoTUN: true, DHCP: true}, used)
	if err != nil {
		t.Fatal(err)
	}
	if !assigned.NoTUN {
		t.Fatal("NoTUN flag not set")
	}
}

func TestMemoryDeviceMTUAndNoTUN(t *testing.T) {
	dev, _ := newMemoryPair(t, 1)
	if err := dev.SetMTU(1400); err != nil {
		t.Fatal(err)
	}
	if dev.MTU() != 1400 {
		t.Fatalf("MTU = %d, want 1400", dev.MTU())
	}
	dev.SetNoTUN(true)
	if !dev.IsNoTUN() {
		t.Fatal("IsNoTUN false after set")
	}
}

func parseAddrs(t *testing.T, strs []string) []netip.Addr {
	t.Helper()
	addrs := make([]netip.Addr, 0, len(strs))
	for _, s := range strs {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

func assertPending(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("operation completed early: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
}

//go:build linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package linux provides a Linux TUN adapter.
package linux

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/EasyTier/EasyTier/go/internal/platform"
	"golang.org/x/sys/unix"
)

const pollTimeoutMilliseconds = 100

type Config = platform.Config

const (
	DefaultMTU    = platform.DefaultMTU
	MaxMTU        = platform.MaxMTU
	MaxPacketSize = platform.MaxPacketSize
)

var (
	ErrInvalidConfig    = platform.ErrInvalidConfig
	ErrInvalidMTU       = platform.ErrInvalidMTU
	ErrInvalidPacketMax = platform.ErrInvalidPacketMax
	ErrInvalidFD        = platform.ErrInvalidFD
	ErrInvalidPacket    = platform.ErrInvalidPacket
	ErrPacketTooLarge   = platform.ErrPacketTooLarge
	ErrClosed           = platform.ErrClosed
)

// TUN is a packet-mode Linux TUN device. The descriptor is owned by TUN,
// including when it was created from an injected descriptor.
type TUN struct {
	mu            sync.RWMutex
	readMu        sync.Mutex
	writeMu       sync.Mutex
	fd            int
	name          string
	mtu           int
	maxPacketSize int
	closed        bool
}

var _ platform.Device = (*TUN)(nil)

// New creates a named TUN device through /dev/net/tun. Packet information is
// disabled so ReadPacket and WritePacket exchange complete IP packets.
func New(config Config) (*TUN, error) {
	config, err := normalizeConfig(config, true)
	if err != nil {
		return nil, err
	}

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(config.Name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("prepare TUN interface %q: %w", config.Name, err)
	}
	ifr.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI))
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create TUN interface %q: %w", config.Name, err)
	}
	return newTUN(fd, ifr.Name(), config), nil
}

// NewTUN creates a named TUN device with MaxPacketSize equal to mtu.
func NewTUN(name string, mtu int) (*TUN, error) {
	return New(Config{Name: name, MTU: mtu})
}

// NewFromFD duplicates and wraps an already-open TUN descriptor. The supplied
// descriptor must refer to a TUN configured with IFF_NO_PI; the duplicate is
// closed by TUN, leaving the caller's descriptor usable.
func NewFromFD(fd int, config Config) (*TUN, error) {
	config, err := normalizeConfig(config, false)
	if err != nil {
		return nil, err
	}
	if fd < 0 {
		return nil, fmt.Errorf("%w: %d", platform.ErrInvalidFD, fd)
	}

	ownedFD, err := unix.Dup(fd)
	if err != nil {
		return nil, fmt.Errorf("%w %d: %v", platform.ErrInvalidFD, fd, err)
	}
	unix.CloseOnExec(ownedFD)

	ifr, err := unix.NewIfreq("")
	if err == nil {
		err = unix.IoctlIfreq(ownedFD, unix.TUNGETIFF, ifr)
	}
	if err != nil {
		_ = unix.Close(ownedFD)
		return nil, fmt.Errorf("%w %d: not a usable TUN descriptor: %v", platform.ErrInvalidFD, fd, err)
	}
	flags := ifr.Uint16()
	if flags&uint16(unix.IFF_TUN) == 0 || flags&uint16(unix.IFF_NO_PI) == 0 {
		_ = unix.Close(ownedFD)
		return nil, fmt.Errorf("%w %d: descriptor is not an IFF_TUN|IFF_NO_PI device", platform.ErrInvalidFD, fd)
	}
	if config.Name != "" && config.Name != ifr.Name() {
		_ = unix.Close(ownedFD)
		return nil, fmt.Errorf("%w: descriptor is %q, requested %q", platform.ErrInvalidConfig, ifr.Name(), config.Name)
	}
	return newTUN(ownedFD, ifr.Name(), config), nil
}

// NewTUNFromFD wraps an injected TUN descriptor with MTU as its packet bound.
func NewTUNFromFD(fd int, mtu int) (*TUN, error) {
	return NewFromFD(fd, Config{MTU: mtu})
}

func newTUN(fd int, name string, config Config) *TUN {
	return &TUN{
		fd:            fd,
		name:          name,
		mtu:           config.MTU,
		maxPacketSize: config.MaxPacketSize,
	}
}

func normalizeConfig(config Config, requireName bool) (Config, error) {
	if requireName {
		if config.Name == "" {
			return Config{}, fmt.Errorf("%w: TUN name is empty", platform.ErrInvalidConfig)
		}
	}
	if strings.IndexByte(config.Name, 0) >= 0 {
		return Config{}, fmt.Errorf("%w: TUN name contains NUL", platform.ErrInvalidConfig)
	}
	if len(config.Name) >= unix.IFNAMSIZ {
		return Config{}, fmt.Errorf("%w: TUN name %q is too long", platform.ErrInvalidConfig, config.Name)
	}
	if config.MTU <= 0 || config.MTU > platform.MaxMTU {
		return Config{}, fmt.Errorf("%w: %w: %d", platform.ErrInvalidConfig, platform.ErrInvalidMTU, config.MTU)
	}
	if config.MaxPacketSize == 0 {
		config.MaxPacketSize = config.MTU
	}
	if config.MaxPacketSize < config.MTU || config.MaxPacketSize > platform.MaxPacketSize {
		return Config{}, fmt.Errorf("%w: %w: %d", platform.ErrInvalidConfig, platform.ErrInvalidPacketMax, config.MaxPacketSize)
	}
	return config, nil
}

// Name returns the kernel interface name.
func (d *TUN) Name() string {
	if d == nil {
		return ""
	}
	return d.name
}

// MTU returns the configured packet MTU.
func (d *TUN) MTU() int {
	if d == nil {
		return 0
	}
	return d.mtu
}

// ReadPacket reads one complete packet, honoring ctx cancellation.
func (d *TUN) ReadPacket(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := d.valid(); err != nil {
		return nil, err
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()

	buffer := make([]byte, d.maxPacketSize+1)
	for {
		if err := d.wait(ctx, unix.POLLIN); err != nil {
			return nil, err
		}
		d.mu.RLock()
		if d.closed {
			d.mu.RUnlock()
			return nil, platform.ErrClosed
		}
		n, err := unix.Read(d.fd, buffer)
		d.mu.RUnlock()
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read TUN packet: %w", err)
		}
		if n == 0 {
			return nil, io.EOF
		}
		if n > d.mtu || n > d.maxPacketSize {
			return nil, fmt.Errorf("%w: packet size %d, MTU %d, maximum %d", platform.ErrPacketTooLarge, n, d.mtu, d.maxPacketSize)
		}
		return append([]byte(nil), buffer[:n]...), nil
	}
}

// WritePacket writes one complete packet, honoring ctx cancellation while the
// descriptor is not ready for writing.
func (d *TUN) WritePacket(ctx context.Context, packet []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := d.valid(); err != nil {
		return err
	}
	if len(packet) == 0 {
		return fmt.Errorf("%w: empty packet", platform.ErrInvalidPacket)
	}
	if len(packet) > d.mtu || len(packet) > d.maxPacketSize {
		return fmt.Errorf("%w: packet size %d, MTU %d, maximum %d", platform.ErrPacketTooLarge, len(packet), d.mtu, d.maxPacketSize)
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	for {
		if err := d.wait(ctx, unix.POLLOUT); err != nil {
			return err
		}
		d.mu.RLock()
		if d.closed {
			d.mu.RUnlock()
			return platform.ErrClosed
		}
		n, err := unix.Write(d.fd, packet)
		d.mu.RUnlock()
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("write TUN packet: %w", err)
		}
		if n != len(packet) {
			return io.ErrShortWrite
		}
		return nil
	}
}

func (d *TUN) valid() error {
	if d == nil {
		return platform.ErrClosed
	}
	d.mu.RLock()
	closed := d.closed
	d.mu.RUnlock()
	if closed {
		return platform.ErrClosed
	}
	return nil
}

func (d *TUN) wait(ctx context.Context, events int16) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		d.mu.RLock()
		if d.closed {
			d.mu.RUnlock()
			return platform.ErrClosed
		}
		fds := []unix.PollFd{{Fd: int32(d.fd), Events: events}}
		n, err := unix.Poll(fds, pollTimeoutMilliseconds)
		closed := d.closed
		d.mu.RUnlock()
		if closed {
			return platform.ErrClosed
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll TUN device: %w", err)
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return fmt.Errorf("poll TUN device: %w", unix.EIO)
		}
		return nil
	}
}

// Close releases the device descriptor. It is safe to call repeatedly.
func (d *TUN) Close() error {
	if d == nil {
		return platform.ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	err := unix.Close(d.fd)
	d.fd = -1
	if err != nil {
		return fmt.Errorf("close TUN device: %w", err)
	}
	return nil
}

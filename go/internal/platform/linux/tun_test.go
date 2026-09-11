//go:build linux

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package linux

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/EasyTier/EasyTier/go/internal/platform"
	"golang.org/x/sys/unix"
)

func TestNewRejectsInvalidConfig(t *testing.T) {
	for _, test := range []struct {
		name   string
		config Config
		want   error
	}{
		{name: "missing name", config: Config{MTU: 1500}, want: platform.ErrInvalidConfig},
		{name: "zero MTU", config: Config{Name: "tun-test", MTU: 0}, want: platform.ErrInvalidMTU},
		{name: "MTU too large", config: Config{Name: "tun-test", MTU: platform.MaxMTU + 1}, want: platform.ErrInvalidMTU},
		{name: "maximum too small", config: Config{Name: "tun-test", MTU: 1500, MaxPacketSize: 1499}, want: platform.ErrInvalidPacketMax},
		{name: "name too long", config: Config{Name: "0123456789abcdef", MTU: 1500}, want: platform.ErrInvalidConfig},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.config)
			if !errors.Is(err, test.want) {
				t.Fatalf("New() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewFromFDRejectsInvalidFD(t *testing.T) {
	_, err := NewFromFD(-1, Config{MTU: 1500})
	if !errors.Is(err, platform.ErrInvalidFD) {
		t.Fatalf("NewFromFD() error = %v, want invalid FD", err)
	}

	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, err = NewFromFD(int(file.Fd()), Config{MTU: 1500})
	if !errors.Is(err, platform.ErrInvalidFD) {
		t.Fatalf("NewFromFD(/dev/null) error = %v, want invalid FD", err)
	}
}

func TestNewTUNRequiresLinuxTUNDevice(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root or CAP_NET_ADMIN")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun is unavailable")
	}

	name := fmt.Sprintf("et%d", os.Getpid())
	device, err := New(Config{Name: name, MTU: 1500})
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("TUN creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if device.Name() != name {
		t.Fatalf("Name() = %q, want %q", device.Name(), name)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
}

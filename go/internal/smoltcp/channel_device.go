// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package smoltcp

import (
	"context"
	"io"
)

// ChannelDevice is the async channel-backed device used for testing and for
// wiring the stack to the peer manager. It mirrors Rust's channel_device.rs.
type ChannelDevice struct {
	recvCh chan []byte
	sendCh chan []byte
	caps   DeviceCapabilities
}

// ChannelDevicePair holds both ends of the channel device.
type ChannelDevicePair struct {
	Device *ChannelDevice
	// Inject is used to deliver packets into the stack (peer -> stack).
	Inject chan []byte
	// Capture is where the stack emits packets (stack -> peer).
	Capture chan []byte
}

func NewChannelDevice(caps DeviceCapabilities) *ChannelDevicePair {
	inject := make(chan []byte, 1000)
	capture := make(chan []byte, 1000)
	dev := &ChannelDevice{
		recvCh: inject,
		sendCh: capture,
		caps:   caps.Clone(),
	}
	// Ensure MTU has sane default.
	if dev.caps.MTU == 0 {
		dev.caps.MTU = 1280
	}
	if dev.caps.Medium == 0 {
		dev.caps.Medium = MediumIP
	}
	return &ChannelDevicePair{
		Device:  dev,
		Inject:  inject,
		Capture: capture,
	}
}

func (d *ChannelDevice) Capabilities() DeviceCapabilities { return d.caps.Clone() }

// RecvChan returns the receive channel (stack reads from it).
func (d *ChannelDevice) RecvChan() <-chan []byte { return d.recvCh }

// Send emits a packet (stack writes to it).
func (d *ChannelDevice) Send(packet []byte) error {
	select {
	case d.sendCh <- append([]byte(nil), packet...):
		return nil
	default:
		return io.ErrShortWrite
	}
}

// TryRecv attempts to receive without blocking.
func (d *ChannelDevice) TryRecv() ([]byte, bool) {
	select {
	case p := <-d.recvCh:
		return p, true
	default:
		return nil, false
	}
}

// RecvWithContext waits for a packet or context cancellation.
func (d *ChannelDevice) RecvWithContext(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case p := <-d.recvCh:
		return p, nil
	}
}

// AsyncDevice is the interface expected by Net/Reactor. ChannelDevice
// implements it.
type AsyncDevice interface {
	Capabilities() DeviceCapabilities
	RecvChan() <-chan []byte
	Send([]byte) error
	TryRecv() ([]byte, bool)
}

// Ensure ChannelDevice implements AsyncDevice.
var _ AsyncDevice = (*ChannelDevice)(nil)

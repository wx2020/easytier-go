// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package smoltcp implements a user-space TCP/IP stack that mimics the Rust
// tokio_smoltcp behavior (easytier/src/gateway/tokio_smoltcp). It is optional
// and enabled via the configuration flag use-smoltcp.
package smoltcp

import "sync"

const DefaultMaxBurstSize = 100

// Packet is a raw IPv4 packet as used by AsyncDevice.
type Packet = []byte

// Medium describes the link-layer medium. We only support IP.
type Medium int

const (
	MediumIP       Medium = iota
	MediumEthernet Medium = iota
)

// DeviceCapabilities mirrors smoltcp::phy::DeviceCapabilities.
type DeviceCapabilities struct {
	MTU          int
	Medium       Medium
	MaxBurstSize *int
}

func (c DeviceCapabilities) Clone() DeviceCapabilities {
	var burst *int
	if c.MaxBurstSize != nil {
		v := *c.MaxBurstSize
		burst = &v
	}
	return DeviceCapabilities{
		MTU:          c.MTU,
		Medium:       c.Medium,
		MaxBurstSize: burst,
	}
}

// BufferDevice is the synchronous device used by the stack (analogous to
// Rust's BufferDevice). It queues packets between the reactor and the async
// device.
type BufferDevice struct {
	mu           sync.Mutex
	caps         DeviceCapabilities
	maxBurstSize int
	recvQueue    [][]byte
	sendQueue    [][]byte
}

func NewBufferDevice(caps DeviceCapabilities) *BufferDevice {
	burst := DefaultMaxBurstSize
	if caps.MaxBurstSize != nil {
		burst = *caps.MaxBurstSize
	}
	return &BufferDevice{
		caps:         caps.Clone(),
		maxBurstSize: burst,
		recvQueue:    make([][]byte, 0, burst),
		sendQueue:    make([][]byte, 0, burst),
	}
}

func (d *BufferDevice) Capabilities() DeviceCapabilities { return d.caps.Clone() }

func (d *BufferDevice) TakeSendQueue() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	q := d.sendQueue
	d.sendQueue = make([][]byte, 0, d.maxBurstSize)
	return q
}

func (d *BufferDevice) PushRecvQueue(packets [][]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	avail := d.maxBurstSize - len(d.recvQueue)
	if avail <= 0 {
		return
	}
	if len(packets) > avail {
		packets = packets[:avail]
	}
	d.recvQueue = append(d.recvQueue, packets...)
}

func (d *BufferDevice) PushOneRecv(packet []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.recvQueue) >= d.maxBurstSize {
		return false
	}
	cp := make([]byte, len(packet))
	copy(cp, packet)
	d.recvQueue = append(d.recvQueue, cp)
	return true
}

func (d *BufferDevice) AvailableRecv() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.maxBurstSize - len(d.recvQueue)
}

func (d *BufferDevice) NeedWait() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.recvQueue) == 0
}

func (d *BufferDevice) PopRecv() ([]byte, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.recvQueue) == 0 {
		return nil, false
	}
	p := d.recvQueue[0]
	d.recvQueue = d.recvQueue[1:]
	return p, true
}

func (d *BufferDevice) EnqueueSend(packet []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.sendQueue) >= d.maxBurstSize {
		return false
	}
	cp := make([]byte, len(packet))
	copy(cp, packet)
	d.sendQueue = append(d.sendQueue, cp)
	return true
}

func (d *BufferDevice) SendQueueLen() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sendQueue)
}

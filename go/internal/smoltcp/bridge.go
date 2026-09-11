// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package smoltcp

// Bridge connects two ChannelDevicePairs so that packets emitted by one are
// injected into the other. This is used for testing two Nets communicating.
func BridgeDevices(a, b *ChannelDevicePair) func() {
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case pkt := <-a.Capture:
				select {
				case b.Inject <- pkt:
				case <-stop:
					return
				}
			case pkt := <-b.Capture:
				select {
				case a.Inject <- pkt:
				case <-stop:
					return
				}
			}
		}
	}()
	return func() { close(stop) }
}

// LoopbackBridge creates a self-loop for a single device (Capture -> Inject).
func LoopbackBridge(p *ChannelDevicePair) func() {
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case pkt := <-p.Capture:
				select {
				case p.Inject <- pkt:
				case <-stop:
					return
				}
			}
		}
	}()
	return func() { close(stop) }
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import "testing"

func FuzzParseBody(f *testing.F) {
	f.Add(make([]byte, PeerManagerHeaderSize))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseBody(data)
	})
}

func FuzzParseUDPDatagram(f *testing.F) {
	f.Add(make([]byte, UDPTunnelHeaderSize))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseUDPDatagram(data)
	})
}

func FuzzParseHandshakeRequest(f *testing.F) {
	f.Add([]byte{0x2a, 0x01, 'x'})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseHandshakeRequest(data)
	})
}

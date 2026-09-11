// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package rpc

import "testing"

func FuzzUnmarshalRpcPacket(f *testing.F) {
	f.Add([]byte{0x08, 0x01})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = UnmarshalRpcPacket(data)
	})
}

func FuzzUnmarshalRpcDescriptor(f *testing.F) {
	f.Add([]byte{0x0a, 0x01, 'd'})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = UnmarshalRpcDescriptor(data)
	})
}

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gateway

import "testing"

func FuzzParsePacket(f *testing.F) {
	f.Add([]byte{0x45})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParsePacket(data)
	})
}

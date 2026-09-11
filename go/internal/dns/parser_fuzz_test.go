// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package dns

import "testing"

func FuzzParseName(f *testing.F) {
	f.Add([]byte{0})
	f.Fuzz(func(_ *testing.T, packet []byte) {
		_, _, _ = parseName(packet, 0)
	})
}

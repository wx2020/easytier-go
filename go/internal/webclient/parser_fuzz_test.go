// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webclient

import "testing"

func FuzzUnmarshalMessage(f *testing.F) {
	f.Add([]byte(`{"type":"heartbeat","machine_id":"machine"}`))
	f.Fuzz(func(_ *testing.T, payload []byte) {
		_, _ = UnmarshalMessage(payload)
	})
}

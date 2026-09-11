// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"encoding/hex"
	"testing"
)

func TestGenerateDigestFromStringsMatchesRustOracle(t *testing.T) {
	for _, test := range []struct {
		first, second, want string
	}{
		{"mesh", "secret", "31107b8e51f0ce46f7b98ceefacfec089fdf3c65e27f8b20fbe21c0ae043c564"},
		{"", "machine-id", "68c22d62bc0ab670f44068eff88224c91b2fa9e3cfffb6722b5553c491f454a7"},
		{"test", "", "e0969da9b8fb378dce342ab96f8be9dc0b5ca8125197369a011a53c6be2ba031"},
	} {
		digest := GenerateDigestFromStrings(test.first, test.second)
		if got := hex.EncodeToString(digest[:]); got != test.want {
			t.Fatalf("GenerateDigestFromStrings(%q, %q) = %s, want %s", test.first, test.second, got, test.want)
		}
	}
}

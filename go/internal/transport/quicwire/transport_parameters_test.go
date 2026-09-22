// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"bytes"
	"testing"
)

func TestTransportParametersRoundTrip(t *testing.T) {
	orig := DefaultTransportParameters([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	orig.OriginalDestCID = []byte{8, 7, 6, 5, 4, 3, 2, 1}
	orig.MaxIdleTimeout = 30000
	orig.InitialMaxData = 1048576
	orig.UnknownParams[0x1234] = []byte("custom-quic-param")

	b := orig.Marshal()
	if len(b) == 0 {
		t.Fatalf("Marshal produced empty bytes")
	}

	decoded, err := UnmarshalTransportParameters(b)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !bytes.Equal(decoded.InitialSourceCID, orig.InitialSourceCID) {
		t.Fatalf("InitialSourceCID mismatch: got %v, want %v", decoded.InitialSourceCID, orig.InitialSourceCID)
	}
	if !bytes.Equal(decoded.OriginalDestCID, orig.OriginalDestCID) {
		t.Fatalf("OriginalDestCID mismatch: got %v, want %v", decoded.OriginalDestCID, orig.OriginalDestCID)
	}
	if decoded.MaxIdleTimeout != orig.MaxIdleTimeout {
		t.Fatalf("MaxIdleTimeout mismatch: got %d, want %d", decoded.MaxIdleTimeout, orig.MaxIdleTimeout)
	}
	if decoded.InitialMaxData != orig.InitialMaxData {
		t.Fatalf("InitialMaxData mismatch: got %d, want %d", decoded.InitialMaxData, orig.InitialMaxData)
	}
	if decoded.InitialMaxStreamsBidi != orig.InitialMaxStreamsBidi {
		t.Fatalf("InitialMaxStreamsBidi mismatch: got %d, want %d", decoded.InitialMaxStreamsBidi, orig.InitialMaxStreamsBidi)
	}
	if !decoded.DisableActiveMigration {
		t.Fatalf("DisableActiveMigration must be true")
	}
	if !bytes.Equal(decoded.UnknownParams[0x1234], []byte("custom-quic-param")) {
		t.Fatalf("UnknownParams mismatch: got %s", string(decoded.UnknownParams[0x1234]))
	}
}

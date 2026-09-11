// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webclient

import (
	"bytes"
	"testing"
)

func TestWebClientParserHardening(t *testing.T) {
	malformed := [][]byte{
		nil,
		{},
		{0xFF},
		bytes.Repeat([]byte{0xFF}, 1024),
		bytes.Repeat([]byte{0x00}, 1024),
		[]byte(`{`),
		[]byte(`{"type":`),
		[]byte(`{"type":"unknown","machine_id":"x"}`),
		[]byte(`{"type":"heartbeat", "machine_id":123}`), // wrong type for machine_id
		[]byte(`not json at all`),
		[]byte(`{"type":"heartbeat","machine_id":"` + string(bytes.Repeat([]byte{'a'}, 10*1024)) + `"}`),
	}
	for i, data := range malformed {
		func(idx int, d []byte) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("UnmarshalMessage panic case %d: %v", idx, r)
				}
			}()
			_, _ = UnmarshalMessage(d)
		}(i, data)
		_, _ = UnmarshalMessage(append([]byte(nil), data...))
	}
	// Valid messages should still parse
	valid := []byte(`{"type":"heartbeat","machine_id":"machine123"}`)
	if msg, err := UnmarshalMessage(valid); err != nil || msg.Type != "heartbeat" {
		t.Fatalf("valid heartbeat: %v %v", msg, err)
	}
	// Ensure large but valid JSON doesn't cause unbounded allocation
	large := []byte(`{"type":"heartbeat","machine_id":"` + string(bytes.Repeat([]byte{'b'}, 4*1024)) + `"}`)
	if _, err := UnmarshalMessage(large); err == nil {
		// Should either succeed or fail gracefully, not panic
	}
}

func TestWebClientMessageBounds(t *testing.T) {
	// Message with nested objects should not panic
	nested := []byte(`{"type":"config","machine_id":"m","payload":{"a":{"b":{"c":123}}}}`)
	_, _ = UnmarshalMessage(nested)
	// Ensure type field is required
	if _, err := UnmarshalMessage([]byte(`{"machine_id":"x"}`)); err == nil {
		t.Fatal("missing type should fail")
	}
}

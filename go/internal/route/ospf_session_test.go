// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import "testing"

func TestSessionTrackerObservesChanges(t *testing.T) {
	tracker := NewSessionTracker()
	if tracker.Observe(1, 100) {
		t.Fatal("first observation must not report a change")
	}
	if tracker.Observe(1, 100) {
		t.Fatal("unchanged session id must not report a change")
	}
	if !tracker.Observe(1, 200) {
		t.Fatal("changed session id must report a change (peer restart)")
	}
	if session, ok := tracker.SessionOf(1); !ok || session != 200 {
		t.Fatalf("stored session = %d, want 200", session)
	}
	// Peers are tracked independently.
	if tracker.Observe(2, 100) {
		t.Fatal("first observation for another peer must not report a change")
	}
}

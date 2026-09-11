// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenRouteFixtures(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "compat", "route", "fixtures.json")
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join("testdata", "compat", "route", "fixtures.json")
		if _, err2 := os.Stat(path); err2 != nil {
			path = filepath.Join("go", "testdata", "compat", "route", "fixtures.json")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read route fixtures: %v", err)
	}
	var fixtures []struct {
		Name           string                        `json:"name"`
		LocalPeerID    uint32                        `json:"local_peer_id"`
		Links          []struct{ A, B, Cost uint32 } `json:"links"`
		ExpectedRoutes []struct {
			Destination uint32 `json:"Destination"`
			NextHop     uint32 `json:"NextHop"`
			Cost        uint64 `json:"Cost"`
		} `json:"expected_routes"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("unmarshal route fixtures: %v", err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			e := NewEngine(f.LocalPeerID)
			for _, l := range f.Links {
				e.AddLink(l.A, l.B, l.Cost)
			}
			got := e.Snapshot()
			m := make(map[uint32]Route)
			for _, r := range got {
				m[r.Destination] = r
			}
			if len(m) != len(f.ExpectedRoutes) {
				t.Fatalf("route count mismatch: got %d want %d, got %+v", len(m), len(f.ExpectedRoutes), got)
			}
			for _, exp := range f.ExpectedRoutes {
				g, ok := m[exp.Destination]
				if !ok {
					t.Fatalf("missing destination %d", exp.Destination)
				}
				if g.NextHop != exp.NextHop || g.Cost != exp.Cost {
					t.Fatalf("route %d mismatch: got next=%d cost=%d want next=%d cost=%d", exp.Destination, g.NextHop, g.Cost, exp.NextHop, exp.Cost)
				}
			}
		})
	}
}

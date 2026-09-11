// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import "testing"

func TestDijkstraWithFirstHop4Node(t *testing.T) {
	graph := NewGraph[string, int32]()
	graph.AddEdge("a", "b", 1)
	graph.AddEdge("b", "c", 1)
	graph.AddEdge("c", "d", 2)

	result := DijkstraWithFirstHop(graph, "a", int32(0))

	if got := result.Scores["b"]; got != 1 {
		t.Fatalf("score b = %d, want 1", got)
	}
	if got := result.Scores["c"]; got != 2 {
		t.Fatalf("score c = %d, want 2", got)
	}
	if got := result.Scores["d"]; got != 4 {
		t.Fatalf("score d = %d, want 4", got)
	}

	if got := result.FirstHop["b"]; got.Node != "b" || got.Distance != 1 {
		t.Fatalf("first hop b = %#v, want (b,1)", got)
	}
	if got := result.FirstHop["c"]; got.Node != "b" || got.Distance != 2 {
		t.Fatalf("first hop c = %#v, want (b,2)", got)
	}
	if got := result.FirstHop["d"]; got.Node != "b" || got.Distance != 3 {
		t.Fatalf("first hop d = %#v, want (b,3)", got)
	}
}

func TestDijkstraWithFirstHopMultiPath(t *testing.T) {
	graph := NewGraph[string, int32]()
	graph.AddEdge("a", "b", 1)
	graph.AddEdge("a", "c", 2)
	graph.AddEdge("b", "d", 1)
	graph.AddEdge("c", "d", 3)
	graph.AddEdge("d", "e", 1)

	result := DijkstraWithFirstHop(graph, "a", int32(0))

	if got := result.Scores["b"]; got != 1 {
		t.Fatalf("score b = %d, want 1", got)
	}
	if got := result.Scores["c"]; got != 2 {
		t.Fatalf("score c = %d, want 2", got)
	}
	if got := result.Scores["d"]; got != 2 {
		t.Fatalf("score d = %d, want 2", got)
	}
	if got := result.Scores["e"]; got != 3 {
		t.Fatalf("score e = %d, want 3", got)
	}

	if got := result.FirstHop["b"]; got.Node != "b" || got.Distance != 1 {
		t.Fatalf("first hop b = %#v, want (b,1)", got)
	}
	if got := result.FirstHop["c"]; got.Node != "c" || got.Distance != 1 {
		t.Fatalf("first hop c = %#v, want (c,1)", got)
	}
	if got := result.FirstHop["d"]; got.Node != "b" || got.Distance != 2 {
		t.Fatalf("first hop d = %#v, want (b,2) via b", got)
	}
	if got := result.FirstHop["e"]; got.Node != "b" || got.Distance != 3 {
		t.Fatalf("first hop e = %#v, want (b,3) via d", got)
	}
}

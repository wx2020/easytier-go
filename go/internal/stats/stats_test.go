// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package stats

import (
	"strings"
	"sync"
	"testing"
)

func TestCountersAddGetAndSnapshot(t *testing.T) {
	counters := New()
	counters.Add("zeta", 2)
	counters.Add("alpha", 3)
	counters.Add("zeta", 4)

	if got, ok := counters.Get("zeta"); !ok || got != 6 {
		t.Fatalf("Get(zeta) = %d, %t; want 6, true", got, ok)
	}
	if _, ok := counters.Get("missing"); ok {
		t.Fatal("Get(missing) reported a value")
	}

	snapshot := counters.Snapshot()
	if len(snapshot) != 2 || snapshot[0] != (Counter{Name: "alpha", Value: 3}) || snapshot[1] != (Counter{Name: "zeta", Value: 6}) {
		t.Fatalf("Snapshot() = %#v", snapshot)
	}
}

func TestCountersConcurrentAdd(t *testing.T) {
	counters := New()
	const goroutines = 32
	const additions = 1_000

	var group sync.WaitGroup
	group.Add(goroutines)
	for range goroutines {
		go func() {
			defer group.Done()
			for range additions {
				counters.Add("requests_total", 1)
			}
		}()
	}
	group.Wait()

	if got, ok := counters.Get("requests_total"); !ok || got != goroutines*additions {
		t.Fatalf("Get(requests_total) = %d, %t; want %d, true", got, ok, goroutines*additions)
	}
}

func TestPrometheusDeterministicAndEscapesHelp(t *testing.T) {
	counters := New()
	counters.Add("zeta_total", 2)
	counters.Add("alpha_total", 1)

	got, err := counters.Prometheus("Count \\ source\nlines")
	if err != nil {
		t.Fatal(err)
	}
	const want = "# HELP alpha_total Count \\\\ source\\nlines\n# TYPE alpha_total counter\nalpha_total 1\n# HELP zeta_total Count \\\\ source\\nlines\n# TYPE zeta_total counter\nzeta_total 2\n"
	if got != want {
		t.Fatalf("Prometheus() = %q; want %q", got, want)
	}
}

func TestPrometheusRejectsInvalidMetricNames(t *testing.T) {
	for _, name := range []string{"", "1st_total", "request-count", "request total", "requests.total"} {
		t.Run(name, func(t *testing.T) {
			counters := New()
			counters.Add(name, 1)
			if _, err := counters.Prometheus("requests"); err == nil || !strings.Contains(err.Error(), "invalid Prometheus metric name") {
				t.Fatalf("Prometheus() error = %v; want invalid metric name error", err)
			}
		})
	}
}

func TestPrometheusLabelsAreStableAndEscaped(t *testing.T) {
	counters := New()
	counters.AddWithLabels("requests_total", map[string]string{"zone": "mesh", "instance": "edge\"1\n"}, 2)
	got, err := counters.Prometheus("requests")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `requests_total{instance="edge\"1\n",zone="mesh"} 2`) {
		t.Fatalf("Prometheus labels = %q", got)
	}
	snapshot := counters.SnapshotWithLabels()
	if len(snapshot) != 1 || snapshot[0].Labels["zone"] != "mesh" {
		t.Fatalf("labeled snapshot = %#v", snapshot)
	}
}

func TestPrometheusEscapesHelpAndMergesCommonLabels(t *testing.T) {
	counters := New()
	counters.AddWithLabels("requests_total", map[string]string{"instance": "specific\"value"}, 2)
	got, err := counters.PrometheusWithLabels("help \\ path\nnext", map[string]string{
		"instance": "common",
		"zone":     "mesh\\\"\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "# HELP requests_total help \\\\ path\\nnext\n# TYPE requests_total counter\nrequests_total{instance=\"specific\\\"value\",zone=\"mesh\\\\\\\"\\n\"} 2\n"
	if got != want {
		t.Fatalf("PrometheusWithLabels() = %q; want %q", got, want)
	}
}

func TestPrometheusRejectsInvalidLabelNames(t *testing.T) {
	for _, name := range []string{"", "1zone", "zone-name", "zone:name"} {
		t.Run(name, func(t *testing.T) {
			counters := New()
			counters.AddWithLabels("requests_total", map[string]string{name: "value"}, 1)
			if _, err := counters.Prometheus("help"); err == nil || !strings.Contains(err.Error(), "invalid Prometheus label name") {
				t.Fatalf("Prometheus() error = %v; want invalid label name error", err)
			}
		})
	}
}

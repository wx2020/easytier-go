// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package stats provides concurrency-safe counters for one runtime instance.
package stats

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Counter is one named counter value in a snapshot.
type Counter struct {
	Name  string
	Value uint64
}

// LabeledCounter is the extended snapshot form used by Prometheus and
// management consumers that need label values.
type LabeledCounter struct {
	Name   string
	Value  uint64
	Labels map[string]string
}

// Counters stores counters belonging to one runtime instance.
type Counters struct {
	mu     sync.RWMutex
	values map[counterKey]uint64
}

type counterKey struct {
	name   string
	labels string
}

// New creates an empty set of counters.
func New() *Counters {
	return &Counters{values: make(map[counterKey]uint64)}
}

// Add increments name by value.
func (c *Counters) Add(name string, value uint64) {
	c.AddWithLabels(name, nil, value)
}

// AddWithLabels increments a counter with a stable set of Prometheus labels.
// Labels are copied so callers may safely reuse or mutate their input map.
func (c *Counters) AddWithLabels(name string, labels map[string]string, value uint64) {
	key := counterKey{name: name, labels: labelKey(labels)}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.values == nil {
		c.values = make(map[counterKey]uint64)
	}
	c.values[key] += value
}

// Get returns the current value for name. The boolean reports whether name has
// been added to this counter set.
func (c *Counters) Get(name string) (uint64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, ok := c.values[counterKey{name: name}]
	return value, ok
}

// Snapshot returns a point-in-time copy of the counters sorted by name.
func (c *Counters) Snapshot() []Counter {
	labeled := c.SnapshotWithLabels()
	result := make([]Counter, len(labeled))
	for i, counter := range labeled {
		result[i] = Counter{Name: counter.Name, Value: counter.Value}
	}
	return result
}

// SnapshotWithLabels returns a point-in-time copy including Prometheus labels.
func (c *Counters) SnapshotWithLabels() []LabeledCounter {
	c.mu.RLock()
	snapshot := make([]LabeledCounter, 0, len(c.values))
	for key, value := range c.values {
		snapshot = append(snapshot, LabeledCounter{Name: key.name, Value: value, Labels: parseLabels(key.labels)})
	}
	c.mu.RUnlock()

	sort.Slice(snapshot, func(i, j int) bool {
		if snapshot[i].Name != snapshot[j].Name {
			return snapshot[i].Name < snapshot[j].Name
		}
		return labelKey(snapshot[i].Labels) < labelKey(snapshot[j].Labels)
	})
	return snapshot
}

// Prometheus returns counters in the Prometheus text exposition format. help is
// used for every counter and is escaped according to the text format rules.
func (c *Counters) Prometheus(help string) (string, error) {
	return c.PrometheusWithLabels(help, nil)
}

// PrometheusWithLabels renders counters and adds labels common to every
// rendered sample. Per-counter labels take precedence over common labels.
func (c *Counters) PrometheusWithLabels(help string, common map[string]string) (string, error) {
	var output strings.Builder
	emittedTypes := make(map[string]struct{})
	for _, counter := range c.SnapshotWithLabels() {
		if !validMetricName(counter.Name) {
			return "", fmt.Errorf("invalid Prometheus metric name %q", counter.Name)
		}
		labels := mergeLabels(common, counter.Labels)
		labelText, err := prometheusLabels(labels)
		if err != nil {
			return "", err
		}
		if _, ok := emittedTypes[counter.Name]; !ok {
			fmt.Fprintf(&output, "# HELP %s %s\n# TYPE %s counter\n", counter.Name, escapeHelp(help), counter.Name)
			emittedTypes[counter.Name] = struct{}{}
		}
		fmt.Fprintf(&output, "%s%s %d\n", counter.Name, labelText, counter.Value)
	}
	return output.String(), nil
}

func mergeLabels(common, specific map[string]string) map[string]string {
	if len(common) == 0 && len(specific) == 0 {
		return nil
	}
	result := make(map[string]string, len(common)+len(specific))
	for name, value := range common {
		result[name] = value
	}
	for name, value := range specific {
		result[name] = value
	}
	return result
}

func prometheusLabels(labels map[string]string) (string, error) {
	if len(labels) == 0 {
		return "", nil
	}
	names := make([]string, 0, len(labels))
	for name := range labels {
		if !validMetricName(name) || strings.Contains(name, ":") {
			return "", fmt.Errorf("invalid Prometheus label name %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var result strings.Builder
	result.WriteByte('{')
	for i, name := range names {
		if i != 0 {
			result.WriteByte(',')
		}
		fmt.Fprintf(&result, `%s="%s"`, name, escapeLabel(labels[name]))
	}
	result.WriteByte('}')
	return result.String(), nil
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return strings.ReplaceAll(value, "\n", `\n`)
}

// labelKey is deliberately textual and sorted, making snapshots deterministic
// without exposing the internal counter map key.
func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	sort.Strings(names)
	var result strings.Builder
	for _, name := range names {
		fmt.Fprintf(&result, "%d:%s=%d:%s;", len(name), name, len(labels[name]), labels[name])
	}
	return result.String()
}

func parseLabels(key string) map[string]string {
	if key == "" {
		return nil
	}
	result := make(map[string]string)
	for len(key) > 0 {
		nameLength, rest, ok := readLength(key)
		if !ok || len(rest) < nameLength {
			return nil
		}
		name := rest[:nameLength]
		rest = rest[nameLength:]
		if !strings.HasPrefix(rest, "=") {
			return nil
		}
		valueLength, rest, ok := readLength(rest[1:])
		if !ok || len(rest) < valueLength {
			return nil
		}
		value := rest[:valueLength]
		rest = rest[valueLength:]
		if !strings.HasPrefix(rest, ";") {
			return nil
		}
		result[name] = value
		key = rest[1:]
	}
	return result
}

func readLength(value string) (int, string, bool) {
	colon := strings.IndexByte(value, ':')
	if colon <= 0 {
		return 0, "", false
	}
	var length int
	if _, err := fmt.Sscanf(value[:colon], "%d", &length); err != nil || length < 0 {
		return 0, "", false
	}
	return length, value[colon+1:], true
}

func validMetricName(name string) bool {
	if name == "" || !isMetricStart(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isMetricPart(name[i]) {
			return false
		}
	}
	return true
}

func isMetricStart(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character == '_' || character == ':'
}

func isMetricPart(character byte) bool {
	return isMetricStart(character) || character >= '0' && character <= '9'
}

func escapeHelp(help string) string {
	help = strings.ReplaceAll(help, "\\", "\\\\")
	help = strings.ReplaceAll(help, "\n", "\\n")
	return help
}

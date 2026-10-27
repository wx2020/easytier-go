// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package core

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// fakeRunner records executed route commands.
type fakeRunner struct {
	commands []string
	failOn   string // substring; commands containing it fail
}

func (f *fakeRunner) run(command []string) error {
	joined := strings.Join(command, " ")
	f.commands = append(f.commands, joined)
	if f.failOn != "" && strings.Contains(joined, f.failOn) {
		return fmt.Errorf("simulated failure for %s", joined)
	}
	return nil
}

func (f *fakeRunner) adds() []string { return f.filter(" add ") }
func (f *fakeRunner) dels() []string { return f.filter(" del ") }

func (f *fakeRunner) filter(verb string) []string {
	var out []string
	for _, command := range f.commands {
		if strings.Contains(command, verb) {
			fields := strings.Fields(command)
			// ip route add <cidr> dev <ifname> ...: cidr is field 3
			if len(fields) >= 4 {
				out = append(out, fields[3])
			}
		}
	}
	return out
}

func newTestManager(runner *fakeRunner) *ProxyRouteManager {
	return &ProxyRouteManager{OSName: "linux", IfName: "easytier0", Run: runner.run}
}

func TestProxyRouteManagerInstallsAndWithdraws(t *testing.T) {
	runner := &fakeRunner{}
	manager := newTestManager(runner)

	added, removed, warnings, err := manager.Sync([]string{"192.168.100.0/24", " 10.5.0.0/16 ", "not-a-cidr"})
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not-a-cidr") {
		t.Fatalf("warnings = %v, want one about not-a-cidr", warnings)
	}
	if !reflect.DeepEqual(added, []string{"10.5.0.0/16", "192.168.100.0/24"}) {
		t.Fatalf("added = %v", added)
	}
	if len(removed) != 0 {
		t.Fatalf("removed = %v", removed)
	}
	if got := runner.adds(); !reflect.DeepEqual(got, []string{"10.5.0.0/16", "192.168.100.0/24"}) {
		t.Fatalf("install commands = %v", got)
	}

	// A repeat sync is a no-op.
	runner.commands = nil
	if _, _, _, err := manager.Sync([]string{"192.168.100.0/24", "10.5.0.0/16"}); err != nil {
		t.Fatalf("idempotent sync: %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("idempotent sync executed %v", runner.commands)
	}

	// Withdrawing one network removes only its route.
	runner.commands = nil
	added, removed, _, err = manager.Sync([]string{"192.168.100.0/24", "10.6.0.0/16"})
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if !reflect.DeepEqual(added, []string{"10.6.0.0/16"}) {
		t.Fatalf("added = %v", added)
	}
	if !reflect.DeepEqual(removed, []string{"10.5.0.0/16"}) {
		t.Fatalf("removed = %v", removed)
	}
	if got := runner.dels(); !reflect.DeepEqual(got, []string{"10.5.0.0/16"}) {
		t.Fatalf("delete commands = %v", got)
	}
}

func TestProxyRouteManagerClearRemovesEverything(t *testing.T) {
	runner := &fakeRunner{}
	manager := newTestManager(runner)
	if _, _, _, err := manager.Sync([]string{"192.168.5.0/24", "10.7.0.0/16"}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	runner.commands = nil
	if err := manager.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	got := runner.dels()
	if len(got) != 2 {
		t.Fatalf("clear deleted %v", got)
	}
	// Clear resets the bookkeeping: a following sync reinstalls.
	if _, _, _, err := manager.Sync([]string{"192.168.5.0/24"}); err != nil {
		t.Fatalf("sync after clear: %v", err)
	}
	if !reflect.DeepEqual(runner.adds(), []string{"192.168.5.0/24"}) {
		t.Fatalf("adds after clear = %v", runner.adds())
	}
}

func TestProxyRouteManagerAddFailureKeepsBookkeeping(t *testing.T) {
	runner := &fakeRunner{failOn: "10.9.0.0/16"}
	manager := newTestManager(runner)
	if _, _, _, err := manager.Sync([]string{"10.9.0.0/16"}); err == nil {
		t.Fatal("expected an error when the add command fails")
	}
	// The failed route must not be recorded as installed, so a later sync
	// retries it.
	runner.failOn = ""
	runner.commands = nil
	added, _, _, err := manager.Sync([]string{"10.9.0.0/16"})
	if err != nil {
		t.Fatalf("retry sync: %v", err)
	}
	if !reflect.DeepEqual(added, []string{"10.9.0.0/16"}) {
		t.Fatalf("retry added = %v", added)
	}
}

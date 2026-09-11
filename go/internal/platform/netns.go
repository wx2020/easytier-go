// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"strings"
)

// NetNS describes a Linux network namespace. On non-Linux it is a no-op
// but still appears in dry-run plans for testing parity with Rust
// easytier/src/common/netns.rs.
type NetNS struct {
	Name *string // nil means no namespace (root)
}

// NewNetNS creates a NetNS from an optional name.
// Empty string is treated as no namespace.
func NewNetNS(name string) NetNS {
	if strings.TrimSpace(name) == "" {
		return NetNS{Name: nil}
	}
	s := strings.TrimSpace(name)
	return NetNS{Name: &s}
}

// RootNetNS is the sentinel for switching to host netns via /proc/1/ns/net.
const RootNetNSName = "_root_ns"

// IsSet reports whether a non-root namespace is configured.
func (n NetNS) IsSet() bool { return n.Name != nil && *n.Name != RootNetNSName }

// String returns the namespace name or "<root>".
func (n NetNS) String() string {
	if n.Name == nil {
		return "<root>"
	}
	return *n.Name
}

// PlanNetNS returns a dry-run plan for entering a network namespace.
// On Linux this corresponds to setns(fd, CLONE_NEWNET) via /var/run/netns/<name>
// or /proc/1/ns/net for RootNetNSName.
func PlanNetNS(osName string, ns NetNS) (Plan, error) {
	plan := newPlan(osName)
	if ns.Name == nil {
		plan.Warnings = append(plan.Warnings, "no network namespace configured; running in host netns")
		return plan, nil
	}
	name := *ns.Name
	if osName != "linux" {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("network namespace %q is Linux-only; no-op on %s", name, osName))
		plan.add("netns (no-op on "+osName+")", []string{"netns", name, "noop"}, false, nil)
		return plan, nil
	}
	var nsPath string
	if name == RootNetNSName {
		nsPath = "/proc/1/ns/net"
	} else {
		nsPath = "/var/run/netns/" + name
	}
	plan.add(fmt.Sprintf("enter netns %s", name), []string{"setns", nsPath, "CLONE_NEWNET"}, true, []string{"setns", "/proc/self/ns/net", "CLONE_NEWNET"})
	plan.Warnings = append(plan.Warnings, "NetNSGuard will restore old ns on Drop; privileged: requires CAP_SYS_ADMIN")
	return plan, nil
}

// PlanNetNSExec returns a plan for executing a command inside a netns
// (ip netns exec helper) — useful for privileged integration where setns
// is not available directly in Go without cgo.
func PlanNetNSExec(osName string, ns NetNS, command []string) (Plan, error) {
	if len(command) == 0 {
		return Plan{}, fmt.Errorf("%w: command required for netns exec", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	if ns.Name == nil {
		plan.add("exec without netns", command, false, nil)
		return plan, nil
	}
	if osName != "linux" {
		plan.add("exec (netns no-op on "+osName+")", command, false, nil)
		plan.Warnings = append(plan.Warnings, "netns exec is Linux-only")
		return plan, nil
	}
	name := *ns.Name
	if name == RootNetNSName {
		plan.add("exec in root netns", append([]string{"nsenter", "--net=/proc/1/ns/net", "--"}, command...), true, nil)
	} else {
		plan.add(fmt.Sprintf("exec in netns %s", name), append([]string{"ip", "netns", "exec", name}, command...), true, nil)
	}
	return plan, nil
}

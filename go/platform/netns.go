// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"fmt"
	"strings"
)

type NetNS struct {
	Name *string
}

func NewNetNS(name string) NetNS {
	if strings.TrimSpace(name) == "" {
		return NetNS{Name: nil}
	}
	s := strings.TrimSpace(name)
	return NetNS{Name: &s}
}

const RootNetNSName = "_root_ns"

func (n NetNS) IsSet() bool { return n.Name != nil && *n.Name != RootNetNSName }
func (n NetNS) String() string {
	if n.Name == nil {
		return "<root>"
	}
	return *n.Name
}

func PlanNetNS(osName string, ns NetNS) (Plan, error) {
	plan := newPlan(osName)
	if ns.Name == nil {
		plan.Warnings = append(plan.Warnings, "no network namespace configured")
		return plan, nil
	}
	name := *ns.Name
	if osName != "linux" {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("network namespace %q is Linux-only; no-op on %s", name, osName))
		plan.Add("netns (no-op on "+osName+")", []string{"netns", name, "noop"}, false, nil)
		return plan, nil
	}
	var nsPath string
	if name == RootNetNSName {
		nsPath = "/proc/1/ns/net"
	} else {
		nsPath = "/var/run/netns/" + name
	}
	plan.Add(fmt.Sprintf("enter netns %s", name), []string{"setns", nsPath, "CLONE_NEWNET"}, true, []string{"setns", "/proc/self/ns/net", "CLONE_NEWNET"})
	plan.Warnings = append(plan.Warnings, "NetNSGuard will restore old ns on Drop; requires CAP_SYS_ADMIN")
	return plan, nil
}

func PlanNetNSExec(osName string, ns NetNS, command []string) (Plan, error) {
	if len(command) == 0 {
		return Plan{}, fmt.Errorf("%w: command required for netns exec", ErrInvalidConfig)
	}
	plan := newPlan(osName)
	if ns.Name == nil {
		plan.Add("exec without netns", command, false, nil)
		return plan, nil
	}
	if osName != "linux" {
		plan.Add("exec (netns no-op on "+osName+")", command, false, nil)
		return plan, nil
	}
	name := *ns.Name
	if name == RootNetNSName {
		plan.Add("exec in root netns", append([]string{"nsenter", "--net=/proc/1/ns/net", "--"}, command...), true, nil)
	} else {
		plan.Add(fmt.Sprintf("exec in netns %s", name), append([]string{"ip", "netns", "exec", name}, command...), true, nil)
	}
	return plan, nil
}

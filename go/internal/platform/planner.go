// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

// Plan describes a dry-run configuration plan for unit tests.
// It lists actions that would be executed on the native platform with
// privileged integration. The planner never touches the host.
type Plan struct {
	OS         string
	DryRun     bool
	Privileged bool
	Actions    []PlannedAction
	Warnings   []string
}

// PlannedAction is one operation in a Plan.
type PlannedAction struct {
	Description string
	Command     []string
	Privileged  bool
	Rollback    []string
}

func newPlan(os string) Plan {
	return Plan{OS: os, DryRun: true}
}

func (p *Plan) add(desc string, cmd []string, privileged bool, rollback []string) {
	p.Actions = append(p.Actions, PlannedAction{
		Description: desc,
		Command:     cmd,
		Privileged:  privileged,
		Rollback:    rollback,
	})
	if privileged {
		p.Privileged = true
	}
}

// IsPrivileged reports whether the plan requires elevated privileges to apply.
func (p *Plan) IsPrivileged() bool { return p.Privileged }

// RequiresPrivileged reports whether any action needs privileges.
func RequiresPrivileged(p Plan) bool { return p.Privileged }

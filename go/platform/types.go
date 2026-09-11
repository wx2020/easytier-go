// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

// TunConfig controls TUN device creation and packet bounds.
type TunConfig struct {
	Name          string
	MTU           int
	MaxPacketSize int
	FD            int // Injected FD for Android VpnService; -1 means create new
}

// RouteConfig describes desired routes for an interface.
type RouteConfig struct {
	IfName string
	Routes []string // CIDRs e.g. "10.144.144.0/24"
	Gateway string
	Metric int
}

// DNSConfig describes resolver configuration.
type DNSConfig struct {
	IfName  string
	Servers []string // e.g. "1.1.1.1", "8.8.8.8"
	Search  []string
	Domain  string
	Mode    string // "systemd-resolved", "resolv.conf", "scutil", "android"
}

// ServiceConfig describes a service to be managed.
type ServiceConfig struct {
	Name                    string
	Exec                    string
	Args                    []string
	WorkDir                 string
	Description             string
	DisplayName             string
	DisableAutostart        bool
	DisableRestartOnFailure bool
}

// Plan is a dry-run description of what would be executed on the target OS.
// It is used for unit tests without requiring privileges.
type Plan struct {
	OS          string
	DryRun      bool
	Privileged  bool
	Actions     []Action
	Warnings    []string
	Rollback    []Action
}

// Action describes a single operation in a Plan.
type Action struct {
	Description string
	Command     []string
	Privileged  bool
	Rollback    []string
}

func newPlan(os string) Plan {
	return Plan{OS: os, DryRun: true, Actions: []Action{}}
}

func (p *Plan) Add(desc string, cmd []string, privileged bool, rollback []string) {
	p.Actions = append(p.Actions, Action{
		Description: desc,
		Command:     cmd,
		Privileged:  privileged,
		Rollback:    rollback,
	})
	if privileged {
		p.Privileged = true
	}
}

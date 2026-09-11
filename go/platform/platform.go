// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package platform provides OS-specific adapters (NTV-06, NTV-07, GWY-02).
//
// It corresponds to the platform layer described in GO_REWRITE_SE.md §7 and
// the per-OS implementations under `go/internal/platform`. This separate
// module (`github.com/EasyTier/EasyTier/go/platform`) houses the
// Linux, macOS, FreeBSD, Android adapters for TUN, routes, DNS, services,
// and driver packaging with dry-run planners for unit tests and privileged
// integration for native execution.
package platform

import (
	"errors"
	"runtime"
)

const (
	ModuleName = "github.com/EasyTier/EasyTier/go/platform"
	Version    = "2.6.4"
)

var (
	ErrUnsupported        = errors.New("platform adapter not implemented for " + runtime.GOOS)
	ErrInvalidConfig      = errors.New("invalid platform configuration")
	ErrInvalidMTU         = errors.New("invalid MTU")
	ErrOneActiveTUN       = errors.New("Android VpnService allows only one active TUN")
	ErrRequiresPrivileged = errors.New("operation requires privileged execution")
)

// Adapter is the common interface implemented by per-OS adapters.
type Adapter interface {
	OS() string
	Version() string
	Supported() bool
	IsPrivileged() bool
	PlanTun(cfg TunConfig) (Plan, error)
	PlanRoutes(cfg RouteConfig) (Plan, error)
	PlanDNS(cfg DNSConfig) (Plan, error)
	PlanService(cfg ServiceConfig) (Plan, error)
	ApplyTun(cfg TunConfig) error
	ApplyRoutes(cfg RouteConfig) error
	ApplyDNS(cfg DNSConfig) error
	ApplyService(cfg ServiceConfig) error
}

// BaseAdapter implements common fields.
type BaseAdapter struct {
	os string
}

func (b *BaseAdapter) OS() string         { return b.os }
func (b *BaseAdapter) Version() string    { return Version }
func (b *BaseAdapter) IsPrivileged() bool { return isPrivileged() }

// New returns an adapter for the current runtime.GOOS.
func New() Adapter {
	return NewForOS(runtime.GOOS)
}

// NewForOS returns an adapter for the given OS string, enabling dry-run tests
// on any host (planner does not require native privileges).
func NewForOS(os string) Adapter {
	switch os {
	case "linux":
		return &LinuxAdapter{BaseAdapter: BaseAdapter{os: os}}
	case "darwin":
		return &DarwinAdapter{BaseAdapter: BaseAdapter{os: os}}
	case "freebsd":
		return &FreeBSDAdapter{BaseAdapter: BaseAdapter{os: os}}
	case "windows":
		return &WindowsAdapter{BaseAdapter: BaseAdapter{os: os}}
	case "android":
		return &AndroidAdapter{BaseAdapter: BaseAdapter{os: os}}
	case "ohos", "openharmony", "harmonyos":
		return NewOHOSAdapter()
	default:
		return &GenericAdapter{BaseAdapter: BaseAdapter{os: os}}
	}
}

// GenericAdapter handles unsupported OS.
type GenericAdapter struct{ BaseAdapter }

func (a *GenericAdapter) Supported() bool { return false }
func (a *GenericAdapter) PlanTun(cfg TunConfig) (Plan, error) {
	return Plan{}, ErrUnsupported
}
func (a *GenericAdapter) PlanRoutes(cfg RouteConfig) (Plan, error) {
	return Plan{}, ErrUnsupported
}
func (a *GenericAdapter) PlanDNS(cfg DNSConfig) (Plan, error) {
	return Plan{}, ErrUnsupported
}
func (a *GenericAdapter) PlanService(cfg ServiceConfig) (Plan, error) {
	return Plan{}, ErrUnsupported
}
func (a *GenericAdapter) ApplyTun(cfg TunConfig) error         { return ErrUnsupported }
func (a *GenericAdapter) ApplyRoutes(cfg RouteConfig) error    { return ErrUnsupported }
func (a *GenericAdapter) ApplyDNS(cfg DNSConfig) error         { return ErrUnsupported }
func (a *GenericAdapter) ApplyService(cfg ServiceConfig) error { return ErrUnsupported }

// isPrivileged reports whether the current process has elevated privileges.
// On Unix, uid 0 is considered privileged. On other platforms, it checks for
// administrative capabilities. Used for privileged integration tests.
func isPrivileged() bool {
	return isPrivilegedImpl()
}

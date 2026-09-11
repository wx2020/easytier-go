// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package instance manages the lifecycle of named EasyTier instances.
package instance

import (
	"context"
	"errors"
	"sort"
	"sync"
)

var (
	// ErrInstanceExists indicates an instance name is already registered.
	ErrInstanceExists = errors.New("instance already exists")
	// ErrInstanceNotFound indicates no running or startable instance has the name.
	ErrInstanceNotFound = errors.New("instance not found")
	// ErrNilInstance indicates an attempt to register a nil instance.
	ErrNilInstance = errors.New("instance is nil")
)

// Instance is a named unit whose lifecycle is owned by an InstanceManager.
type Instance interface {
	ID() string
	Name() string
	Start(context.Context) error
	Close() error
}

// InstanceManager owns instances keyed by their names.
type InstanceManager struct {
	mu        sync.RWMutex
	instances map[string]*managedInstance
}

type instanceState uint8

const (
	instanceAdded instanceState = iota
	instanceStarting
	instanceStarted
	instanceStopped
	instanceStopping
)

type managedInstance struct {
	instance Instance
	name     string

	mu          sync.Mutex
	state       instanceState
	startDone   chan struct{}
	startErr    error
	startCancel context.CancelFunc
	closeOnce   sync.Once
	closeErr    error
}

// Status is a point-in-time lifecycle snapshot.
type Status struct {
	ID      string
	Name    string
	Running bool
	State   string
}

// NewInstanceManager creates an empty instance manager.
func NewInstanceManager() *InstanceManager {
	return &InstanceManager{instances: make(map[string]*managedInstance)}
}

// Add registers an instance without starting it.
func (m *InstanceManager) Add(instance Instance) error {
	if instance == nil {
		return ErrNilInstance
	}

	name := instance.Name()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.instances == nil {
		m.instances = make(map[string]*managedInstance)
	}
	if _, exists := m.instances[name]; exists {
		return ErrInstanceExists
	}
	m.instances[name] = &managedInstance{instance: instance, name: name, state: instanceAdded}
	return nil
}

// Start starts the named instance. Concurrent calls wait for the first start.
func (m *InstanceManager) Start(ctx context.Context, name string) error {
	if ctx == nil {
		return errors.New("instance start context is nil")
	}
	m.mu.RLock()
	managed := m.instances[name]
	m.mu.RUnlock()
	if managed == nil {
		return ErrInstanceNotFound
	}

	managed.mu.Lock()
	switch managed.state {
	case instanceStarted:
		managed.mu.Unlock()
		return nil
	case instanceStopped:
		managed.state = instanceStarting
		managed.startDone = make(chan struct{})
		managed.closeOnce = sync.Once{}
		managed.closeErr = nil
	case instanceStopping:
		managed.mu.Unlock()
		return ErrInstanceNotFound
	case instanceStarting:
		done := managed.startDone
		managed.mu.Unlock()
		select {
		case <-done:
			managed.mu.Lock()
			err := managed.startErr
			managed.mu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case instanceAdded:
		managed.state = instanceStarting
		managed.startDone = make(chan struct{})
		managed.closeOnce = sync.Once{}
		managed.closeErr = nil
	}
	startCtx, cancel := context.WithCancel(ctx)
	managed.startCancel = cancel
	managed.mu.Unlock()

	err := managed.instance.Start(startCtx)
	cancel()
	managed.mu.Lock()
	managed.startErr = err
	managed.startCancel = nil
	cleanup := err != nil && managed.state != instanceStopping
	if err == nil && managed.state == instanceStarting {
		managed.state = instanceStarted
	}
	if cleanup {
		managed.state = instanceStopping
	}
	close(managed.startDone)
	managed.mu.Unlock()

	if cleanup {
		_ = managed.close()
		m.remove(managed)
	}
	return err
}

// Stop closes the named instance while retaining its registration. Stopping an
// absent instance is a successful no-op.
func (m *InstanceManager) Stop(name string) error {
	m.mu.RLock()
	managed := m.instances[name]
	m.mu.RUnlock()
	if managed == nil {
		return nil
	}

	managed.mu.Lock()
	if managed.state == instanceStarting {
		if managed.startCancel != nil {
			managed.startCancel()
		}
		done := managed.startDone
		managed.mu.Unlock()
		<-done
		managed.mu.Lock()
	}
	if managed.state != instanceStopping {
		managed.state = instanceStopping
	}
	managed.mu.Unlock()

	err := managed.close()
	managed.mu.Lock()
	if managed.state == instanceStopping {
		managed.state = instanceStopped
	}
	managed.mu.Unlock()
	return err
}

// Get returns a registered instance that is not being stopped.
func (m *InstanceManager) Get(name string) (Instance, bool) {
	m.mu.RLock()
	managed := m.instances[name]
	m.mu.RUnlock()
	if managed == nil {
		return nil, false
	}

	managed.mu.Lock()
	defer managed.mu.Unlock()
	if managed.state == instanceStopping {
		return nil, false
	}
	return managed.instance, true
}

// List returns registered instances sorted by name.
func (m *InstanceManager) List() []Instance {
	m.mu.RLock()
	managed := make([]*managedInstance, 0, len(m.instances))
	for _, item := range m.instances {
		managed = append(managed, item)
	}
	m.mu.RUnlock()

	sort.Slice(managed, func(i, j int) bool {
		return managed[i].name < managed[j].name
	})
	instances := make([]Instance, 0, len(managed))
	for _, item := range managed {
		item.mu.Lock()
		if item.state != instanceStopping {
			instances = append(instances, item.instance)
		}
		item.mu.Unlock()
	}
	return instances
}

// Statuses returns lifecycle snapshots sorted by name.
func (m *InstanceManager) Statuses() []Status {
	m.mu.RLock()
	managed := make([]*managedInstance, 0, len(m.instances))
	for _, item := range m.instances {
		managed = append(managed, item)
	}
	m.mu.RUnlock()
	sort.Slice(managed, func(i, j int) bool { return managed[i].name < managed[j].name })
	statuses := make([]Status, 0, len(managed))
	for _, item := range managed {
		item.mu.Lock()
		state := "added"
		running := false
		switch item.state {
		case instanceStarting:
			state = "starting"
		case instanceStarted:
			state, running = "running", true
		case instanceStopped:
			state = "stopped"
		case instanceStopping:
			state = "stopping"
		}
		statuses = append(statuses, Status{ID: item.instance.ID(), Name: item.name, Running: running, State: state})
		item.mu.Unlock()
	}
	return statuses
}

// CloseAll closes and removes every instance registered when it is called.
func (m *InstanceManager) CloseAll() error {
	m.mu.RLock()
	managed := make([]*managedInstance, 0, len(m.instances))
	for _, item := range m.instances {
		managed = append(managed, item)
	}
	m.mu.RUnlock()

	var errs []error
	for _, item := range managed {
		item.mu.Lock()
		if item.state == instanceStarting && item.startCancel != nil {
			item.startCancel()
		}
		item.state = instanceStopping
		done := item.startDone
		item.mu.Unlock()
		if done != nil {
			<-done
		}
		if err := item.close(); err != nil {
			errs = append(errs, err)
		}
		m.remove(item)
	}
	return errors.Join(errs...)
}

func (m *InstanceManager) remove(managed *managedInstance) {
	m.mu.Lock()
	if m.instances[managed.name] == managed {
		delete(m.instances, managed.name)
	}
	m.mu.Unlock()
}

func (m *managedInstance) close() error {
	m.closeOnce.Do(func() {
		m.closeErr = m.instance.Close()
	})
	return m.closeErr
}

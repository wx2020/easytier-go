// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package instance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestInstanceManagerLifecycle(t *testing.T) {
	manager := NewInstanceManager()
	alpha := &testInstance{id: "1", name: "alpha"}
	beta := &testInstance{id: "2", name: "beta"}
	if err := manager.Add(beta); err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(alpha); err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(&testInstance{name: "alpha"}); !errors.Is(err, ErrInstanceExists) {
		t.Fatalf("Add duplicate error = %v, want %v", err, ErrInstanceExists)
	}

	listed := manager.List()
	if len(listed) != 2 || listed[0].Name() != "alpha" || listed[1].Name() != "beta" {
		t.Fatalf("List() = %#v", listed)
	}
	got, ok := manager.Get("alpha")
	if !ok || got != alpha {
		t.Fatalf("Get(alpha) = %v, %t", got, ok)
	}
	if err := manager.Start(context.Background(), "alpha"); err != nil {
		t.Fatal(err)
	}
	if starts := alpha.starts(); starts != 1 {
		t.Fatalf("Start calls = %d, want 1", starts)
	}
	if err := manager.Stop("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Stop("alpha"); err != nil {
		t.Fatal(err)
	}
	if closes := alpha.closes(); closes != 1 {
		t.Fatalf("Close calls = %d, want 1", closes)
	}
	if _, ok := manager.Get("alpha"); !ok {
		t.Fatal("stopped instance is no longer registered")
	}
	if err := manager.Add(&testInstance{name: "alpha"}); !errors.Is(err, ErrInstanceExists) {
		t.Fatalf("Add stopped duplicate error = %v, want %v", err, ErrInstanceExists)
	}
	if err := manager.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if closes := beta.closes(); closes != 1 {
		t.Fatalf("CloseAll Close calls = %d, want 1", closes)
	}
}

func TestStoppedInstanceCanBeStartedAgain(t *testing.T) {
	manager := NewInstanceManager()
	item := &testInstance{id: "1", name: "restart"}
	if err := manager.Add(item); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background(), item.Name()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Stop(item.Name()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background(), item.Name()); err != nil {
		t.Fatal(err)
	}
	if starts := item.starts(); starts != 2 {
		t.Fatalf("Start calls = %d, want 2", starts)
	}
	if state := manager.Statuses()[0].State; state != "running" {
		t.Fatalf("state = %q, want running", state)
	}
	if err := manager.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if closes := item.closes(); closes != 2 {
		t.Fatalf("Close calls = %d, want 2", closes)
	}
}

func TestCloseAllCancelsAnInFlightStart(t *testing.T) {
	manager := NewInstanceManager()
	item := &blockingInstance{testInstance: testInstance{id: "1", name: "blocked"}, started: make(chan struct{})}
	if err := manager.Add(item); err != nil {
		t.Fatal(err)
	}
	startResult := make(chan error, 1)
	go func() { startResult <- manager.Start(context.Background(), item.Name()) }()
	select {
	case <-item.started:
	case <-time.After(time.Second):
		t.Fatal("instance did not start")
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- manager.CloseAll() }()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseAll did not finish")
	}
	if err := <-startResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Start error = %v, want context cancellation", err)
	}
	if item.closes() != 1 || len(manager.List()) != 0 {
		t.Fatalf("instance cleanup = closes %d, list %#v", item.closes(), manager.List())
	}
}

func TestStartFailureClosesAndRemovesInstance(t *testing.T) {
	manager := NewInstanceManager()
	startErr := errors.New("start failed")
	failed := &testInstance{name: "failed", startErr: startErr}
	if err := manager.Add(failed); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background(), "failed"); !errors.Is(err, startErr) {
		t.Fatalf("Start error = %v, want %v", err, startErr)
	}
	if closes := failed.closes(); closes != 1 {
		t.Fatalf("Close calls = %d, want 1", closes)
	}
	if _, ok := manager.Get("failed"); ok {
		t.Fatal("failed instance is still registered")
	}
	if len(manager.List()) != 0 {
		t.Fatalf("List() = %#v, want empty", manager.List())
	}
	if err := manager.Add(&testInstance{name: "failed"}); err != nil {
		t.Fatalf("Add replacement after failed start: %v", err)
	}
}

func TestListIsSafeDuringConcurrentLifecycleChanges(t *testing.T) {
	manager := NewInstanceManager()
	const count = 64
	instances := make([]*testInstance, count)
	for i := range instances {
		instances[i] = &testInstance{name: fmt.Sprintf("instance-%03d", i)}
	}

	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i, item := range instances {
		wg.Add(1)
		go func(i int, item *testInstance) {
			defer wg.Done()
			if err := manager.Add(item); err != nil {
				errs <- err
				return
			}
			if i%2 == 0 {
				if err := manager.Stop(item.Name()); err != nil {
					errs <- err
				}
			}
		}(i, item)
	}
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < count; j++ {
				listed := manager.List()
				for k := 1; k < len(listed); k++ {
					if listed[k-1].Name() > listed[k].Name() {
						errs <- errors.New("List returned unsorted instances")
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

type testInstance struct {
	id       string
	name     string
	startErr error

	mu         sync.Mutex
	startCalls int
	closeCalls int
}

type blockingInstance struct {
	testInstance
	started chan struct{}
}

func (i *blockingInstance) Start(ctx context.Context) error {
	close(i.started)
	<-ctx.Done()
	return ctx.Err()
}

func (i *testInstance) ID() string {
	return i.id
}

func (i *testInstance) Name() string {
	return i.name
}

func (i *testInstance) Start(context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.startCalls++
	return i.startErr
}

func (i *testInstance) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.closeCalls++
	return nil
}

func (i *testInstance) starts() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.startCalls
}

func (i *testInstance) closes() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.closeCalls
}

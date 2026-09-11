// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package forward

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestManagerRejectsBadAndDuplicateRules(t *testing.T) {
	manager := NewManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })

	for _, rule := range []Rule{
		{Bind: "0.0.0.0:8080", Destination: "127.0.0.1:8081"},
		{Bind: "127.0.0.1:0", Destination: "127.0.0.1:8081"},
		{Bind: "127.0.0.1:8080", Destination: "127.0.0.1:0"},
		{Bind: "127.0.0.1:8080", Destination: "not a host:8081"},
	} {
		if err := manager.Add(rule); !errors.Is(err, ErrInvalidRule) {
			t.Errorf("Add(%+v) error = %v, want invalid rule", rule, err)
		}
	}

	rule := Rule{Bind: unusedLoopbackAddress(t), Destination: "127.0.0.1:8081"}
	if err := manager.Add(rule); err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(Rule{Bind: rule.Bind, Destination: "127.0.0.1:8082"}); !errors.Is(err, ErrDuplicateRule) {
		t.Fatalf("duplicate Add error = %v, want duplicate rule", err)
	}
}

func TestManagerListsSortedRulesAndRemovesByRule(t *testing.T) {
	manager := NewManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })

	first := Rule{Bind: unusedLoopbackAddress(t), Destination: "127.0.0.1:9101"}
	second := Rule{Bind: unusedLoopbackAddress(t), Destination: "127.0.0.1:9102"}
	if first.Bind < second.Bind {
		first, second = second, first
	}
	if err := manager.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(second); err != nil {
		t.Fatal(err)
	}

	want := []Rule{second, first}
	if got := manager.List(); !reflect.DeepEqual(got, want) {
		t.Fatalf("List() = %+v, want %+v", got, want)
	}
	if err := manager.Remove(first); err != nil {
		t.Fatal(err)
	}
	if got := manager.List(); !reflect.DeepEqual(got, []Rule{second}) {
		t.Fatalf("List after Remove = %+v, want %+v", got, []Rule{second})
	}
	if err := manager.Remove(first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Remove error = %v, want not found", err)
	}
}

func TestManagerForwardsAndPreservesHalfClose(t *testing.T) {
	backend := startEchoServer(t)
	manager := NewManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })

	rule := Rule{Bind: unusedLoopbackAddress(t), Destination: backend.Addr().String()}
	if err := manager.Add(rule); err != nil {
		t.Fatal(err)
	}

	connection, err := net.Dial("tcp", rule.Bind)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}
	if err := connection.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(connection)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "echo" {
		t.Fatalf("forwarded response = %q, want %q", got, "echo")
	}
}

func TestManagerContextCancellationStopsListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	manager := NewManager(ctx)
	rule := Rule{Bind: unusedLoopbackAddress(t), Destination: "127.0.0.1:9999"}
	if err := manager.Add(rule); err != nil {
		t.Fatal(err)
	}
	cancel()

	deadline := time.Now().Add(time.Second)
	for {
		connection, err := net.DialTimeout("tcp", rule.Bind, 20*time.Millisecond)
		if err != nil {
			break
		}
		_ = connection.Close()
		if time.Now().After(deadline) {
			t.Fatal("listener remained reachable after context cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := manager.Add(Rule{Bind: unusedLoopbackAddress(t), Destination: "127.0.0.1:9999"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Add after cancellation error = %v, want closed", err)
	}
}

func TestManagerStatusReportsLiveListener(t *testing.T) {
	manager := NewManager(context.Background())
	t.Cleanup(func() { _ = manager.Close() })
	rule := Rule{Bind: unusedLoopbackAddress(t), Destination: "127.0.0.1:9999"}
	if err := manager.Add(rule); err != nil {
		t.Fatal(err)
	}
	statuses := manager.Statuses()
	if len(statuses) != 1 || statuses[0].Rule != rule || statuses[0].State != "listening" || statuses[0].ActiveConnections != 0 {
		t.Fatalf("statuses = %#v", statuses)
	}
	connection, err := net.Dial("tcp", rule.Bind)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	deadline := time.Now().Add(time.Second)
	for {
		statuses = manager.Statuses()
		if statuses[0].Accepted >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("accepted connection was not observed: %#v", statuses)
		}
		time.Sleep(time.Millisecond)
	}
}

func unusedLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener
}

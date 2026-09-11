// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAllowUsesBurstAndRefillsAtSuppliedTimes(t *testing.T) {
	limiter, err := New(10, 20)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	for _, test := range []struct {
		n    int64
		at   time.Time
		want bool
	}{
		{n: 20, at: start, want: true},
		{n: 1, at: start, want: false},
		{n: 9, at: start.Add(900 * time.Millisecond), want: true},
		{n: 2, at: start.Add(time.Second), want: false},
		{n: 11, at: start.Add(2 * time.Second), want: true},
		{n: 21, at: start.Add(10 * time.Second), want: false},
	} {
		if got := limiter.Allow(test.n, test.at); got != test.want {
			t.Fatalf("Allow(%d, %v) = %t; want %t", test.n, test.at, got, test.want)
		}
	}
}

func TestAllowDoesNotRefillWhenTimeMovesBackward(t *testing.T) {
	limiter, err := New(10, 10)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	if !limiter.Allow(10, start) {
		t.Fatal("initial burst was not allowed")
	}
	if !limiter.Allow(5, start.Add(time.Second)) {
		t.Fatal("refilled tokens were not allowed")
	}
	if limiter.Allow(6, start.Add(500*time.Millisecond)) {
		t.Fatal("backward time refilled tokens")
	}
}

func TestUnlimitedAllowsAnyNonNegativeRequest(t *testing.T) {
	limiter, err := New(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !limiter.Allow(1<<62, time.Time{}) {
		t.Fatal("unlimited limiter rejected request")
	}
	if limiter.Allow(-1, time.Time{}) {
		t.Fatal("limiter accepted negative request")
	}
}

func TestNewValidatesConfiguration(t *testing.T) {
	for _, test := range []struct {
		rate, burst int64
		want        error
	}{
		{rate: -1, burst: 1, want: ErrInvalidRate},
		{rate: 1, burst: -1, want: ErrInvalidBurst},
	} {
		if _, err := New(test.rate, test.burst); !errors.Is(err, test.want) {
			t.Fatalf("New(%d, %d) error = %v; want %v", test.rate, test.burst, err, test.want)
		}
	}
}

func TestWaitValidatesRequest(t *testing.T) {
	limiter, err := New(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := limiter.Wait(context.Background(), -1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Wait() error = %v; want %v", err, ErrInvalidRequest)
	}
	if err := limiter.Wait(context.Background(), 2); !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("Wait() error = %v; want %v", err, ErrRequestTooLarge)
	}
}

func TestWaitHonorsContextDeadline(t *testing.T) {
	limiter, err := New(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := limiter.Wait(context.Background(), 1); err != nil {
		t.Fatalf("initial Wait() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := limiter.Wait(ctx, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait() error = %v; want context deadline exceeded", err)
	}
}

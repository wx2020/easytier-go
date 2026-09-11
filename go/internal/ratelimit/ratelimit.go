// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package ratelimit provides byte-based token bucket rate limiting.
package ratelimit

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

var (
	ErrInvalidRate     = errors.New("rate must not be negative")
	ErrInvalidBurst    = errors.New("burst must not be negative")
	ErrInvalidRequest  = errors.New("request size must not be negative")
	ErrRequestTooLarge = errors.New("request size exceeds burst")
	ErrNilContext      = errors.New("context must not be nil")
)

// Limiter limits byte consumption using a token bucket.
type Limiter struct {
	rate  int64
	burst int64

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// New returns a limiter initially filled to its burst capacity.
func New(rate, burst int64) (*Limiter, error) {
	if rate < 0 {
		return nil, ErrInvalidRate
	}
	if burst < 0 {
		return nil, ErrInvalidBurst
	}
	return &Limiter{rate: rate, burst: burst, tokens: float64(burst)}, nil
}

// Allow reports whether n bytes can be consumed at t.
func (l *Limiter) Allow(n int64, t time.Time) bool {
	if n < 0 {
		return false
	}
	if l.rate == 0 {
		return true
	}
	if n > l.burst {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.refill(t)
	if l.tokens < float64(n) {
		return false
	}
	l.tokens -= float64(n)
	return true
}

// Wait blocks until n bytes can be consumed or ctx is canceled.
func (l *Limiter) Wait(ctx context.Context, n int64) error {
	if ctx == nil {
		return ErrNilContext
	}
	if n < 0 {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.rate == 0 {
		return nil
	}
	if n > l.burst {
		return ErrRequestTooLarge
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		l.refill(time.Now())
		if l.tokens >= float64(n) {
			l.tokens -= float64(n)
			l.mu.Unlock()
			return nil
		}
		delay := timeUntil(float64(n)-l.tokens, l.rate)
		l.mu.Unlock()

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *Limiter) refill(t time.Time) {
	if l.last.IsZero() {
		l.last = t
		return
	}
	if !t.After(l.last) {
		return
	}
	l.tokens = min(float64(l.burst), l.tokens+t.Sub(l.last).Seconds()*float64(l.rate))
	l.last = t
}

func timeUntil(tokens float64, rate int64) time.Duration {
	nanoseconds := math.Ceil(tokens * float64(time.Second) / float64(rate))
	if nanoseconds >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	if nanoseconds < 1 {
		return time.Nanosecond
	}
	return time.Duration(nanoseconds)
}

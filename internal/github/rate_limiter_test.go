package github

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCheckCoreRateLimitHonorsContextCancellation(t *testing.T) {
	limiter := NewRateLimiter(500)
	limiter.coreRemaining = 0
	limiter.coreReset = time.Now().Add(time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := limiter.CheckCoreRateLimit(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation error, got %v", err)
	}
}

func TestSleepWithContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sleepWithContext(ctx, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation error, got %v", err)
	}
}

package notify

import (
	"math/rand/v2"
	"time"
)

const (
	backoffFactor = 2.0
	backoffJitter = 0.5
)

type backoff struct {
	current  time.Duration
	maxDelay time.Duration
}

func newBackoff(initial, maxDelay time.Duration) *backoff {
	return &backoff{current: initial, maxDelay: maxDelay}
}

func (b *backoff) next() time.Duration {
	delay := b.current
	b.current = min(time.Duration(float64(b.current)*backoffFactor), b.maxDelay)
	if delay > 0 {
		delay += time.Duration(rand.Int64N(int64(float64(delay) * backoffJitter))) //nolint:gosec // retry jitter is not security-sensitive
	}
	return delay
}

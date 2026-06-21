package obfuscation

import (
	"net/http"
	"testing"
	"time"
)

func TestExtractClientIPIgnoresForwardedHeaders(t *testing.T) {
	r := &http.Request{
		Header:     http.Header{},
		RemoteAddr: "203.0.113.5:4444",
	}
	// Spoofed headers must NOT override the real transport peer.
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")

	if got := extractClientIP(r); got != "203.0.113.5" {
		t.Errorf("extractClientIP = %q, want 203.0.113.5 (RemoteAddr); headers must be ignored", got)
	}
}

func TestRateLimiterPruneLocked(t *testing.T) {
	rl := newRateLimiter(&RateLimitConfig{RequestsPerSecond: 1, BurstSize: 5, BlockDuration: time.Minute})
	now := time.Now()

	rl.buckets["full"] = &bucket{tokens: 5, lastTime: now}    // full -> evicted
	rl.buckets["partial"] = &bucket{tokens: 2, lastTime: now} // in use -> kept
	rl.blocked["expired"] = now.Add(-time.Minute)             // expired -> evicted
	rl.blocked["active"] = now.Add(time.Minute)               // active -> kept

	rl.pruneLocked(now)

	if _, ok := rl.buckets["full"]; ok {
		t.Error("full bucket should be evicted")
	}
	if _, ok := rl.buckets["partial"]; !ok {
		t.Error("in-use bucket should be kept")
	}
	if _, ok := rl.blocked["expired"]; ok {
		t.Error("expired block should be evicted")
	}
	if _, ok := rl.blocked["active"]; !ok {
		t.Error("active block should be kept")
	}
}

func TestPaddingRandomModeBadConfigNoPanic(t *testing.T) {
	// MaxPadding < MinPadding must not panic rng.Intn.
	p := NewPadder(&PaddingConfig{Enabled: true, Mode: "random", MinPadding: 100, MaxPadding: 10})
	_ = p.Pad([]byte("hello")) // would panic before the guard
}

func TestDecoyIntervalEqualBoundsNoPanic(t *testing.T) {
	// MinInterval == MaxInterval must not panic rng.Int63n.
	d := NewDecoyGenerator(&DecoyConfig{
		Enabled:     true,
		MinInterval: time.Second,
		MaxInterval: time.Second,
		MinSize:     64,
		MaxSize:     64,
	}, nil)
	_ = d.nextInterval() // would panic before the guard
}

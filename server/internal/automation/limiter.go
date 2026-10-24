package automation

import (
	"sync"
	"time"
)

// window is an in-memory sliding-window counter keyed by string. Unlike auth.Limiter it can count without recording
// (the per-address failure throttle is checked before a credential is verified, and only failures are recorded) and
// it says how long until the next slot frees up (Retry-After).
type window struct {
	mu   sync.Mutex
	max  int
	dur  time.Duration
	hits map[string][]time.Time
}

func newWindow(max int, dur time.Duration) *window {
	return &window{max: max, dur: dur, hits: map[string][]time.Time{}}
}

// prune drops expired hits for key and returns what is left. Callers hold w.mu.
func (w *window) prune(key string, now time.Time) []time.Time {
	cut := now.Add(-w.dur)
	h := w.hits[key]
	i := 0
	for i < len(h) && !h[i].After(cut) {
		i++
	}
	h = h[i:]
	if len(h) == 0 {
		delete(w.hits, key)
		return nil
	}
	w.hits[key] = h
	return h
}

func (w *window) gc(now time.Time) {
	if len(w.hits) < 10000 { // bound memory under a spray of distinct keys
		return
	}
	for k := range w.hits {
		w.prune(k, now)
	}
	if len(w.hits) >= 10000 {
		w.hits = map[string][]time.Time{}
	}
}

// full reports whether key has used all its slots, and when the oldest one frees up.
func (w *window) full(key string) (bool, time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	h := w.prune(key, now)
	if len(h) < w.max {
		return false, 0
	}
	return true, h[0].Add(w.dur).Sub(now)
}

// add records one hit.
func (w *window) add(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	w.gc(now)
	w.prune(key, now)
	w.hits[key] = append(w.hits[key], now)
}

// take records a hit if there is room. When there is none it returns false and the wait.
func (w *window) take(key string) (bool, time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	w.gc(now)
	h := w.prune(key, now)
	if len(h) >= w.max {
		return false, h[0].Add(w.dur).Sub(now)
	}
	w.hits[key] = append(h, now)
	return true, 0
}

// retrySeconds turns a wait into a Retry-After value (whole seconds, at least 1).
func retrySeconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	if s < 1 {
		return 1
	}
	return s
}

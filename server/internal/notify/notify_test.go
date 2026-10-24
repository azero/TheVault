// Vendored from OmniCore reference/go/notify; change upstream, not here.

package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type beacon struct {
	mu       sync.Mutex
	messages []map[string]any
	catalog  map[string]any
	fail     int // answer 503 this many times before accepting
	auth     string
}

func (b *beacon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.auth = r.Header.Get("Authorization")
	body, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	switch {
	case r.Method == "PUT" && r.URL.Path == "/api/v1/sources/cortex":
		b.catalog = m
		w.WriteHeader(200)
	case r.Method == "POST" && r.URL.Path == "/api/v1/messages":
		if b.fail > 0 {
			b.fail--
			w.WriteHeader(503)
			return
		}
		if m["subject"] == "bad" {
			w.WriteHeader(422)
			return
		}
		b.messages = append(b.messages, m)
		w.WriteHeader(202)
	default:
		w.WriteHeader(404)
	}
}

func (b *beacon) count() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.messages) }

func cfg(url string) Config {
	return Config{URL: url, Key: "id.secret", Source: "cortex", Title: "Cortex",
		Categories: []Category{{ID: "assigned", Title: "Assigned to you", Level: Notice}, {ID: "login", Title: "Security", Level: Critical, Mandatory: true}, {ID: "fyi", Title: "FYI", Level: Info}},
		Backoffs:   []time.Duration{5 * time.Millisecond, 5 * time.Millisecond}}
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestNilIsSafe(t *testing.T) {
	var n *Notifier
	if n.Notify(Event{}) {
		t.Fatal("nil notifier accepted an event")
	}
	n.Run(context.Background())
	if New(Config{}) != nil {
		t.Fatal("unconfigured notifier must be nil")
	}
}

func TestSendAndCatalog(t *testing.T) {
	b := &beacon{}
	srv := httptest.NewServer(b)
	defer srv.Close()
	n := New(cfg(srv.URL))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	if !n.Notify(Event{Category: "assigned", To: []Recipient{{User: "u1"}, {Group: "admins"}}, Title: "Card CX-1", Body: "Ana assigned you", URL: "https://cortex.example.com/c/1", IdempotencyKey: "assign-1"}) {
		t.Fatal("not accepted")
	}
	waitFor(t, func() bool { return b.count() == 1 })
	m := b.messages[0]
	if m["source"] != "cortex" || m["category"] != "assigned" || m["level"] != "notice" || m["priority"] != "normal" || m["idempotency_key"] != "cortex:assign-1" {
		t.Fatalf("message %v", m)
	}
	if b.auth != "Bearer id.secret" {
		t.Fatalf("auth %q", b.auth)
	}
	to := m["to"].([]any)
	if to[0].(map[string]any)["user"] != "u1" || to[1].(map[string]any)["group"] != "admins" {
		t.Fatalf("to %v", to)
	}
	waitFor(t, func() bool { _, _, reg := n.Stats(); return reg })
	if cats := b.catalog["categories"].([]any); len(cats) != 3 {
		t.Fatalf("catalog %v", b.catalog)
	}
}

func TestRetryDropAndFloor(t *testing.T) {
	b := &beacon{fail: 2}
	srv := httptest.NewServer(b)
	defer srv.Close()
	c := cfg(srv.URL)
	c.MinLevel = Important
	n := New(c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	if n.Notify(Event{Category: "fyi", To: []Recipient{{User: "u"}}, Title: "x"}) {
		t.Error("below the floor must not be sent")
	}
	if n.Notify(Event{Category: "nope", To: []Recipient{{User: "u"}}, Title: "x"}) {
		t.Error("unknown category accepted")
	}
	if n.Notify(Event{Category: "assigned", Title: "no recipients"}) {
		t.Error("event without recipients accepted")
	}
	if !n.Notify(Event{Category: "login", To: []Recipient{{User: "u"}}, Title: "new sign-in", Level: Critical}) {
		t.Fatal("mandatory event refused")
	}
	waitFor(t, func() bool { return b.count() == 1 }) // survived two 503s
	if b.messages[0]["priority"] != "critical" {
		t.Errorf("priority %v", b.messages[0]["priority"])
	}
	// A permanent rejection is dropped, not retried forever.
	n.Notify(Event{Category: "login", To: []Recipient{{User: "u"}}, Title: "bad"})
	waitFor(t, func() bool { _, d, _ := n.Stats(); return d == 1 })
}

func TestNeverBlocks(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	c := cfg(slow.URL)
	c.QueueSize = 2
	n := New(c) // Run is never started: the queue fills up and Notify must still return at once
	start := time.Now()
	for i := 0; i < 50; i++ {
		n.Notify(Event{Category: "assigned", To: []Recipient{{User: "u"}}, Title: "x"})
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("Notify blocked")
	}
	if _, dropped, _ := n.Stats(); dropped != 48 {
		t.Fatalf("dropped %d", dropped)
	}
}

func TestEncodeLimits(t *testing.T) {
	n := New(cfg("https://beacon.example.com"))
	b, err := n.encode(Event{Category: "assigned", Level: Notice, To: []Recipient{{User: "u"}}, Title: strings.Repeat("é", 500), Body: strings.Repeat("x", 5000), URL: "javascript:alert(1)"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if len([]rune(m["subject"].(string))) != 120 || len([]rune(m["text"].(string))) != 1000 {
		t.Error("not truncated")
	}
	if _, ok := m["action"]; ok {
		t.Error("non-http URL kept")
	}
}

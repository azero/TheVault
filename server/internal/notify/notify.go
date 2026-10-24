// Vendored from OmniCore reference/go/notify; change upstream, not here.

// Package notify sends an application's notifications to Beacon (the company messaging service) with a
// severity level and a category, so that every person can choose per application (and per kind of
// notification) what they want to hear about. See docs/notifications.md.
//
// Guarantees, like the SkyNet reporter: Notify never blocks and never fails the caller, a Beacon outage never
// affects the application (events are retried a few times in memory and then dropped), and nothing but the
// fields of Event is ever sent. Callers must keep secrets and user content out of those fields.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Level is the severity of an event, and the "at least this" threshold a person chooses.
type Level string

const (
	Info      Level = "info"      // FYI; people who want "everything" see it
	Notice    Level = "notice"    // worth knowing (the default threshold)
	Important Level = "important" // needs attention soon
	Critical  Level = "critical"  // needs action now
)

// Rank orders levels; unknown levels rank 0.
func (l Level) Rank() int {
	switch l {
	case Info:
		return 1
	case Notice:
		return 2
	case Important:
		return 3
	case Critical:
		return 4
	}
	return 0
}

// ParseLevel accepts a level name.
func ParseLevel(s string) (Level, bool) {
	l := Level(strings.ToLower(strings.TrimSpace(s)))
	return l, l.Rank() > 0
}

// DefaultPriority maps a level to the Beacon delivery priority used when an event does not set one.
func (l Level) DefaultPriority() string {
	switch l {
	case Info:
		return "low"
	case Important:
		return "urgent"
	case Critical:
		return "critical"
	}
	return "normal"
}

// Category is one kind of notification the application can send.
type Category struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Level       Level  `json:"level"`               // usual severity; an Event may override it
	Mandatory   bool   `json:"mandatory,omitempty"` // people cannot turn it off (security-critical)
}

// Recipient addresses one person (ClosedDoor sub or e-mail) or a Beacon group. Exactly one field is set.
type Recipient struct {
	User  string // ClosedDoor sub
	Email string // a ClosedDoor user's e-mail
	Group string // Beacon group name
}

type Event struct {
	Category       string
	Level          Level // empty: the category's level
	To             []Recipient
	Title          string // <= 120 chars
	Body           string // <= 1000 chars
	URL            string // where "Open" leads (https)
	ActionLabel    string
	Priority       string // empty: derived from Level
	IdempotencyKey string // stable per real-world event so retries and restarts never double-send
	ExpiresIn      int    // seconds; 0 = Beacon default
	Tags           []string
	Metadata       map[string]string
}

type Config struct {
	URL         string // Beacon base URL, e.g. https://beacon.example.com
	Key         string // API key "<id>.<secret>" with scope send
	Source      string // this application's id, [a-z][a-z0-9-]{1,30}
	Title       string // display name
	Description string
	Categories  []Category
	// MinLevel is an application-wide floor set by the admin (env <APP>_NOTIFY_MIN_LEVEL): events below it are
	// not sent at all, except Mandatory categories. Empty means info (send everything; people decide).
	MinLevel  Level
	HTTP      *http.Client
	Logf      func(format string, args ...any)
	QueueSize int             // default 256
	Backoffs  []time.Duration // retry delays; default 1s, 5s, 30s, 2m
}

// Notifier queues events and delivers them from Run. A nil *Notifier is valid and does nothing, so callers
// need no "is Beacon configured" checks.
type Notifier struct {
	cfg  Config
	hc   *http.Client
	ch   chan queued
	cats map[string]Category

	mu         sync.Mutex
	registered bool
	dropped    int
	sent       int
}

type queued struct {
	body  []byte
	tries int
}

// New returns nil when URL or Key is empty (notifications are then simply off).
func New(cfg Config) *Notifier {
	if cfg.URL == "" || cfg.Key == "" || cfg.Source == "" {
		return nil
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	if len(cfg.Backoffs) == 0 {
		cfg.Backoffs = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second, 2 * time.Minute}
	}
	if cfg.MinLevel.Rank() == 0 {
		cfg.MinLevel = Info
	}
	n := &Notifier{cfg: cfg, hc: cfg.HTTP, ch: make(chan queued, cfg.QueueSize), cats: map[string]Category{}}
	for _, c := range cfg.Categories {
		n.cats[c.ID] = c
	}
	return n
}

// Notify queues an event. It reports whether the event was accepted for sending (false: Beacon is not
// configured, the category is unknown, the level is below the floor, or the queue is full).
func (n *Notifier) Notify(e Event) bool {
	if n == nil {
		return false
	}
	cat, ok := n.cats[e.Category]
	if !ok {
		n.cfg.Logf("notify: unknown category %q (not in the catalog)", e.Category)
		return false
	}
	if e.Level.Rank() == 0 {
		e.Level = cat.Level
	}
	if e.Level.Rank() < n.cfg.MinLevel.Rank() && !cat.Mandatory {
		return false
	}
	body, err := n.encode(e)
	if err != nil {
		n.cfg.Logf("notify: %v", err)
		return false
	}
	select {
	case n.ch <- queued{body: body}:
		return true
	default:
		n.mu.Lock()
		n.dropped++
		n.mu.Unlock()
		return false
	}
}

func (n *Notifier) encode(e Event) ([]byte, error) {
	if len(e.To) == 0 || len(e.To) > 100 {
		return nil, fmt.Errorf("event %q needs 1..100 recipients", e.Category)
	}
	var to []map[string]string
	for _, r := range e.To {
		switch {
		case r.User != "":
			to = append(to, map[string]string{"user": r.User})
		case r.Email != "":
			to = append(to, map[string]string{"user_email": r.Email})
		case r.Group != "":
			to = append(to, map[string]string{"group": r.Group})
		default:
			return nil, fmt.Errorf("event %q has an empty recipient", e.Category)
		}
	}
	prio := e.Priority
	if prio == "" {
		prio = e.Level.DefaultPriority()
	}
	m := map[string]any{
		"to": to, "channels": []string{"auto"}, "priority": prio,
		"source": n.cfg.Source, "category": e.Category, "level": string(e.Level),
		"subject": trunc(e.Title, 120), "text": trunc(e.Body, 1000),
	}
	if u := httpsURL(e.URL); u != "" {
		a := map[string]string{"url": u}
		if e.ActionLabel != "" {
			a["label"] = trunc(e.ActionLabel, 40)
		}
		m["action"] = a
	}
	if e.IdempotencyKey != "" {
		m["idempotency_key"] = n.cfg.Source + ":" + trunc(e.IdempotencyKey, 150)
	}
	if e.ExpiresIn > 0 {
		m["expires_in"] = e.ExpiresIn
	}
	if len(e.Tags) > 0 {
		m["tags"] = e.Tags
	}
	if len(e.Metadata) > 0 {
		m["metadata"] = e.Metadata
	}
	return json.Marshal(m)
}

// Run registers the category catalog with Beacon (retrying until it succeeds) and delivers queued events
// until ctx ends. Start it in its own goroutine.
func (n *Notifier) Run(ctx context.Context) {
	if n == nil {
		return
	}
	go n.register(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-n.ch:
			n.deliver(ctx, q)
		}
	}
}

// Stats returns how many events were sent and dropped (queue overflow or retries exhausted).
func (n *Notifier) Stats() (sent, dropped int, registered bool) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sent, n.dropped, n.registered
}

func (n *Notifier) register(ctx context.Context) {
	body, _ := json.Marshal(map[string]any{"title": n.cfg.Title, "description": n.cfg.Description, "categories": n.cfg.Categories})
	for i := 0; ; i++ {
		status, err := n.do(ctx, http.MethodPut, "/api/v1/sources/"+url.PathEscape(n.cfg.Source), body)
		if err == nil && status/100 == 2 {
			n.mu.Lock()
			n.registered = true
			n.mu.Unlock()
			return
		}
		if err == nil && status/100 == 4 && status != 429 {
			n.cfg.Logf("notify: Beacon refused the catalog for %q (HTTP %d); check the API key's scope and sources", n.cfg.Source, status)
		}
		d := n.cfg.Backoffs[min(i, len(n.cfg.Backoffs)-1)]
		if i > 3 {
			d = 5 * time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
	}
}

func (n *Notifier) deliver(ctx context.Context, q queued) {
	for i := 0; ; i++ {
		status, err := n.do(ctx, http.MethodPost, "/api/v1/messages", q.body)
		switch {
		case err == nil && status/100 == 2:
			n.mu.Lock()
			n.sent++
			n.mu.Unlock()
			return
		case err == nil && status/100 == 4 && status != 429:
			n.cfg.Logf("notify: Beacon rejected a %q event (HTTP %d); dropped", n.cfg.Source, status)
			n.drop()
			return
		}
		if i >= len(n.cfg.Backoffs) {
			n.drop()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(n.cfg.Backoffs[i]):
		}
	}
}

func (n *Notifier) drop() {
	n.mu.Lock()
	n.dropped++
	n.mu.Unlock()
}

func (n *Notifier) do(ctx context.Context, method, path string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, n.cfg.URL+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+n.cfg.Key)
	req.Header.Set("Content-Type", "application/json")
	res, err := n.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	return res.StatusCode, nil
}

func trunc(s string, max int) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "")
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max-1]) + "…"
}

func httpsURL(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return u.String()
}

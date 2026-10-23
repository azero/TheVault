// Package skynet connects TheVault to SkyNet in both directions:
//
//   - out: every audit event is queued in a bounded on-disk outbox and shipped as NDJSON to /api/v1/ingest, so an
//     outage of SkyNet loses nothing (up to the cap) and never slows a request;
//   - in: signed block_ip / unblock_ip commands are verified (Ed25519, pinned key, agent id, expiry, replay) and
//     applied as a deny list that the HTTP layer enforces.
//
// It uses the same wire protocol as SkyNet's PHP adapter.
package skynet

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/store"
)

const (
	outboxMax = 50000
	batchMax  = 500
)

type Config struct {
	URL, Key, EnrollToken, CommandKey, Host, Version, DataDir, Allowlist string
}

type creds struct {
	URL           string `json:"url"`
	APIKey        string `json:"api_key"`
	AgentID       string `json:"agent_id"`
	CommandPubkey string `json:"command_pubkey"`
}

type Client struct {
	cfg  Config
	st   *store.Store
	hc   *http.Client
	cred creds

	queue   chan Event
	dropped atomic.Int64
	wake    chan struct{}

	deny atomic.Pointer[map[string]int64]

	mu       sync.Mutex
	lastSend time.Time
	lastErr  string
	sent     int64
	lastCmd  time.Time
	cmdErr   string
	allow    []cidr
}

// New loads (or obtains, via a one-time enrollment token) the SkyNet credentials and hooks into the auditor.
func New(cfg Config, st *store.Store, a *audit.Auditor) (*Client, error) {
	c := &Client{cfg: cfg, st: st, hc: &http.Client{Timeout: 30 * time.Second}, queue: make(chan Event, 4096), wake: make(chan struct{}, 1)}
	if err := c.loadCreds(); err != nil {
		return nil, err
	}
	var err error
	if c.allow, err = parseAllow(cfg.Allowlist); err != nil {
		return nil, err
	}
	empty := map[string]int64{}
	c.deny.Store(&empty)
	c.refreshDeny(context.Background())
	a.AddSink(func(e audit.Event) { c.Emit(FromAudit(e, cfg.Host, time.Now())) })
	return c, nil
}

func (c *Client) credPath() string { return filepath.Join(c.cfg.DataDir, "keys", "skynet.json") }

func (c *Client) loadCreds() error {
	if b, err := os.ReadFile(c.credPath()); err == nil {
		var cr creds
		if json.Unmarshal(b, &cr) == nil && cr.APIKey != "" && strings.TrimRight(cr.URL, "/") == c.cfg.URL {
			c.cred = cr
			if c.cfg.CommandKey != "" {
				c.cred.CommandPubkey = c.cfg.CommandKey
			}
			return nil
		}
	}
	switch {
	case c.cfg.Key != "":
		c.cred = creds{URL: c.cfg.URL, APIKey: c.cfg.Key, CommandPubkey: c.cfg.CommandKey}
		c.cred.AgentID, _, _ = strings.Cut(c.cfg.Key, ".")
		return nil
	case c.cfg.EnrollToken != "":
		return c.enroll()
	}
	return errors.New("skynet: no credentials")
}

func (c *Client) enroll() error {
	host, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{"token": c.cfg.EnrollToken, "name": c.cfg.Host, "host": c.cfg.Host + "@" + host, "os": "linux", "version": "thevault/" + c.cfg.Version})
	resp, err := c.hc.Post(c.cfg.URL+"/api/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("skynet enroll: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AgentID       string `json:"agent_id"`
		APIKey        string `json:"api_key"`
		CommandPubkey string `json:"command_pubkey"`
		Error         string `json:"error"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out)
	if resp.StatusCode != 200 || out.APIKey == "" {
		return fmt.Errorf("skynet enroll refused (HTTP %d): %s", resp.StatusCode, out.Error)
	}
	c.cred = creds{URL: c.cfg.URL, APIKey: out.APIKey, AgentID: out.AgentID, CommandPubkey: out.CommandPubkey}
	b, _ := json.Marshal(c.cred)
	if err := os.WriteFile(c.credPath(), b, 0o600); err != nil {
		return fmt.Errorf("save skynet credentials: %w", err)
	}
	log.Printf("skynet: enrolled as %s (the one-time token can now be removed from the environment)", out.AgentID)
	return nil
}

// Emit queues an event without ever blocking the caller. When the queue is full the event is dropped and counted.
func (c *Client) Emit(e Event) {
	select {
	case c.queue <- e:
	default:
		c.dropped.Add(1)
	}
}

// Run starts the background loops and returns when ctx ends.
func (c *Client) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, f := range []func(context.Context){c.writer, c.sender, c.heartbeat, c.poller, c.denyJanitor} {
		wg.Add(1)
		go func(f func(context.Context)) { defer wg.Done(); f(ctx) }(f)
	}
	wg.Wait()
}

// writer moves queued events into the outbox in small batches.
func (c *Client) writer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			c.drainQueue()
			return
		case e := <-c.queue:
			c.push(e)
			for i := 0; i < 200; i++ {
				select {
				case e := <-c.queue:
					c.push(e)
				default:
					i = 200
				}
			}
			select {
			case c.wake <- struct{}{}:
			default:
			}
		}
	}
}

func (c *Client) drainQueue() {
	for {
		select {
		case e := <-c.queue:
			c.push(e)
		default:
			return
		}
	}
}

func (c *Client) push(e Event) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	if err := c.st.OutboxPush(context.Background(), string(b), outboxMax); err != nil {
		log.Printf("skynet outbox: %v", err)
	}
}

func (c *Client) sender(ctx context.Context) {
	backoff := time.Second
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.wake:
			time.Sleep(300 * time.Millisecond) // let a burst gather
		}
		for {
			n, err := c.flushOnce(ctx)
			if err != nil {
				c.setErr(err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff = min(backoff*2, 5*time.Minute)
				break
			}
			backoff = time.Second
			if n < batchMax {
				break
			}
		}
	}
}

func (c *Client) setErr(err error) {
	c.mu.Lock()
	c.lastErr = err.Error()
	c.mu.Unlock()
}

// flushOnce sends up to batchMax events. It returns how many were acknowledged.
func (c *Client) flushOnce(ctx context.Context) (int, error) {
	rows, err := c.st.OutboxPeek(ctx, batchMax)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	for _, r := range rows {
		zw.Write([]byte(r.Payload))
		zw.Write([]byte("\n"))
	}
	zw.Close()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cred.URL+"/api/v1/ingest", &buf)
	req.Header.Set("Authorization", "Bearer "+c.cred.APIKey)
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-SkyNet-Version", "thevault/"+c.cfg.Version)
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("send to skynet: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == 200:
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return 0, fmt.Errorf("skynet refused our key (HTTP %d): re-enroll", resp.StatusCode)
	case resp.StatusCode == 413 || resp.StatusCode == 400:
		// a poisoned batch must not block the queue forever: drop it and say so
		log.Printf("skynet: dropping %d events rejected with HTTP %d", len(rows), resp.StatusCode)
	default:
		return 0, fmt.Errorf("skynet answered HTTP %d", resp.StatusCode)
	}
	if err := c.st.OutboxAck(ctx, rows[len(rows)-1].ID); err != nil {
		return 0, err
	}
	c.mu.Lock()
	c.lastSend, c.lastErr, c.sent = time.Now(), "", c.sent+int64(len(rows))
	c.mu.Unlock()
	return len(rows), nil
}

// heartbeat lets SkyNet's silent-agent alert notice a dead or cut-off vault.
func (c *Client) heartbeat(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	send := func() {
		f := map[string]string{"version": c.cfg.Version, "outbox": itoa(c.st.OutboxCount(ctx))}
		if d := c.dropped.Swap(0); d > 0 {
			c.Emit(Event{TS: time.Now().UTC().Format(time.RFC3339Nano), Host: c.cfg.Host, Source: "thevault", Category: "system", Action: "events_dropped", Fields: map[string]string{"count": itoa(int(d))}})
		}
		c.Emit(Event{TS: time.Now().UTC().Format(time.RFC3339Nano), Host: c.cfg.Host, Source: "thevault", Category: "system", Action: "heartbeat", Fields: f})
	}
	send()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			send()
		}
	}
}

// Status feeds the admin overview.
func (c *Client) Status(ctx context.Context) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	deny, _ := c.st.DenyActive(ctx)
	type d struct {
		IP     string `json:"ip"`
		Until  int64  `json:"until"`
		Reason string `json:"reason"`
	}
	dl := []d{}
	for _, x := range deny {
		dl = append(dl, d{x.IP, x.Until, x.Reason})
	}
	return map[string]any{
		"enabled": true, "url": c.cred.URL, "agent_id": c.cred.AgentID, "last_send": unix(c.lastSend), "last_error": c.lastErr, "sent": c.sent,
		"outbox": c.st.OutboxCount(ctx), "dropped": c.dropped.Load(), "commands_enabled": c.cred.CommandPubkey != "", "last_command": unix(c.lastCmd), "command_error": c.cmdErr, "deny": dl,
	}
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

var _ = base64.StdEncoding

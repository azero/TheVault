package skynet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/azero/thevault/server/internal/store"
)

// Same constants as SkyNet's agents (docs/response.md there).
const (
	sigContext  = "skynet-cmd-v1\n"
	maxValidity = 15 * 60
	skew        = 120
	minPollGap  = 200 * time.Millisecond
)

type signed struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

type payload struct {
	V         int            `json:"v"`
	ID        int64          `json:"id"`
	AgentID   string         `json:"agent_id"`
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	DryRun    bool           `json:"dry_run"`
	Nonce     string         `json:"nonce"`
	IssuedAt  int64          `json:"issued_at"`
	ExpiresAt int64          `json:"expires_at"`
}

// verify checks a command exactly like the endpoint agent does. reportable says whether the refusal may be reported
// to SkyNet (an unauthenticated payload must not be echoed back as if it were valid).
func (c *Client) verify(s signed, now time.Time) (p *payload, why string, reportable bool) {
	pub, err := base64.StdEncoding.DecodeString(c.cred.CommandPubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, "no valid command key is pinned", false
	}
	raw, err1 := base64.StdEncoding.DecodeString(s.Payload)
	sig, err2 := base64.StdEncoding.DecodeString(s.Sig)
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, append([]byte(sigContext), raw...), sig) {
		return nil, "bad signature", false
	}
	var pl payload
	if json.Unmarshal(raw, &pl) != nil || pl.ID == 0 || pl.Action == "" {
		return nil, "malformed payload", false
	}
	switch {
	case pl.V != 1:
		return &pl, "unsupported version", true
	case pl.AgentID != c.cred.AgentID:
		return &pl, "addressed to a different agent", true
	case pl.ExpiresAt <= now.Unix():
		return &pl, "expired", true
	case pl.IssuedAt > now.Unix()+skew:
		return &pl, "not yet valid", true
	case pl.ExpiresAt-pl.IssuedAt <= 0 || pl.ExpiresAt-pl.IssuedAt > maxValidity:
		return &pl, "validity window too long", true
	}
	return &pl, "", true
}

func (c *Client) poller(ctx context.Context) {
	backoff := 2 * time.Second
	for {
		if c.cred.CommandPubkey == "" {
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Minute):
				continue
			}
		}
		started := time.Now()
		n, err := c.pollOnce(ctx, 25)
		if ctx.Err() != nil {
			return
		}
		if d := minPollGap - time.Since(started); d > 0 && err == nil { // never hot-loop against a server that answers at once
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
			}
		}
		if err != nil {
			c.mu.Lock()
			c.cmdErr = err.Error()
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 2*time.Minute)
			continue
		}
		c.mu.Lock()
		c.cmdErr = ""
		c.mu.Unlock()
		backoff = 2 * time.Second
		if n == 0 {
			continue // the long poll already waited
		}
	}
}

func (c *Client) pollOnce(ctx context.Context, wait int) (int, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/commands?wait=%d", c.cred.URL, wait), nil)
	req.Header.Set("Authorization", "Bearer "+c.cred.APIKey)
	req.Header.Set("X-SkyNet-Version", "thevault/"+c.cfg.Version)
	hc := &http.Client{Timeout: time.Duration(wait+15) * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return 0, fmt.Errorf("skynet commands: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Commands []signed `json:"commands"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return 0, err
	}
	for _, s := range out.Commands {
		c.handle(ctx, s)
	}
	return len(out.Commands), nil
}

func (c *Client) handle(ctx context.Context, s signed) {
	p, why, reportable := c.verify(s, time.Now())
	if why != "" {
		log.Printf("skynet: command rejected: %s", why)
		if reportable && p != nil {
			c.report(ctx, p.ID, "skipped", "refused by thevault: "+why)
		}
		return
	}
	// Record the id BEFORE acting, so a crash can never lead to a second execution.
	if already, err := c.st.CommandSeen(ctx, p.ID); err != nil || already {
		if already {
			c.report(ctx, p.ID, "skipped", "refused by thevault: replay")
		}
		return
	}
	status, msg := c.execute(ctx, p)
	c.mu.Lock()
	c.lastCmd = time.Now()
	c.mu.Unlock()
	c.report(ctx, p.ID, status, msg)
}

func (c *Client) report(ctx context.Context, id int64, status, msg string) {
	if len(msg) > 900 {
		msg = msg[:900]
	}
	b, _ := json.Marshal(map[string]string{"status": status, "message": msg})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v1/commands/%d/result", c.cred.URL, id), bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+c.cred.APIKey)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := c.hc.Do(req); err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
	}
}

func (c *Client) execute(ctx context.Context, p *payload) (status, msg string) {
	str := func(k string) string { s, _ := p.Params[k].(string); return s }
	switch p.Action {
	case "block_ip":
		ip, err := c.blockable(str("ip"))
		if err != nil {
			return "skipped", "refused: " + err.Error()
		}
		ttl := int64(3600)
		if f, ok := p.Params["ttl_seconds"].(float64); ok {
			ttl = int64(f)
		}
		ttl = max(60, min(ttl, 7*86400))
		if p.DryRun {
			return "skipped", fmt.Sprintf("dry-run: would deny %s for %ds", ip, ttl)
		}
		if err := c.st.DenyAdd(ctx, store.Deny{IP: ip, Until: time.Now().Unix() + ttl, Reason: "skynet command " + itoa(int(p.ID)), CommandID: p.ID}); err != nil {
			return "failed", "could not store the deny entry"
		}
		c.refreshDeny(ctx)
		c.audit(ip, "block", ttl)
		return "succeeded", fmt.Sprintf("denying %s for %ds (HTTP 403 for every request)", ip, ttl)
	case "unblock_ip":
		a, err := netip.ParseAddr(strings.TrimSpace(str("ip")))
		if err != nil {
			return "skipped", "refused: not an IP address"
		}
		ip := a.Unmap().String()
		if p.DryRun {
			return "skipped", "dry-run: would allow " + ip + " again"
		}
		c.st.DenyRemove(ctx, ip)
		c.refreshDeny(ctx)
		c.audit(ip, "unblock", 0)
		return "succeeded", "removed " + ip + " from the deny list"
	}
	return "skipped", "refused: TheVault supports only block_ip and unblock_ip"
}

// audit goes through the sink so the SkyNet event is the same shape as every other.
func (c *Client) audit(ip, what string, ttl int64) {
	c.Emit(Event{TS: time.Now().UTC().Format(time.RFC3339Nano), Host: c.cfg.Host, Source: "thevault", Category: "system", Action: "response_applied",
		Fields: map[string]string{"ip": ip, "what": what, "ttl_seconds": itoa(int(ttl))}})
}

// ---- deny list ----

type cidr struct{ p netip.Prefix }

func parseAllow(csv string) ([]cidr, error) {
	var out []cidr
	for _, e := range strings.Split(csv, ",") {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			a, err := netip.ParseAddr(e)
			if err != nil {
				return nil, fmt.Errorf("VAULT_RESPONSE_ALLOWLIST entry %q: %w", e, err)
			}
			e = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String()
		}
		p, err := netip.ParsePrefix(e)
		if err != nil {
			return nil, fmt.Errorf("VAULT_RESPONSE_ALLOWLIST entry %q: %w", e, err)
		}
		out = append(out, cidr{p.Masked()})
	}
	return out, nil
}

var errNotBlockable = errors.New("not a blockable address")

// blockable returns the canonical address, or an error saying why it must never be blocked: loopback, unspecified,
// link-local, multicast, broadcast, SkyNet itself, or anything in VAULT_RESPONSE_ALLOWLIST.
func (c *Client) blockable(raw string) (string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("not an IP address")
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || (a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255})) {
		return "", fmt.Errorf("%s is %w", a, errNotBlockable)
	}
	for _, n := range c.allow {
		if n.p.Contains(a) {
			return "", fmt.Errorf("%s is on the never-block list", a)
		}
	}
	if u, err := url.Parse(c.cred.URL); err == nil {
		host := u.Hostname()
		ips := []net.IP{net.ParseIP(host)}
		if ips[0] == nil {
			ips, _ = net.LookupIP(host)
		}
		for _, ip := range ips {
			if na, ok := netip.AddrFromSlice(ip); ok && na.Unmap() == a {
				return "", fmt.Errorf("%s is the SkyNet server", a)
			}
		}
	}
	return a.String(), nil
}

func (c *Client) refreshDeny(ctx context.Context) {
	list, err := c.st.DenyActive(ctx)
	if err != nil {
		return
	}
	m := make(map[string]int64, len(list))
	for _, d := range list {
		m[d.IP] = d.Until
	}
	c.deny.Store(&m)
}

func (c *Client) denyJanitor(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.refreshDeny(ctx)
		}
	}
}

// Denied is called on every request: one map lookup.
func (c *Client) Denied(ip string) bool {
	m := c.deny.Load()
	if m == nil {
		return false
	}
	until, ok := (*m)[ip]
	return ok && until > time.Now().Unix()
}

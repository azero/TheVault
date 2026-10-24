// Package omnicore exposes TheVault to OmniCore (the company dashboard) through the signed, read-only widget protocol in
// internal/omniconnect (docs/omnicore.md).
//
// Zero-knowledge rules (AGENTS.md hard constraint 1), enforced by construction:
//   - A signed OmniCore request never needs, implies or grants an unlocked vault. Nothing here reads a session's unlock
//     state, and no query touches an item blob, a space name, a wrap, a proof, a key or a token (see store/omnicore.go).
//   - Widgets show counts, timestamps, device names the person chose and audit event names, which the person's own
//     screens already show. Space and item names are encrypted and cannot be shown.
//   - Administrator widgets show operational numbers only. Administrators can never read vault data, here or anywhere.
package omnicore

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/auth"
	"github.com/azero/thevault/server/internal/config"
	"github.com/azero/thevault/server/internal/httpx"
	oc "github.com/azero/thevault/server/internal/omniconnect"
	"github.com/azero/thevault/server/internal/store"
)

type Options struct {
	Cfg     *config.Config
	Store   *store.Store
	Audit   *audit.Auditor
	Version string
}

// Provider implements omniconnect.Provider over the store.
type Provider struct {
	Options
	verifier *oc.Verifier
	rate     *auth.Limiter // requests per client address (valid or not)
	denyPer  *auth.Limiter // omnicore_auth_failed audit rows per address
	denyAll  *auth.Limiter // and in total, so a spray of addresses cannot fill the audit table
	now      func() time.Time
}

const requestsPerMinute = 900

// New returns nil when no key is configured: the endpoints are then not mounted at all.
func New(o Options) *Provider {
	if len(o.Cfg.OmniCoreKeys) == 0 {
		return nil
	}
	var ks []oc.Key
	for _, k := range o.Cfg.OmniCoreKeys {
		ks = append(ks, oc.Key{ID: k.ID, Secret: []byte(k.Secret)})
	}
	return &Provider{Options: o, verifier: oc.NewVerifier(ks...), rate: auth.NewLimiter(requestsPerMinute, time.Minute),
		denyPer: auth.NewLimiter(1, time.Minute), denyAll: auth.NewLimiter(30, time.Minute), now: time.Now}
}

// Mount registers the protocol under /integrations/omnicore/v1/. These requests carry no cookie and no CSRF token: they
// authenticate with their own signature (and are never accepted without one). They stay behind the global SkyNet deny
// list and security headers, and get their own per-address rate limit.
func (p *Provider) Mount(mux *http.ServeMux) {
	if p == nil {
		return
	}
	sub := http.NewServeMux()
	oc.Mount(sub, p, p.verifier, oc.Hooks{Denied: p.denied})
	mux.Handle(oc.Prefix+"/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Same answer as every other authentication failure: the protocol only has signed GETs.
			p.denied(r, "omniconnect: unauthorized (method)")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}` + "\n"))
			return
		}
		if !p.rate.Allow(httpx.ClientIP(r, p.Cfg.TrustedIPHeader)) {
			w.Header().Set("Retry-After", "30")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}` + "\n"))
			return
		}
		sub.ServeHTTP(w, r)
	}))
}

// denied reports a failed verification. The client always sees the same 401; here the reason (one of a fixed set of words,
// never the key id or any header value) goes to the audit log and SkyNet, thinned to one row a minute per address.
func (p *Provider) denied(r *http.Request, reason string) {
	ip := httpx.ClientIP(r, p.Cfg.TrustedIPHeader)
	if !p.denyPer.Allow(ip) || !p.denyAll.Allow("all") {
		return
	}
	p.Audit.Log(context.WithoutCancel(r.Context()), audit.Event{Name: "omnicore_auth_failed", IP: ip, UA: r.UserAgent(), Outcome: "failure",
		Details: map[string]string{"reason": reasonWord(reason)}})
}

var reasons = []string{"method", "body", "unknown key", "timestamp", "clock skew", "nonce", "user", "signature", "replay", "no user"}

func reasonWord(s string) string {
	for _, w := range reasons {
		if strings.Contains(s, "("+w+")") || s == w {
			return strings.ReplaceAll(w, " ", "_")
		}
	}
	return "other"
}

// ---- who is asking ----

// person maps the ClosedDoor subject to TheVault's own account. OmniCore's word is not taken for names or roles.
type person struct {
	sub   string
	admin bool
}

// resolve finds the account. An unknown subject has never signed in to TheVault (not linked); an account locked by an
// administrator has no access to TheVault, so none to its widgets either.
func (p *Provider) resolve(ctx context.Context, u oc.User) (person, error) {
	acc, err := p.Store.GetUser(ctx, u.Sub)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return person{}, oc.ErrNotLinked
		}
		return person{}, err
	}
	if acc.Locked {
		return person{}, oc.ErrForbidden
	}
	pr := person{sub: acc.Sub, admin: acc.Role == "admin"}
	if pr.admin {
		// The recorded role is from the last sign-in. A live session is re-validated against ClosedDoor every five minutes, so if
		// any of the person's live sessions already reports a lower role, believe the lower one.
		live, err := p.Store.SessionMetas(ctx, acc.Sub, 50)
		if err != nil {
			return person{}, err
		}
		for _, s := range live {
			if s.Role != "admin" {
				pr.admin = false
			}
		}
	}
	return pr, nil
}

// Manifest lists the widgets for everybody; role-restricted ones are refused at Widget time.
func (p *Provider) Manifest() oc.Manifest { return buildManifest(p.Cfg, p.Version) }

func (p *Provider) Widget(ctx context.Context, u oc.User, id string, cfg map[string]string) (oc.Widget, error) {
	pr, err := p.resolve(ctx, u)
	if err != nil {
		return oc.Widget{}, err
	}
	spec, ok := specs[id]
	if !ok {
		return oc.Widget{}, oc.ErrNotFound
	}
	if spec.admin && !pr.admin {
		return oc.Widget{}, oc.ErrForbidden
	}
	return spec.build(p, ctx, pr, cfg)
}

func itoa(n int) string { return strconv.Itoa(n) }

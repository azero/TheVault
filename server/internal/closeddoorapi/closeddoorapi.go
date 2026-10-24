// Package closeddoorapi verifies ClosedDoor API keys (and ClosedDoor access tokens) for a Go backend.
//
// It is one file with no dependencies: copy it into your service. The service asks the SSO server "who is
// behind this credential and what may they do here?" with its OWN client ID and secret (POST /api/introspect),
// so the answer only ever covers this service, whichever other services the same key may also call.
//
//	v, _ := closeddoorapi.New(closeddoorapi.Config{
//		Issuer: "https://sso.example.com", ClientID: "app_...", ClientSecret: "cds_...",
//		CacheTTL: 30 * time.Second, // optional; a revoked key keeps working here for up to this long
//	})
//	mux.Handle("/api/reports", v.Middleware("reports:read")(http.HandlerFunc(list)))
//
//	func list(w http.ResponseWriter, r *http.Request) {
//		who := closeddoorapi.FromContext(r.Context()) // who.Subject, who.Type, who.Roles, who.Can("reports:write")
//	}
//
// Failing closed is deliberate: if the SSO server cannot be reached the middleware answers 503, never "allowed".
package closeddoorapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Principal is what the SSO server says about a credential, for this service.
type Principal struct {
	Active  bool   `json:"active"`
	Kind    string `json:"token_kind"` // "api_key" or "access_token"
	Subject string `json:"sub"`        // the person's stable id; "svc_..." for service keys
	Type    string `json:"principal"`  // "user" or "service"
	KeyID   string `json:"key_id"`
	KeyName string `json:"key_name"`
	// Scope is the space-separated list of this key's permissions in THIS service. For access tokens it holds the
	// OIDC scopes (openid, profile, ...) instead: users express authority as Roles.
	Scope   string   `json:"scope"`
	Roles   []string `json:"roles"`
	Name    string   `json:"name"`  // user keys and tokens only
	Email   string   `json:"email"` // user keys and tokens only
	Expires int64    `json:"exp"`   // 0 = never
}

// IsUser reports whether the credential acts as a person (a user key or user access token), as opposed to a service key.
func (p *Principal) IsUser() bool { return p.Type == "user" }

// IsService reports whether the credential belongs to a script or system rather than a person.
func (p *Principal) IsService() bool { return p.Type == "service" }

// Can reports whether the credential holds the permission.
func (p *Principal) Can(scope string) bool {
	for _, s := range strings.Fields(p.Scope) {
		if s == scope {
			return true
		}
	}
	return false
}

// HasRole reports whether the person has the role in this service (user keys and user access tokens).
func (p *Principal) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Config describes this service to the SSO server.
type Config struct {
	Issuer       string // https://sso.example.com (no trailing slash needed)
	ClientID     string // this service, registered in ClosedDoor (confidential)
	ClientSecret string
	HTTPClient   *http.Client  // optional; default has a 5 second timeout
	CacheTTL     time.Duration // 0 = ask the SSO server on every request
	CacheSize    int           // maximum cached answers (default 1000)
}

type cacheEntry struct {
	who     *Principal // nil = inactive
	expires time.Time
}

// Verifier checks credentials against ClosedDoor. It is safe for concurrent use.
type Verifier struct {
	cfg   Config
	url   string
	mu    sync.Mutex
	cache map[[32]byte]cacheEntry
}

// New validates the configuration.
func New(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("closeddoorapi: Issuer, ClientID and ClientSecret are required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = 1000
	}
	return &Verifier{cfg: cfg, url: strings.TrimRight(cfg.Issuer, "/") + "/api/introspect", cache: map[[32]byte]cacheEntry{}}, nil
}

// Verify returns the principal for a credential, or (nil, nil) when it is not valid for this service
// (unknown, expired, revoked, not granted here, user disabled...). An error means "could not check": treat it as
// a failure, never as permission.
func (v *Verifier) Verify(ctx context.Context, token string) (*Principal, error) {
	if token == "" {
		return nil, nil
	}
	key := sha256.Sum256([]byte(token))
	if who, ok := v.cached(key); ok {
		return who, nil
	}
	who, err := v.introspect(ctx, token)
	if err != nil {
		return nil, err
	}
	v.store(key, who)
	return who, nil
}

func (v *Verifier) cached(key [32]byte) (*Principal, bool) {
	if v.cfg.CacheTTL <= 0 {
		return nil, false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[key]
	if !ok || time.Now().After(e.expires) {
		delete(v.cache, key)
		return nil, false
	}
	return e.who, true
}

func (v *Verifier) store(key [32]byte, who *Principal) {
	if v.cfg.CacheTTL <= 0 {
		return
	}
	expires := time.Now().Add(v.cfg.CacheTTL)
	if who != nil && who.Expires > 0 && time.Unix(who.Expires, 0).Before(expires) {
		expires = time.Unix(who.Expires, 0)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) >= v.cfg.CacheSize {
		now := time.Now()
		for k, e := range v.cache {
			if now.After(e.expires) {
				delete(v.cache, k)
			}
		}
		if len(v.cache) >= v.cfg.CacheSize {
			v.cache = map[[32]byte]cacheEntry{}
		}
	}
	v.cache[key] = cacheEntry{who: who, expires: expires}
}

func (v *Verifier) introspect(ctx context.Context, token string) (*Principal, error) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 section 2.3.1: form-urlencode the id and secret before base64.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(v.cfg.ClientID)+":"+url.QueryEscape(v.cfg.ClientSecret))))

	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("closeddoorapi: SSO server unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("closeddoorapi: reading answer: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, errors.New("closeddoorapi: the SSO server rejected this service's client ID or secret")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("closeddoorapi: unexpected answer from the SSO server (HTTP %d)", resp.StatusCode)
	}
	var who Principal
	if err := json.Unmarshal(body, &who); err != nil {
		return nil, fmt.Errorf("closeddoorapi: bad answer from the SSO server: %w", err)
	}
	if !who.Active {
		return nil, nil
	}
	return &who, nil
}

// TokenFromRequest returns the credential from "Authorization: Bearer ..." or else "X-API-Key", or "".
func TokenFromRequest(r *http.Request) string {
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

type ctxKey struct{}

// WithPrincipal stores a principal in the context (the middleware does this; tests and custom middleware can too).
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the principal the middleware stored, or nil.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// Middleware protects a handler: 401 without a valid credential, 403 without every listed permission,
// 503 if the SSO server cannot be asked. The verified principal is available via FromContext.
func (v *Verifier) Middleware(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			who, err := v.Verify(r.Context(), TokenFromRequest(r))
			switch {
			case err != nil:
				writeJSON(w, http.StatusServiceUnavailable, `{"error":"authentication_unavailable"}`, "")
				return
			case who == nil:
				writeJSON(w, http.StatusUnauthorized, `{"error":"invalid_token"}`, `Bearer error="invalid_token"`)
				return
			}
			for _, s := range scopes {
				if !who.Can(s) {
					writeJSON(w, http.StatusForbidden, `{"error":"insufficient_scope","needs":`+quote(s)+`}`, `Bearer error="insufficient_scope"`)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), who)))
		})
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func writeJSON(w http.ResponseWriter, status int, body, challenge string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

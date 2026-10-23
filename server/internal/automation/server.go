// Package automation is TheVault's administration API for scripts: /api/v1/whoami, /status, /users, /audit and so on,
// authenticated by ClosedDoor API keys (cdk_...) and granted per permission ("scope") in ClosedDoor.
//
// TheVault is zero-knowledge and an API key can never be unlocked with a master password, so this API exposes NO vault
// content in any form: no item, folder, space content or key material, not even as ciphertext. It is the operations
// side only: health, accounts, sessions, the audit log and SkyNet's block list (docs/automation-api.md).
//
// It is deliberately separate from the browser/extension API in internal/api: no cookies, no CSRF token, no CORS, and
// a different credential that the web UI does not accept (and vice versa).
package automation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/auth"
	"github.com/azero/thevault/server/internal/closeddoorapi"
	"github.com/azero/thevault/server/internal/config"
	"github.com/azero/thevault/server/internal/httpx"
	"github.com/azero/thevault/server/internal/store"
)

const (
	maxCredential   = 4096
	maxBody         = 1 << 20
	requestDeadline = 15 * time.Second
	failuresPerMin  = 20 // failed authentications per client address, checked before ClosedDoor is asked again
)

// A ClosedDoor API key: "cdk_" and 43 URL-safe characters. Anything else is refused without asking ClosedDoor.
var reKey = regexp.MustCompile(`^cdk_[A-Za-z0-9_-]{43}$`)

// Verifier is what ClosedDoor's client library provides; tests substitute a stub that counts calls.
type Verifier interface {
	Verify(ctx context.Context, token string) (*closeddoorapi.Principal, error)
}

type Options struct {
	Cfg     *config.Config
	Store   *store.Store
	Audit   *audit.Auditor
	Version string
	// SkyNetStatus feeds /status and /response/blocks (nil when SkyNet is not configured).
	SkyNetStatus func(ctx context.Context) any
	// Verifier is built from Cfg (issuer, client id and secret, cache) when nil.
	Verifier Verifier
}

type Server struct {
	Options
	fails *window // failed authentications per client address
	keyRL *window // requests per credential
	noisy *window // caps how often a repeating condition reaches the audit log and SkyNet

	mu    sync.Mutex
	known map[string]string // sha256(credential) -> key id, learnt from successful verifications (labels rate-limit events)
	start time.Time
}

// New builds the API. It fails if the ClosedDoor credentials needed to verify keys are missing.
func New(o Options) (*Server, error) {
	if o.Verifier == nil {
		v, err := closeddoorapi.New(closeddoorapi.Config{Issuer: o.Cfg.OIDCIssuer, ClientID: o.Cfg.OIDCClientID, ClientSecret: o.Cfg.OIDCClientSecret,
			CacheTTL: time.Duration(o.Cfg.APICacheSeconds) * time.Second})
		if err != nil {
			return nil, err
		}
		o.Verifier = v
	}
	rate := o.Cfg.APIRatePerMinute
	if rate < 1 {
		rate = 120
	}
	return &Server{Options: o, fails: newWindow(failuresPerMin, time.Minute), keyRL: newWindow(rate, time.Minute), noisy: newWindow(1, time.Minute),
		known: map[string]string{}, start: time.Now()}, nil
}

// call is the per-request context handed to handlers.
type call struct {
	W      http.ResponseWriter
	R      *http.Request
	P      *closeddoorapi.Principal
	IP     string
	Server *Server
}

func (c *call) json(status int, v any) { httpx.JSON(c.W, status, v) }

func (c *call) fail(status int, code, msg string) { httpx.Error(c.W, status, code, msg) }

// body accepts the (empty) bodies of the action endpoints: nothing, or a JSON object with no fields. JSON only,
// bounded, unknown fields rejected.
func (c *call) noBody() bool {
	raw, err := io.ReadAll(http.MaxBytesReader(c.W, c.R.Body, maxBody))
	if err != nil {
		c.fail(http.StatusBadRequest, "invalid_request", "The request body is too large or unreadable.")
		return false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return true
	}
	ct := c.R.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if strings.ToLower(strings.TrimSpace(ct)) != "application/json" {
		c.fail(http.StatusBadRequest, "invalid_request", "Request bodies must be application/json.")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var none struct{}
	if err := dec.Decode(&none); err != nil {
		c.fail(http.StatusBadRequest, "invalid_request", "This endpoint takes no parameters in the body.")
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		c.fail(http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return false
	}
	return true
}

// statusWriter remembers the status code so the audit event can record it.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

type route struct {
	Method  string
	Pattern string
	Scope   string // "" only for whoami: any valid key
	Admin   bool   // user keys need the admin role (what the administration screen needs); service keys are bound by scope only
	Handler func(*call)
}

func (s *Server) routes() []route {
	return []route{
		{"GET", "/api/v1/whoami", "", false, s.whoami},
		{"GET", "/api/v1/status", "status:read", true, s.status},
		{"GET", "/api/v1/users", "users:read", true, s.listUsers},
		{"GET", "/api/v1/users/{sub}", "users:read", true, s.getUser},
		{"POST", "/api/v1/users/{sub}/lock", "users:lock", true, s.lockUser},
		{"POST", "/api/v1/users/{sub}/unlock", "users:unlock", true, s.unlockUser},
		{"GET", "/api/v1/users/{sub}/sessions", "sessions:read", true, s.listSessions},
		{"DELETE", "/api/v1/users/{sub}/sessions", "sessions:revoke", true, s.revokeSessions},
		{"DELETE", "/api/v1/users/{sub}/sessions/{id}", "sessions:revoke", true, s.revokeSession},
		{"GET", "/api/v1/audit", "audit:read", true, s.listAudit},
		{"GET", "/api/v1/response/blocks", "response:read", true, s.listBlocks},
	}
}

// Routes registers the API on mux. Called only when the API is enabled: otherwise these paths do not exist (404).
func (s *Server) Routes(mux *http.ServeMux) {
	methods := map[string][]string{}
	for _, rt := range s.routes() {
		mux.HandleFunc(rt.Method+" "+rt.Pattern, s.wrap(rt))
		methods[rt.Pattern] = append(methods[rt.Pattern], rt.Method)
	}
	// No CORS here: it is a server-to-server API. Without these, the browser API's preflight handler for /api/v1/ would
	// answer OPTIONS (with CORS headers for the extension's origin).
	for pattern, ms := range methods {
		allow := strings.Join(ms, ", ")
		mux.HandleFunc("OPTIONS "+pattern, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Allow", allow)
			w.Header().Set("Cache-Control", "no-store")
			httpx.Error(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed.")
		})
	}
}

// credential returns what the caller presented: "Authorization: Bearer ..." or else "X-API-Key". A request with some
// other Authorization scheme and no X-API-Key presented something unusable, which is reported as malformed.
func credential(r *http.Request) (token string, presented bool) {
	if h := r.Header.Get("Authorization"); len(h) >= 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:]), true
	}
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); k != "" {
		return k, true
	}
	if r.Header.Get("Authorization") != "" {
		return "", true
	}
	return "", false
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *Server) remember(hash, keyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.known) >= 2000 {
		s.known = map[string]string{}
	}
	s.known[hash] = keyID
}

func (s *Server) knownKey(hash string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.known[hash]
}

func (s *Server) wrap(rt route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		ctx, cancel := context.WithTimeout(r.Context(), requestDeadline)
		defer cancel()
		r = r.WithContext(ctx)
		ip := httpx.ClientIP(r, s.Cfg.TrustedIPHeader)

		token, presented := credential(r)
		if !presented {
			unauthorized(w, "Send your API key as \"Authorization: Bearer cdk_...\" (or X-API-Key).")
			return
		}
		// Too many recent failures from this address: refuse before spending another request on ClosedDoor.
		if full, wait := s.fails.full(ip); full {
			s.rateLimited(r, ip, "", "ip", failuresPerMin, wait, w)
			return
		}
		if len(token) > maxCredential || !reKey.MatchString(token) {
			s.fails.add(ip)
			s.authFailed(r, ip, "malformed", "")
			unauthorized(w, "The credential is not an API key.")
			return
		}
		hash := tokenHash(token)
		if ok, wait := s.keyRL.take(hash); !ok {
			s.rateLimited(r, ip, s.knownKey(hash), "key", s.Cfg.APIRatePerMinute, wait, w)
			return
		}
		p, err := s.Verifier.Verify(ctx, token)
		if err != nil {
			// ClosedDoor unreachable, or it rejected this application's own credentials: never "allowed".
			if s.noisy.takeQuiet("unavail") {
				log.Printf("automation api: cannot verify API keys: %v", err)
			}
			s.authFailed(r, ip, "unavailable", token[:8])
			httpx.Error(w, http.StatusServiceUnavailable, "authentication_unavailable", "API keys cannot be verified right now. Try again later.")
			return
		}
		if p == nil || !p.Active || p.Kind != "api_key" || (!p.IsUser() && !p.IsService()) || p.KeyID == "" {
			s.fails.add(ip)
			s.authFailed(r, ip, "invalid_token", token[:8])
			unauthorized(w, "The API key is invalid, expired or revoked.")
			return
		}
		s.remember(hash, p.KeyID)

		c := &call{W: w, R: r, P: p, IP: ip, Server: s}
		if rt.Scope != "" && !p.Can(rt.Scope) {
			s.forbidden(c, "scope", rt.Scope)
			challenge := `Bearer error="insufficient_scope", scope="` + rt.Scope + `"`
			h.Set("WWW-Authenticate", challenge)
			httpx.JSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope", "message": "This API key lacks the permission " + rt.Scope + ".", "needs": rt.Scope})
			return
		}
		if rt.Admin && p.IsUser() && !s.userMayAdminister(c) {
			s.forbidden(c, "role", rt.Scope)
			httpx.Error(w, http.StatusForbidden, "forbidden", "The person behind this key may not do this in TheVault.")
			return
		}

		sw := &statusWriter{ResponseWriter: w}
		c.W = sw
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("automation api: panic in %s %s: %v", rt.Method, rt.Pattern, rec)
					if sw.status == 0 {
						httpx.Error(sw, http.StatusInternalServerError, "server_error", "Something went wrong on the server.")
					}
				}
			}()
			rt.Handler(c)
		}()
		if sc, ok := scopeInfo(rt.Scope); ok && (r.Method != http.MethodGet && r.Method != http.MethodHead || sc.Sensitive) {
			s.apiCall(c, sc, sw.status)
		}
	}
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	httpx.Error(w, http.StatusUnauthorized, "invalid_token", msg)
}

// userMayAdminister: a user key may do only what the person could do in the web UI. The administration screens need
// the admin role (exact match on ClosedDoor's roles claim, read live by the introspection) and an account that an
// administrator has not locked.
func (s *Server) userMayAdminister(c *call) bool {
	if auth.RoleFromClaims(c.P.Roles) != auth.RoleAdmin {
		return false
	}
	u, err := s.Store.GetUser(c.R.Context(), c.P.Subject)
	switch {
	case err == nil:
		return !u.Locked
	case errors.Is(err, store.ErrNotFound):
		return true // an admin who has never opened TheVault: the role alone decides, as it would on first sign-in
	}
	log.Printf("automation api: user lookup: %v", err)
	return false
}

// ---- audit + SkyNet ----

var reCleanName = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func cleanName(s string, max int) string {
	s = reCleanName.ReplaceAllString(s, " ")
	if len(s) > max {
		s = s[:max]
	}
	return strings.ToValidUTF8(s, "")
}

// identity is who the audit trail names: the person for a user key (email, else sub), "key:<name>" for a service key.
func identity(p *closeddoorapi.Principal) (actor, user string) {
	if p.IsUser() {
		if a, err := mail.ParseAddress(p.Email); err == nil && a.Address == p.Email {
			return p.Subject, p.Email
		}
		return p.Subject, p.Subject
	}
	return p.Subject, "key:" + cleanName(p.KeyName, 100)
}

func keyDetails(p *closeddoorapi.Principal) map[string]string {
	return map[string]string{"key_id": cleanName(p.KeyID, 64), "key_name": cleanName(p.KeyName, 100), "principal": p.Type}
}

func (s *Server) log(r *http.Request, e audit.Event) {
	// A client that hangs up must not cost us the audit row.
	s.Audit.Log(context.WithoutCancel(r.Context()), e)
}

// authFailed records a credential that was presented and rejected. It never contains the credential: at most the first
// eight characters, and only when the value is shaped like a key.
func (s *Server) authFailed(r *http.Request, ip, reason, prefix string) {
	d := map[string]string{"reason": reason}
	if prefix != "" {
		d["key_prefix"] = prefix
	}
	s.log(r, audit.Event{Name: "api_auth_failed", IP: ip, UA: r.UserAgent(), Outcome: "failure", Details: d})
}

func (s *Server) forbidden(c *call, reason, needs string) {
	d := keyDetails(c.P)
	d["reason"], d["needs"] = reason, needs
	actor, user := identity(c.P)
	s.log(c.R, audit.Event{Name: "api_forbidden", Actor: actor, User: user, IP: c.IP, UA: c.R.UserAgent(), Outcome: "failure", Details: d})
}

// rateLimited answers 429. The event is thinned to one a minute per address or key: the throttle itself bounds what a
// flood can cost, and SkyNet only needs to know it is happening.
func (s *Server) rateLimited(r *http.Request, ip, keyID, by string, limit int, wait time.Duration, w http.ResponseWriter) {
	w.Header().Set("Retry-After", itoa(retrySeconds(wait)))
	who := ip
	if by == "key" && keyID != "" {
		who = keyID
	}
	if s.noisy.takeQuiet("rl|" + by + "|" + who) {
		d := map[string]string{"limit": itoa(limit), "by": by}
		if keyID != "" {
			d["key_id"] = cleanName(keyID, 64)
		}
		s.log(r, audit.Event{Name: "api_rate_limited", IP: ip, UA: r.UserAgent(), Outcome: "failure", Details: d})
	}
	httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "Too many requests. Wait for Retry-After seconds.")
}

// apiCall records every mutating call and every call to a sensitive read scope: who, with which key, what, and how it ended.
func (s *Server) apiCall(c *call, sc Scope, status int) {
	if status == 0 {
		status = http.StatusOK
	}
	d := keyDetails(c.P)
	d["scope"], d["method"], d["status"] = sc.Name, c.R.Method, itoa(status)
	d["target"] = cleanName(c.R.URL.Path, 200)
	outcome := "success"
	if status >= 400 {
		outcome = "failure"
	}
	actor, user := identity(c.P)
	s.log(c.R, audit.Event{Name: "api_call", Category: sc.Category, Actor: actor, User: user, IP: c.IP, UA: c.R.UserAgent(), Outcome: outcome, Details: d})
}

// takeQuiet is a one-per-window gate for log lines and events (not a limiter of requests).
func (w *window) takeQuiet(key string) bool {
	ok, _ := w.take(key)
	return ok
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Endpoint describes one route for documentation and tests.
type Endpoint struct {
	Method, Pattern string
	Scope           string // "" = any valid key
	AdminRole       bool   // user keys additionally need the admin role
}

// Endpoints lists every route of the API.
func Endpoints() []Endpoint {
	var out []Endpoint
	for _, rt := range (&Server{}).routes() {
		out = append(out, Endpoint{rt.Method, rt.Pattern, rt.Scope, rt.Admin})
	}
	return out
}

// Package api is TheVault's JSON interface plus the SSO routes. The browser UI and the Chrome extension are its only
// clients, and both treat the server as an untrusted store of ciphertext.
//
// Every route goes through one guard (see Server.handle): session (cookie) or bearer token (extension), account lock,
// CSRF + origin checks, and, for anything that touches vault data, a server-side unlock.
package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/auth"
	"github.com/azero/thevault/server/internal/config"
	"github.com/azero/thevault/server/internal/httpx"
	"github.com/azero/thevault/server/internal/keys"
	"github.com/azero/thevault/server/internal/store"
)

const (
	webIdle   = 30 * time.Minute
	webAbs    = 8 * time.Hour
	extIdle   = 14 * 24 * time.Hour
	extAbs    = 30 * 24 * time.Hour
	recheckIn = 5 * time.Minute
	tokenSkew = 60 * time.Second
	// An unlocked session may outlive its SSO access token by this much (ClosedDoor has no refresh tokens, and
	// re-authenticating a web page would throw away the in-memory keys). Unlocking itself always needs a fresh token.
	ssoGrace = 2 * time.Hour

	bearerPrefix = "vxs_"
)

type Options struct {
	Cfg     *config.Config
	Store   *store.Store
	Auth    *auth.Authenticator
	Audit   *audit.Auditor
	Pepper  *keys.Pepper
	Version string

	// ErrorPage renders an HTML error page (provided by the web package).
	ErrorPage func(w http.ResponseWriter, status int, msg string)
	// SkyNetStatus feeds the admin overview (nil when SkyNet is not configured).
	SkyNetStatus func(ctx context.Context) any
}

type Server struct {
	Options
	unlockRL *auth.Limiter // per IP
	apiRL    *auth.Limiter // per session
	dirRL    *auth.Limiter
	extRL    *auth.Limiter
	loginRL  *auth.Limiter
	noisy    *auth.Limiter // caps how often a repeating failure is reported to the audit log
	cookie   string
}

func New(o Options) *Server {
	s := &Server{
		Options:  o,
		unlockRL: auth.NewLimiter(20, time.Minute),
		apiRL:    auth.NewLimiter(1500, time.Minute),
		dirRL:    auth.NewLimiter(30, time.Minute),
		extRL:    auth.NewLimiter(30, time.Minute),
		loginRL:  auth.NewLimiter(40, time.Minute),
		noisy:    auth.NewLimiter(1, time.Minute),
		cookie:   "vault_session",
	}
	if o.Cfg.SecureCookie {
		s.cookie = "__Host-vault_session"
	}
	return s
}

// need says what a route requires on top of a valid session.
type need struct {
	unlocked bool // the vault must be unlocked (master-password proof verified server-side)
	admin    bool
	public   bool // no session needed (extension token exchange)
}

// rc is the per-request context handed to handlers.
type rc struct {
	W      http.ResponseWriter
	R      *http.Request
	Sess   *store.Session
	IP     string
	Bearer bool
}

type handler func(*rc)

func (s *Server) Routes(mux *http.ServeMux) {
	h := func(pattern string, n need, f handler) { s.handle(mux, pattern, n, f) }
	anyOK := need{}
	unl := need{unlocked: true}
	adm := need{admin: true}

	h("GET /api/v1/session", anyOK, s.getSession)
	h("POST /api/v1/session/logout", anyOK, s.logout)
	h("PUT /api/v1/settings", anyOK, s.putSettings)

	h("GET /api/v1/vault/prelogin", anyOK, s.prelogin)
	h("POST /api/v1/vault/setup", anyOK, s.setup)
	h("POST /api/v1/vault/unlock", anyOK, s.unlock)
	h("POST /api/v1/vault/lock", anyOK, s.lock)
	h("POST /api/v1/vault/password", unl, s.changePassword)
	h("POST /api/v1/vault/recovery/start", anyOK, s.recoveryStart)
	h("POST /api/v1/vault/recovery/finish", anyOK, s.recoveryFinish)
	h("POST /api/v1/vault/recovery/rotate", unl, s.recoveryRotate)
	h("POST /api/v1/vault/erase", anyOK, s.eraseOwnVault)

	h("GET /api/v1/sync", unl, s.sync)
	h("PUT /api/v1/items/{id}", unl, s.putItem)
	h("DELETE /api/v1/items/{id}", unl, s.deleteItem)
	h("POST /api/v1/items/{id}/restore", unl, s.restoreItem)
	h("GET /api/v1/items/{id}/versions", unl, s.itemVersions)
	h("POST /api/v1/items/import", unl, s.importItems)

	h("GET /api/v1/directory", unl, s.directory)
	h("GET /api/v1/users/{sub}/keys", unl, s.userKeys)
	h("POST /api/v1/spaces", unl, s.createSpace)
	h("PUT /api/v1/spaces/{id}", unl, s.renameSpace)
	h("DELETE /api/v1/spaces/{id}", unl, s.deleteSpace)
	h("POST /api/v1/spaces/{id}/members", unl, s.addMember)
	h("PUT /api/v1/spaces/{id}/members/{sub}", unl, s.setMemberRole)
	h("DELETE /api/v1/spaces/{id}/members/{sub}", unl, s.removeMember)
	h("POST /api/v1/spaces/{id}/rotate", unl, s.rotateSpace)

	h("GET /api/v1/sessions", anyOK, s.listSessions)
	h("DELETE /api/v1/sessions/{id}", anyOK, s.revokeSession)
	h("POST /api/v1/sessions/revoke-others", anyOK, s.revokeOthers)
	h("GET /api/v1/activity", anyOK, s.activity)
	h("POST /api/v1/audit/client", unl, s.clientAudit)

	h("POST /api/v1/ext/token", need{public: true}, s.extToken)

	h("GET /api/v1/admin/overview", adm, s.adminOverview)
	h("GET /api/v1/admin/audit", adm, s.adminAudit)
	h("POST /api/v1/admin/users/{sub}/lock", adm, s.adminLockUser)
	h("POST /api/v1/admin/users/{sub}/unlock", adm, s.adminUnlockUser)
	h("POST /api/v1/admin/users/{sub}/revoke-sessions", adm, s.adminRevokeSessions)
	h("POST /api/v1/admin/users/{sub}/erase-vault", adm, s.adminEraseVault)

	// SSO (browser navigations, not JSON)
	mux.HandleFunc("GET /auth/login", s.authLogin)
	mux.HandleFunc("GET /auth/callback", s.authCallback)
	mux.HandleFunc("GET /ext/auth", s.extAuth)

	// CORS preflight for the extension
	mux.HandleFunc("OPTIONS /api/v1/", s.preflight)
}

// ---- guard ----

func (s *Server) handle(mux *http.ServeMux, pattern string, n need, f handler) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		ip := httpx.ClientIP(r, s.Cfg.TrustedIPHeader)
		s.applyCORS(w, r)
		c := &rc{W: w, R: r, IP: ip}
		if n.public {
			if !s.originOK(r, true) {
				s.refuseOrigin(c, nil)
				return
			}
			f(c)
			return
		}
		sess, bearer, ok := s.authenticate(c)
		if !ok {
			return
		}
		c.Sess, c.Bearer = sess, bearer
		if !s.apiRL.Allow(sess.IDHash) {
			w.Header().Set("Retry-After", "30")
			httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "Too many requests. Wait a moment.")
			return
		}
		if sess.Locked {
			httpx.Error(w, http.StatusForbidden, "account_locked", "This account is locked by an administrator.")
			return
		}
		safe := r.Method == http.MethodGet || r.Method == http.MethodHead
		if !s.originOK(r, bearer) {
			s.refuseOrigin(c, sess)
			return
		}
		if !safe && !bearer && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Vault-CSRF")), []byte(sess.CSRF)) != 1 {
			s.Audit.Log(r.Context(), audit.Event{Name: "csrf_failed", Actor: sess.Sub, IP: ip, UA: r.UserAgent(), Outcome: "failure"})
			httpx.Error(w, http.StatusForbidden, "csrf", "The request was refused. Reload the page and try again.")
			return
		}
		if n.admin && sess.Role != auth.RoleAdmin {
			httpx.Error(w, http.StatusForbidden, "forbidden", "Administrators only.")
			return
		}
		if n.unlocked {
			now := time.Now()
			if sess.UnlockedUntil <= now.Unix() {
				httpx.Error(w, http.StatusLocked, "locked", "The vault is locked.")
				return
			}
			s.extendUnlock(r.Context(), sess, now)
		}
		f(c)
	})
}

// extendUnlock slides the idle window, but never past the SSO grace limit.
func (s *Server) extendUnlock(ctx context.Context, sess *store.Session, now time.Time) {
	want := now.Add(s.idleFor(sess)).Unix()
	if limit := time.Unix(sess.TokenExpiry, 0).Add(ssoGrace).Unix(); want > limit {
		want = limit
	}
	if want > sess.UnlockedUntil+5 {
		s.Store.SetUnlockedUntil(ctx, sess.IDHash, want)
		sess.UnlockedUntil = want
	}
}

func (s *Server) idleFor(sess *store.Session) time.Duration {
	if sess.UnlockIdleMinutes > 0 {
		return time.Duration(sess.UnlockIdleMinutes) * time.Minute
	}
	return s.Cfg.UnlockIdle()
}

func (s *Server) extOrigins() map[string]bool {
	m := map[string]bool{}
	for _, id := range s.Cfg.ExtensionIDs {
		m["chrome-extension://"+id] = true
	}
	return m
}

func (s *Server) applyCORS(w http.ResponseWriter, r *http.Request) {
	o := r.Header.Get("Origin")
	if o != "" && s.extOrigins()[o] {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", o)
		h.Add("Vary", "Origin")
		h.Set("Access-Control-Expose-Headers", "Retry-After")
	}
}

func (s *Server) preflight(w http.ResponseWriter, r *http.Request) {
	o := r.Header.Get("Origin")
	if o == "" || !s.extOrigins()[o] {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", o)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	h.Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

// originOK: cookie sessions accept only our own origin; bearer sessions also accept the configured extension origins.
// An absent Origin is fine (non-browser clients, same-origin GETs): the CSRF header still applies to cookie sessions.
func (s *Server) originOK(r *http.Request, bearer bool) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); !bearer && sfs != "" && sfs != "same-origin" && sfs != "none" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" || o == s.Cfg.PublicURL {
		return true
	}
	return bearer && s.extOrigins()[o]
}

func (s *Server) refuseOrigin(c *rc, sess *store.Session) {
	actor := ""
	if sess != nil {
		actor = sess.Sub
	}
	if s.noisy.Allow("origin|" + c.IP) {
		s.Audit.Log(c.R.Context(), audit.Event{Name: "origin_refused", Actor: actor, IP: c.IP, UA: c.R.UserAgent(), Outcome: "failure", Details: map[string]string{"origin": cleanText(c.R.Header.Get("Origin"), 100)}})
	}
	httpx.Error(c.W, http.StatusForbidden, "origin", "Cross-origin request refused.")
}

// authenticate resolves the session. On failure it has already written the response.
func (s *Server) authenticate(c *rc) (*store.Session, bool, bool) {
	r, w := c.R, c.W
	ctx := r.Context()
	var token string
	bearer := false
	if h := r.Header.Get("Authorization"); h != "" {
		t, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || !strings.HasPrefix(strings.TrimSpace(t), bearerPrefix) {
			s.reportBearerFailure(c)
			httpx.Error(w, http.StatusUnauthorized, "unauthenticated", "Sign in required.")
			return nil, false, false
		}
		token, bearer = strings.TrimSpace(t), true
	} else if ck, err := r.Cookie(s.cookie); err == nil {
		token = ck.Value
	}
	sess, err := s.Store.GetSession(ctx, token, webIdle, extIdle)
	if err != nil || (bearer && sess.Kind != "ext") || (!bearer && sess.Kind != "web") {
		if bearer {
			s.reportBearerFailure(c)
		}
		httpx.Error(w, http.StatusUnauthorized, "unauthenticated", "Sign in required.")
		return nil, false, false
	}
	now := time.Now()
	if now.After(time.Unix(sess.TokenExpiry, 0).Add(-tokenSkew)) {
		// The SSO token has expired: the session lives on (see ssoGrace) but cannot be re-validated; unlocking will ask
		// the client to sign in again first.
	} else if now.Sub(time.Unix(sess.CheckedAt, 0)) > recheckIn {
		if !s.revalidate(c, sess) {
			return nil, false, false
		}
	}
	if sess.IP != "" && sess.IP != c.IP {
		if s.noisy.Allow("ipchg|" + sess.IDHash) {
			s.Audit.Log(ctx, audit.Event{Name: "session_ip_changed", Actor: sess.Sub, IP: c.IP, UA: r.UserAgent(), Details: map[string]string{"from": sess.IP, "kind": sess.Kind}})
		}
		s.Store.SetSessionIP(ctx, sess.IDHash, c.IP)
		sess.IP = c.IP
	}
	return sess, bearer, true
}

func (s *Server) reportBearerFailure(c *rc) {
	if s.noisy.Allow("bearer|" + c.IP) {
		s.Audit.Log(c.R.Context(), audit.Event{Name: "bearer_failed", IP: c.IP, UA: c.R.UserAgent(), Outcome: "failure"})
	}
}

// revalidate asks ClosedDoor whether the user is still active and still granted the app. 401/403 ends the session;
// an outage keeps it (the next request retries).
func (s *Server) revalidate(c *rc, sess *store.Session) bool {
	ctx := c.R.Context()
	roles, err := s.Auth.UserInfo(ctx, sess.AccessToken)
	switch {
	case err == nil:
		role := auth.RoleFromClaims(roles)
		if role != sess.Role {
			s.Store.UpdateSessionRole(ctx, sess.IDHash, role)
			s.Audit.Log(ctx, audit.Event{Name: "role_changed", Actor: sess.Sub, IP: c.IP, Details: map[string]string{"from": sess.Role, "to": role}})
			sess.Role = role
		}
		s.Store.MarkSessionChecked(ctx, sess.IDHash)
	case errors.Is(err, auth.ErrRevoked):
		s.Store.DeleteSessionByHash(ctx, sess.IDHash)
		s.Audit.Log(ctx, audit.Event{Name: "session_revoked", Actor: sess.Sub, IP: c.IP, Outcome: "failure", Details: map[string]string{"reason": "sso rejected token", "kind": sess.Kind}})
		httpx.Error(c.W, http.StatusUnauthorized, "session_revoked", "Your access was removed in ClosedDoor.")
		return false
	}
	return true
}

// safeReturn allows only on-site absolute paths. Browsers silently strip TAB/CR/LF and treat "\" like "/", so any
// control character or backslash is refused outright, and the value must parse as a bare path.
func safeReturn(p string) string {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/auth/") || strings.HasPrefix(p, "/login") || strings.HasPrefix(p, "/api/") {
		return "/"
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f || p[i] == '\\' {
			return "/"
		}
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return p
}

// ---- shared helpers for handlers ----

func (c *rc) audit(s *Server, name, outcome, target string, details map[string]string) {
	s.Audit.Log(c.R.Context(), audit.Event{Name: name, Actor: c.Sess.Sub, Email: c.Sess.Email, Target: target, IP: c.IP, UA: c.R.UserAgent(), Outcome: outcome, Details: details})
}

func (c *rc) decode(v any, max int64) bool {
	if err := httpx.Decode(c.W, c.R, v, max); err != nil {
		httpx.Error(c.W, http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

func (c *rc) fail(status int, code, msg string) { httpx.Error(c.W, status, code, msg) }
func (c *rc) ok(v any)                          { httpx.JSON(c.W, http.StatusOK, v) }

// storeErr maps store errors to HTTP responses. Unknown errors are logged and shown generically.
func (s *Server) storeErr(c *rc, err error) {
	var ce store.ConflictError
	switch {
	case errors.As(err, &ce):
		body := map[string]any{"error": "conflict", "message": "This item changed on the server. Reload and try again."}
		if ce.Current != nil {
			body["current"] = ce.Current
		}
		httpx.JSON(c.W, http.StatusConflict, body)
	case errors.Is(err, store.ErrNotFound):
		c.fail(http.StatusNotFound, "not_found", "Not found.")
	case errors.Is(err, store.ErrForbidden):
		c.fail(http.StatusForbidden, "forbidden", "You do not have permission to do that.")
	case errors.Is(err, store.ErrExists):
		c.fail(http.StatusConflict, "exists", "That already exists.")
	case errors.Is(err, store.ErrLimit):
		c.fail(http.StatusConflict, "limit", "A limit was reached.")
	case errors.Is(err, store.ErrLastOwner):
		c.fail(http.StatusConflict, "last_owner", "A space needs at least one owner.")
	case errors.Is(err, store.ErrBadRequest):
		c.fail(http.StatusBadRequest, "bad_request", "The request does not fit the current state. Reload and try again.")
	default:
		logErr("store", err)
		c.fail(http.StatusInternalServerError, "server_error", "Something went wrong on the server.")
	}
}

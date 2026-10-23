package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/auth"
	"github.com/azero/thevault/server/internal/httpx"
	"github.com/azero/thevault/server/internal/store"
)

func urlQuery(s string) string { return url.QueryEscape(s) }

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r, s.Cfg.TrustedIPHeader)
	if !s.loginRL.Allow(ip) {
		http.Redirect(w, r, "/login?msg="+url.QueryEscape("Too many sign-in attempts. Wait a minute."), http.StatusFound)
		return
	}
	if err := s.Auth.Begin(w, r, safeReturn(r.URL.Query().Get("return")), r.URL.Query().Get("silent") == "1", auth.Ext{}); err != nil {
		log.Printf("sso begin: %v", err)
		s.ErrorPage(w, http.StatusBadGateway, "The sign-in service is not reachable right now. Try again shortly.")
	}
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r, s.Cfg.TrustedIPHeader)
	ctx := r.Context()
	res, err := s.Auth.Callback(w, r)
	var lr auth.LoginRequired
	switch {
	case errors.As(err, &lr):
		if lr.Ext.Redirect != "" {
			extRedirect(w, r, lr.Ext, url.Values{"error": {"login_required"}})
			return
		}
		http.Redirect(w, r, "/login?msg="+url.QueryEscape("Your session ended. Sign in again."), http.StatusFound)
		return
	case err != nil:
		log.Printf("sso callback: %v", err)
		s.Audit.Log(ctx, audit.Event{Name: "login_failed", IP: ip, UA: r.UserAgent(), Outcome: "failure", Details: map[string]string{"reason": "callback"}})
		s.ErrorPage(w, http.StatusBadRequest, "Sign-in failed. Start again from the sign-in page.")
		return
	}
	role := auth.RoleFromClaims(res.Roles)
	if err := s.Store.UpsertUser(ctx, store.User{Sub: res.Sub, Email: res.Email, Name: res.Name, Role: role}); err != nil {
		log.Printf("upsert user: %v", err)
		s.ErrorPage(w, http.StatusInternalServerError, "Could not start your session.")
		return
	}
	if u, err := s.Store.GetUser(ctx, res.Sub); err == nil && u.Locked {
		s.Audit.Log(ctx, audit.Event{Name: "login_denied", Actor: res.Sub, Email: res.Email, IP: ip, UA: r.UserAgent(), Outcome: "failure", Details: map[string]string{"reason": "locked"}})
		if res.Ext.Redirect != "" {
			extRedirect(w, r, res.Ext, url.Values{"error": {"access_denied"}})
			return
		}
		s.ErrorPage(w, http.StatusForbidden, "This account is locked. Ask an administrator.")
		return
	}
	if res.Ext.Redirect != "" { // sign-in started by the extension: hand it a one-time code, create no web session
		code, err := s.Store.CreateExtCode(ctx, store.ExtCode{Sub: res.Sub, Email: res.Email, Name: res.Name, Role: role, Challenge: res.Ext.Challenge,
			Redirect: res.Ext.Redirect, AccessToken: res.AccessToken, TokenExpiry: res.TokenExpiry.Unix()})
		if err != nil {
			extRedirect(w, r, res.Ext, url.Values{"error": {"server_error"}})
			return
		}
		extRedirect(w, r, res.Ext, url.Values{"code": {code}})
		return
	}
	cookie, _, err := s.Store.CreateSession(ctx, store.NewSession{Sub: res.Sub, Kind: "web", Label: browserLabel(r.UserAgent()), Role: role, IP: ip, UserAgent: r.UserAgent(),
		AccessToken: res.AccessToken, TokenExpiry: res.TokenExpiry, Idle: webIdle, Absolute: webAbs})
	if err != nil {
		s.ErrorPage(w, http.StatusInternalServerError, "Could not start your session.")
		return
	}
	s.Audit.Log(ctx, audit.Event{Name: "login", Actor: res.Sub, Email: res.Email, IP: ip, UA: r.UserAgent(), Outcome: "success", Details: map[string]string{"role": role, "silent": boolStr(res.Silent)}})
	http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: cookie, Path: "/", MaxAge: int(webAbs.Seconds()), HttpOnly: true, Secure: s.Cfg.SecureCookie, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, safeReturn(res.Return), http.StatusFound)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// browserLabel is a short human label from a User-Agent: "Chrome on Windows". Display only.
func browserLabel(ua string) string {
	b, o := "Browser", ""
	switch {
	case strings.Contains(ua, "Edg/"):
		b = "Edge"
	case strings.Contains(ua, "Firefox/"):
		b = "Firefox"
	case strings.Contains(ua, "Chrome/"):
		b = "Chrome"
	case strings.Contains(ua, "Safari/"):
		b = "Safari"
	}
	switch {
	case strings.Contains(ua, "Windows"):
		o = "Windows"
	case strings.Contains(ua, "Android"):
		o = "Android"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		o = "iOS"
	case strings.Contains(ua, "Mac OS X"):
		o = "macOS"
	case strings.Contains(ua, "Linux"):
		o = "Linux"
	}
	if o == "" {
		return b
	}
	return b + " on " + o
}

// ---- extension sign-in ----
//
// The extension never talks to ClosedDoor itself. It opens /ext/auth in chrome.identity.launchWebAuthFlow with a PKCE
// challenge; the vault runs the normal SSO flow and, instead of a cookie, redirects to the extension's
// https://<id>.chromiumapp.org/ URL with a one-time code. The extension then exchanges the code (plus the PKCE verifier)
// for a bearer token at POST /api/v1/ext/token.

var reExtRedirect = regexp.MustCompile(`^https://([a-p]{32})\.chromiumapp\.org(/[A-Za-z0-9._~/-]*)?$`)

func (s *Server) extRedirectOK(redirect string) bool {
	m := reExtRedirect.FindStringSubmatch(redirect)
	if m == nil {
		return false
	}
	for _, id := range s.Cfg.ExtensionIDs {
		if id == m[1] {
			return true
		}
	}
	return false
}

func extRedirect(w http.ResponseWriter, r *http.Request, e auth.Ext, q url.Values) {
	u, err := url.Parse(e.Redirect)
	if err != nil {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	q.Set("state", e.State)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) extAuth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, challenge, state := q.Get("redirect_uri"), q.Get("code_challenge"), q.Get("state")
	if !s.extRedirectOK(redirect) || !reChallenge.MatchString(challenge) || len(state) > 128 || !reB64u.MatchString(state+"x") || q.Get("code_challenge_method") != "S256" {
		// Never redirect to an unvalidated address: show a page instead.
		s.ErrorPage(w, http.StatusBadRequest, "This sign-in request is not valid. Open the extension again and retry.")
		return
	}
	ip := httpx.ClientIP(r, s.Cfg.TrustedIPHeader)
	if !s.loginRL.Allow(ip) {
		extRedirect(w, r, auth.Ext{Redirect: redirect, State: state}, url.Values{"error": {"rate_limited"}})
		return
	}
	silent := q.Get("prompt") == "none"
	if err := s.Auth.Begin(w, r, "/", silent, auth.Ext{Redirect: redirect, Challenge: challenge, State: state}); err != nil {
		log.Printf("sso begin (ext): %v", err)
		extRedirect(w, r, auth.Ext{Redirect: redirect, State: state}, url.Values{"error": {"sso_unavailable"}})
	}
}

func (s *Server) extToken(c *rc) {
	if !s.extRL.Allow(c.IP) {
		c.fail(http.StatusTooManyRequests, "rate_limited", "Too many attempts.")
		return
	}
	var in struct {
		Code        string `json:"code"`
		Verifier    string `json:"verifier"`
		RedirectURI string `json:"redirect_uri"`
		Label       string `json:"label"`
	}
	if !c.decode(&in, 4<<10) {
		return
	}
	ctx := c.R.Context()
	fail := func() {
		s.Audit.Log(ctx, audit.Event{Name: "ext_token_failed", IP: c.IP, UA: c.R.UserAgent(), Outcome: "failure"})
		c.fail(http.StatusBadRequest, "invalid_grant", "The sign-in code is invalid or expired.")
	}
	if !reVerifier.MatchString(in.Verifier) || len(in.Code) > 100 {
		fail()
		return
	}
	code, err := s.Store.ConsumeExtCode(ctx, in.Code)
	if err != nil {
		fail()
		return
	}
	sum := sha256.Sum256([]byte(in.Verifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(code.Challenge)) != 1 || in.RedirectURI != code.Redirect {
		fail()
		return
	}
	// Renewal: the caller proves it holds the previous token, so unlock state carries over and the old token dies.
	var unlocked int64
	if h, ok := strings.CutPrefix(c.R.Header.Get("Authorization"), "Bearer "); ok {
		if old, err := s.Store.GetSession(ctx, strings.TrimSpace(h), webIdle, extIdle); err == nil && old.Kind == "ext" && old.Sub == code.Sub {
			if old.UnlockedUntil > time.Now().Unix() {
				unlocked = old.UnlockedUntil
			}
			s.Store.DeleteSessionByHash(ctx, old.IDHash)
		}
	}
	label := cleanText(in.Label, 80)
	if label == "" {
		label = "Browser extension"
	}
	exp := time.Unix(code.TokenExpiry, 0)
	token, _, err := s.Store.CreateSession(ctx, store.NewSession{Sub: code.Sub, Kind: "ext", Label: label, Role: code.Role, IP: c.IP, UserAgent: c.R.UserAgent(),
		AccessToken: code.AccessToken, TokenExpiry: exp, Idle: extIdle, Absolute: extAbs, UnlockedUntil: unlocked, Prefix: bearerPrefix})
	if err != nil {
		c.fail(http.StatusInternalServerError, "server_error", "Could not create the session.")
		return
	}
	s.Audit.Log(ctx, audit.Event{Name: "ext_device_added", Actor: code.Sub, Email: code.Email, IP: c.IP, UA: c.R.UserAgent(), Outcome: "success", Details: map[string]string{"label": label, "renewed": boolStr(unlocked > 0)}})
	c.ok(map[string]any{"token": token, "expires_at": time.Now().Add(extAbs).Unix(), "user": userJSON{Sub: code.Sub, Email: code.Email, Name: code.Name, Role: code.Role}})
}

// Package auth signs people in through ClosedDoor (OpenID Connect, authorization code + PKCE) and maps its per-app
// "roles" claim to TheVault roles. Being granted the app in ClosedDoor is what lets someone in at all; the only role
// the claim adds is "admin".
//
// ClosedDoor has no refresh tokens and no back-channel logout, so sessions are short and re-validated against
// /userinfo (see api.Server.authenticate).
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	RoleMember = "member"
	RoleAdmin  = "admin"
)

// RoleFromClaims: everyone ClosedDoor lets in is a member; the "admin" label adds the admin pages.
func RoleFromClaims(roles []string) string {
	for _, r := range roles {
		if r == RoleAdmin {
			return RoleAdmin
		}
	}
	return RoleMember
}

type Config struct {
	Issuer, ClientID, ClientSecret string
	RedirectURL                    string
	Secure                         bool
	SigningKey                     []byte
}

type Authenticator struct {
	cfg Config
	hc  *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
	userinfo string
}

func New(cfg Config) *Authenticator {
	return &Authenticator{cfg: cfg, hc: &http.Client{Timeout: 10 * time.Second}}
}

// ensure discovers the provider on first use and retries later if ClosedDoor was unreachable, so the vault still
// starts during an SSO outage.
func (a *Authenticator) ensure(ctx context.Context) (*oidc.Provider, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.provider != nil {
		return a.provider, nil
	}
	ctx = oidc.ClientContext(ctx, a.hc)
	p, err := oidc.NewProvider(ctx, a.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("sso discovery: %w", err)
	}
	var meta struct {
		UserInfo string `json:"userinfo_endpoint"`
	}
	if err := p.Claims(&meta); err != nil || meta.UserInfo == "" {
		return nil, errors.New("sso discovery: no userinfo_endpoint")
	}
	a.provider, a.userinfo = p, meta.UserInfo
	return p, nil
}

func (a *Authenticator) oauth(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID: a.cfg.ClientID, ClientSecret: a.cfg.ClientSecret, Endpoint: p.Endpoint(), RedirectURL: a.cfg.RedirectURL,
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// Ext carries the parameters of a sign-in that was started by the browser extension.
type Ext struct {
	Redirect  string `json:"xr,omitempty"`
	Challenge string `json:"xc,omitempty"`
	State     string `json:"xs,omitempty"`
}

// flow is the pre-login state, kept in a signed cookie so it survives restarts.
type flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Silent   bool   `json:"q,omitempty"`
	Ext
	Exp int64 `json:"e"`
}

const flowCookie = "vault_oidc"

func (a *Authenticator) sign(payload []byte) string {
	m := hmac.New(sha256.New, a.cfg.SigningKey)
	m.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *Authenticator) unsign(v string) ([]byte, bool) {
	p, s, ok := strings.Cut(v, ".")
	if !ok {
		return nil, false
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(p)
	sig, err2 := base64.RawURLEncoding.DecodeString(s)
	if err1 != nil || err2 != nil {
		return nil, false
	}
	m := hmac.New(sha256.New, a.cfg.SigningKey)
	m.Write(payload)
	return payload, hmac.Equal(sig, m.Sum(nil))
}

func rnd(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Begin redirects the browser to ClosedDoor. silent adds prompt=none so a still-valid SSO session re-authenticates
// without showing a form.
func (a *Authenticator) Begin(w http.ResponseWriter, r *http.Request, returnPath string, silent bool, ext Ext) error {
	p, err := a.ensure(r.Context())
	if err != nil {
		return err
	}
	f := flow{State: rnd(24), Nonce: rnd(24), Verifier: oauth2.GenerateVerifier(), Return: returnPath, Silent: silent, Ext: ext, Exp: time.Now().Add(10 * time.Minute).Unix()}
	b, _ := json.Marshal(f)
	// SameSite=Lax (not Strict): the callback is a cross-site top-level navigation from ClosedDoor and must carry this cookie.
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: a.sign(b), Path: "/auth/", MaxAge: 600, HttpOnly: true, Secure: a.cfg.Secure, SameSite: http.SameSiteLaxMode})
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(f.Verifier), oidc.Nonce(f.Nonce)}
	if silent {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "none"))
	}
	http.Redirect(w, r, a.oauth(p).AuthCodeURL(f.State, opts...), http.StatusFound)
	return nil
}

// Result is a verified sign-in.
type Result struct {
	Sub, Email, Name string
	Roles            []string
	AccessToken      string
	TokenExpiry      time.Time
	Return           string
	Silent           bool
	Ext              Ext
}

var (
	ErrLoginRequired = errors.New("login required") // prompt=none with no SSO session
	ErrBadCallback   = errors.New("invalid sign-in response")
	ErrRevoked       = errors.New("sso says this session is no longer valid")
	ErrTransient     = errors.New("sso temporarily unreachable")
)

// CallbackExt is returned alongside ErrLoginRequired so the extension flow can report the failure to its redirect.
type LoginRequired struct{ Ext Ext }

func (e LoginRequired) Error() string   { return ErrLoginRequired.Error() }
func (e LoginRequired) Is(t error) bool { return t == ErrLoginRequired }

// Callback validates state, PKCE, nonce, issuer and signature, and returns the identity.
func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) (*Result, error) {
	c, err := r.Cookie(flowCookie)
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: "", Path: "/auth/", MaxAge: -1, HttpOnly: true, Secure: a.cfg.Secure, SameSite: http.SameSiteLaxMode})
	if err != nil {
		return nil, ErrBadCallback
	}
	raw, ok := a.unsign(c.Value)
	if !ok {
		return nil, ErrBadCallback
	}
	var f flow
	if json.Unmarshal(raw, &f) != nil || time.Now().Unix() > f.Exp {
		return nil, ErrBadCallback
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.State)) != 1 {
		return nil, ErrBadCallback
	}
	if strings.TrimRight(q.Get("iss"), "/") != a.cfg.Issuer { // RFC 9207; ClosedDoor always sends it, so a missing one is refused too
		return nil, ErrBadCallback
	}
	if e := q.Get("error"); e != "" {
		if f.Silent && (e == "login_required" || e == "interaction_required" || e == "consent_required") {
			return nil, LoginRequired{Ext: f.Ext}
		}
		return nil, fmt.Errorf("%w: %s", ErrBadCallback, e)
	}
	code := q.Get("code")
	if code == "" {
		return nil, ErrBadCallback
	}
	p, err := a.ensure(r.Context())
	if err != nil {
		return nil, err
	}
	ctx := oidc.ClientContext(r.Context(), a.hc)
	tok, err := a.oauth(p).Exchange(ctx, code, oauth2.VerifierOption(f.Verifier))
	if err != nil {
		return nil, fmt.Errorf("%w: token exchange", ErrBadCallback)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, fmt.Errorf("%w: no id_token", ErrBadCallback)
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: a.cfg.ClientID, SupportedSigningAlgs: []string{"RS256"}}).Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("%w: id_token", ErrBadCallback)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(f.Nonce)) != 1 {
		return nil, ErrBadCallback
	}
	var cl struct {
		Email string   `json:"email"`
		Name  string   `json:"name"`
		Roles []string `json:"roles"`
	}
	if err := idt.Claims(&cl); err != nil {
		return nil, ErrBadCallback
	}
	exp := tok.Expiry
	if exp.IsZero() {
		exp = time.Now().Add(time.Hour)
	}
	return &Result{Sub: idt.Subject, Email: cl.Email, Name: cl.Name, Roles: cl.Roles, AccessToken: tok.AccessToken, TokenExpiry: exp, Return: f.Return, Silent: f.Silent, Ext: f.Ext}, nil
}

// UserInfo re-validates a session with ClosedDoor. ClosedDoor re-checks that the user is active and still granted
// this app, so this is how a disabled user loses access without back-channel logout. 401/403 -> ErrRevoked.
func (a *Authenticator) UserInfo(ctx context.Context, accessToken string) ([]string, error) {
	if _, err := a.ensure(ctx); err != nil {
		return nil, ErrTransient
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.userinfo, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, ErrTransient
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return nil, ErrRevoked
	case resp.StatusCode != 200:
		return nil, ErrTransient
	}
	var cl struct {
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&cl); err != nil {
		return nil, ErrTransient
	}
	return cl.Roles, nil
}

// EndSessionURL returns ClosedDoor's logout URL if it advertises one.
func (a *Authenticator) EndSessionURL(ctx context.Context) string {
	p, err := a.ensure(ctx)
	if err != nil {
		return ""
	}
	var m struct {
		End string `json:"end_session_endpoint"`
	}
	if p.Claims(&m) != nil {
		return ""
	}
	return m.End
}

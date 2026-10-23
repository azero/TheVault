package e2e

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azero/thevault/server/internal/app"
	"github.com/azero/thevault/server/internal/config"
	"github.com/azero/thevault/server/internal/store"
)

// ---- fake ClosedDoor ----

type fakeSSO struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]authz
	Roles  []string
	Login  bool // the SSO browser session exists (for prompt=none)
	Revoke bool // /userinfo answers 401
	Down   bool // /userinfo answers 503
	Expiry int  // access token lifetime in seconds
	Sub    string
	Email  string
	Name   string
}

type authz struct{ challenge, nonce, redirect string }

func newFakeSSO(t *testing.T) *fakeSSO {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeSSO{t: t, key: k, codes: map[string]authz{}, Roles: nil, Login: true, Expiry: 3600, Sub: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Email: "ana@example.com", Name: "Ana Admin"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSSO) set(fn func()) { f.mu.Lock(); fn(); f.mu.Unlock() }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (f *fakeSSO) jwt(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	c, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	return in + "." + b64(sig)
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func (f *fakeSSO) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	base := f.srv.URL
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
			"userinfo_endpoint": base + "/userinfo", "jwks_uri": base + "/jwks.json", "end_session_endpoint": base + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	case "/jwks.json":
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(f.key.N.Bytes()), "e": b64(big.NewInt(int64(f.key.E)).Bytes())}}})
	case "/authorize":
		q := r.URL.Query()
		redirect := q.Get("redirect_uri")
		if q.Get("client_id") != "app_test" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("response_type") != "code" {
			http.Error(w, "bad authorize request", 400)
			return
		}
		u, _ := url.Parse(redirect)
		rq := u.Query()
		rq.Set("state", q.Get("state"))
		rq.Set("iss", base)
		if q.Get("prompt") == "none" && !f.Login {
			rq.Set("error", "login_required")
		} else {
			code := "code_" + b64(randBytes(8))
			f.codes[code] = authz{q.Get("code_challenge"), q.Get("nonce"), redirect}
			rq.Set("code", code)
		}
		u.RawQuery = rq.Encode()
		http.Redirect(w, r, u.String(), 302)
	case "/token":
		r.ParseForm()
		user, pass, _ := r.BasicAuth()
		if user == "" {
			user, pass = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if user != "app_test" || pass != "cds_secret" {
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		}
		a, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || a.challenge != b64(sum[:]) || r.PostForm.Get("redirect_uri") != a.redirect {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		now := time.Now().Unix()
		roles := f.Roles
		if roles == nil {
			roles = []string{}
		}
		idt := f.jwt(map[string]any{"iss": base, "sub": f.Sub, "aud": "app_test", "iat": now, "exp": now + 3600, "nonce": a.nonce, "email": f.Email, "name": f.Name, "roles": roles})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at_" + b64(randBytes(8)), "token_type": "Bearer", "expires_in": f.Expiry, "id_token": idt})
	case "/userinfo":
		switch {
		case f.Down:
			http.Error(w, "down", 503)
		case f.Revoke || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer at_"):
			http.Error(w, "revoked", 401)
		default:
			roles := f.Roles
			if roles == nil {
				roles = []string{}
			}
			json.NewEncoder(w).Encode(map[string]any{"sub": f.Sub, "roles": roles})
		}
	default:
		http.NotFound(w, r)
	}
}

// ---- fake SkyNet ----

type fakeSky struct {
	srv      *httptest.Server
	mu       sync.Mutex
	Events   []map[string]any
	Results  map[int64][2]string
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	agentID  string
	apiKey   string
	pending  []map[string]string
	Enrolled int
	Status   int // forced ingest status (0 = 200)
}

func newFakeSky(t *testing.T) *fakeSky {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeSky{pub: pub, priv: priv, agentID: "agt_test", apiKey: "agt_test.secretsecret", Results: map[int64][2]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSky) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/api/v1/enroll" {
		var in struct{ Token string }
		json.NewDecoder(r.Body).Decode(&in)
		if in.Token != "skyenr_ok" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"invalid or expired enrollment token"}`))
			return
		}
		f.Enrolled++
		json.NewEncoder(w).Encode(map[string]string{"agent_id": f.agentID, "api_key": f.apiKey, "kind": "adapter", "command_pubkey": base64.StdEncoding.EncodeToString(f.pub)})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.apiKey {
		w.WriteHeader(401)
		return
	}
	switch {
	case r.URL.Path == "/api/v1/ingest":
		if f.Status != 0 {
			w.WriteHeader(f.Status)
			return
		}
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, _ := gzip.NewReader(r.Body)
			body = zr
		}
		b, _ := io.ReadAll(body)
		for _, line := range bytes.Split(b, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var e map[string]any
			if json.Unmarshal(line, &e) == nil {
				f.Events = append(f.Events, e)
			}
		}
		w.Write([]byte(`{"accepted":1}`))
	case r.URL.Path == "/api/v1/commands":
		cmds := f.pending
		f.pending = nil
		if cmds == nil {
			cmds = []map[string]string{}
		}
		json.NewEncoder(w).Encode(map[string]any{"commands": cmds})
	case strings.HasPrefix(r.URL.Path, "/api/v1/commands/") && strings.HasSuffix(r.URL.Path, "/result"):
		var in struct{ Status, Message string }
		json.NewDecoder(r.Body).Decode(&in)
		var id int64
		for _, c := range strings.Split(strings.Trim(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/commands/"), "/result"), "/"), "/") {
			for _, ch := range c {
				id = id*10 + int64(ch-'0')
			}
		}
		f.Results[id] = [2]string{in.Status, in.Message}
		w.Write([]byte(`{"ok":true}`))
	default:
		w.WriteHeader(404)
	}
}

// command signs a command the way SkyNet's server does and queues it for the next poll.
func (f *fakeSky) command(id int64, agent, action string, params map[string]any, dry bool, issued, expires int64) {
	p := map[string]any{"v": 1, "id": id, "agent_id": agent, "action": action, "params": params, "dry_run": dry, "nonce": "n", "issued_at": issued, "expires_at": expires}
	raw, _ := json.Marshal(p)
	sig := ed25519.Sign(f.priv, append([]byte("skynet-cmd-v1\n"), raw...))
	f.mu.Lock()
	f.pending = append(f.pending, map[string]string{"payload": base64.StdEncoding.EncodeToString(raw), "sig": base64.StdEncoding.EncodeToString(sig)})
	f.mu.Unlock()
}

func (f *fakeSky) events(action string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, e := range f.Events {
		if e["action"] == action {
			out = append(out, e)
		}
	}
	return out
}

// ---- the vault under test ----

type env struct {
	t    *testing.T
	sso  *fakeSSO
	st   *store.Store
	app  *app.App
	srv  *httptest.Server
	cfg  *config.Config
	ctx  context.Context
	stop context.CancelFunc
}

const extID = "abcdefghijklmnopabcdefghijklmnop"

type opt func(m map[string]string, e *env)

func newEnv(t *testing.T, opts ...opt) *env {
	t.Helper()
	e := &env{t: t, sso: newFakeSSO(t)}
	var h http.Handler
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(e.srv.Close)
	m := map[string]string{
		"VAULT_DATA_DIR": t.TempDir(), "VAULT_PUBLIC_URL": e.srv.URL, "VAULT_OIDC_ISSUER": e.sso.srv.URL, "VAULT_OIDC_CLIENT_ID": "app_test",
		"VAULT_OIDC_CLIENT_SECRET": "cds_secret", "VAULT_EXTENSION_IDS": extID, "VAULT_TRUSTED_IP_HEADER": "X-Test-IP",
	}
	for _, o := range opts {
		o(m, e)
	}
	cfg, err := config.Load(func(k string) string { return m[k] })
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	e.st, err = store.Open(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.st.Close() })
	e.app, err = app.New(cfg, e.st, "test")
	if err != nil {
		t.Fatal(err)
	}
	h = e.app.Handler
	e.ctx, e.stop = context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.app.Run(e.ctx); close(done) }()
	// registered last, so it runs first: stop the background work before the store is closed and the temp dir removed
	t.Cleanup(func() { e.stop(); <-done })
	return e
}

// ---- a browser-like client ----

type client struct {
	t      *testing.T
	e      *env
	hc     *http.Client
	csrf   string
	bearer string
	ip     string
}

func (e *env) newClient() *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: e.t, e: e, hc: &http.Client{Jar: jar, Timeout: 15 * time.Second}}
}

// login signs in through the fake SSO as (sub, email, roles) and returns a client with a web session.
func (e *env) login(sub, email string, roles ...string) *client {
	e.t.Helper()
	e.sso.set(func() {
		e.sso.Sub, e.sso.Email, e.sso.Roles, e.sso.Name = sub, email, roles, strings.Split(email, "@")[0]
	})
	c := e.newClient()
	resp, err := c.hc.Get(e.srv.URL + "/auth/login?return=/")
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/" {
		e.t.Fatalf("login ended at %s (status %d)", resp.Request.URL, resp.StatusCode)
	}
	var sess struct{ CSRF string }
	c.getJSON("/api/v1/session", &sess)
	c.csrf = sess.CSRF
	return c
}

func (c *client) do(method, path string, body any, hdr map[string]string) (int, []byte, http.Header) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	} else if method != "GET" && c.csrf != "" {
		req.Header.Set("X-Vault-CSRF", c.csrf)
	}
	if c.ip != "" {
		req.Header.Set("X-Test-IP", c.ip)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func (c *client) getJSON(path string, out any) int {
	st, b, _ := c.do("GET", path, nil, nil)
	if out != nil {
		json.Unmarshal(b, out)
	}
	return st
}

// call does a JSON request, expects `want`, and decodes the body into out (if not nil).
func (c *client) call(method, path string, body any, want int, out any) {
	c.t.Helper()
	st, b, _ := c.do(method, path, body, nil)
	if st != want {
		c.t.Fatalf("%s %s: want %d got %d: %s", method, path, want, st, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			c.t.Fatalf("%s %s: bad json %v: %s", method, path, err, b)
		}
	}
}

func (c *client) status(method, path string, body any) (int, map[string]any) {
	st, b, _ := c.do(method, path, body, nil)
	m := map[string]any{}
	json.Unmarshal(b, &m)
	return st, m
}

// ---- payload factories (the server cannot check ciphertext, only shape) ----

func envelope() string { return "1." + b64(randBytes(12)) + "." + b64(randBytes(40)) }
func proof() string    { return b64(randBytes(32)) }
func pub() string      { return b64(randBytes(65)) }
func sig() string      { return b64(randBytes(64)) }
func newID() string    { return strings.ReplaceAll(strings.ToLower(b64(randBytes(24))[:32]), "_", "a") }

func hexID() string {
	const hex = "0123456789abcdef"
	b := randBytes(32)
	out := make([]byte, 32)
	for i := range out {
		out[i] = hex[int(b[i])%16]
	}
	return string(out)
}

type vaultMaterial struct {
	Auth, RecoveryProof string
	Setup               map[string]any
}

func newMaterial() vaultMaterial {
	m := vaultMaterial{Auth: proof(), RecoveryProof: proof()}
	m.Setup = map[string]any{"kdf": "pbkdf2-sha256", "iterations": 1000000, "salt": b64(randBytes(32)), "auth": m.Auth, "key_version": 1, "wrapped_uk": envelope(),
		"enc_pub": pub(), "sig_pub": pub(), "enc_priv": envelope(), "sig_priv": envelope(), "recovery": map[string]any{"proof": m.RecoveryProof, "wrapped_uk": envelope()}}
	return m
}

func wrap() map[string]any { return map[string]any{"eph": pub(), "ct": envelope(), "sig": sig()} }

var _ = context.Background

func jsonUnmarshal(b []byte, v any) { json.Unmarshal(b, v) }

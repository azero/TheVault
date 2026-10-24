package automation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/closeddoorapi"
	"github.com/azero/thevault/server/internal/config"
	"github.com/azero/thevault/server/internal/store"
)

// ---- catalog ----

func TestCatalogRules(t *testing.T) {
	if len(Catalog) == 0 || len(Catalog) > 100 {
		t.Fatalf("ClosedDoor accepts 1..100 scopes, have %d", len(Catalog))
	}
	seen := map[string]bool{}
	for _, s := range Catalog {
		if seen[s.Name] {
			t.Errorf("duplicate scope %s", s.Name)
		}
		seen[s.Name] = true
		if len(s.Name) == 0 || len(s.Name) > 64 {
			t.Errorf("scope name length: %q", s.Name)
		}
		for _, r := range s.Name {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:-", r)) {
				t.Errorf("scope %q has the character %q (allowed: a-z 0-9 _ . : -)", s.Name, r)
			}
		}
		if !strings.Contains(s.Name, ":") {
			t.Errorf("scope %q is not <resource>:<action>", s.Name)
		}
		if len(s.Description) == 0 || len(s.Description) > 190 {
			t.Errorf("scope %s: description is %d characters (1..190)", s.Name, len(s.Description))
		}
		if s.Category == "" {
			t.Errorf("scope %s has no SkyNet category", s.Name)
		}
	}
}

func TestCatalogTextIsNamePairedWithDescription(t *testing.T) {
	lines := strings.Split(strings.TrimRight(CatalogText(), "\n"), "\n")
	if len(lines) != len(Catalog) {
		t.Fatalf("%d lines for %d scopes", len(lines), len(Catalog))
	}
	for i, l := range lines {
		if l != Catalog[i].Name+"  "+Catalog[i].Description {
			t.Errorf("line %d: %q", i, l)
		}
	}
}

func TestEveryRouteScopeIsInTheCatalogAndEveryCatalogScopeIsUsed(t *testing.T) {
	s := &Server{}
	used := map[string]bool{}
	unscoped := 0
	for _, rt := range s.routes() {
		if rt.Scope == "" {
			unscoped++
			if rt.Pattern != "/api/v1/whoami" {
				t.Errorf("%s %s needs a scope", rt.Method, rt.Pattern)
			}
			continue
		}
		if _, ok := scopeInfo(rt.Scope); !ok {
			t.Errorf("%s %s requires %q which is not in the catalog", rt.Method, rt.Pattern, rt.Scope)
		}
		used[rt.Scope] = true
		if !rt.Admin {
			t.Errorf("%s %s: every scoped route is an administration route and must need the admin role for user keys", rt.Method, rt.Pattern)
		}
	}
	if unscoped != 1 {
		t.Errorf("only whoami may be unscoped, found %d", unscoped)
	}
	for _, sc := range Catalog {
		if !used[sc.Name] {
			t.Errorf("catalog scope %s is used by no route", sc.Name)
		}
	}
}

func TestNoRouteTouchesVaultContent(t *testing.T) {
	s := &Server{}
	for _, rt := range s.routes() {
		for _, bad := range []string{"item", "vault", "sync", "space", "folder", "key", "blob", "export", "secret", "tag", "note", "wrap", "kdf", "cipher", "salt", "proof", "recover", "member", "rotat", "director", "backup/", "download", "password"} {
			if strings.Contains(strings.ToLower(rt.Pattern), bad) {
				t.Errorf("%s %s: the automation API must expose no vault content, and %q suggests it does", rt.Method, rt.Pattern, bad)
			}
		}
	}
}

func TestDocsMentionEveryScopeAndHoldTheCatalogBlock(t *testing.T) {
	b, err := os.ReadFile("../../../docs/automation-api.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, s := range Catalog {
		if !strings.Contains(doc, "`"+s.Name+"`") {
			t.Errorf("docs/automation-api.md does not mention scope %s", s.Name)
		}
	}
	if !strings.Contains(doc, CatalogText()) {
		t.Errorf("docs/automation-api.md must contain the exact output of `thevault api-scopes`:\n%s", CatalogText())
	}
	for _, rt := range (&Server{}).routes() {
		if !strings.Contains(doc, rt.Method+" "+rt.Pattern) {
			t.Errorf("docs/automation-api.md does not document %s %s", rt.Method, rt.Pattern)
		}
	}
}

// ---- harness ----

const goodKey = "cdk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // cdk_ + 43 characters

type stubVerifier struct {
	mu    sync.Mutex
	calls int
	who   map[string]*closeddoorapi.Principal
	err   error
}

func (v *stubVerifier) Verify(_ context.Context, token string) (*closeddoorapi.Principal, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	if v.err != nil {
		return nil, v.err
	}
	return v.who[token], nil
}

func (v *stubVerifier) count() int { v.mu.Lock(); defer v.mu.Unlock(); return v.calls }

func key(n byte) string { return "cdk_" + strings.Repeat(string('A'+n), 43) }

func principal(typ, sub, keyID, scope string, roles ...string) *closeddoorapi.Principal {
	p := &closeddoorapi.Principal{Active: true, Kind: "api_key", Subject: sub, Type: typ, KeyID: keyID, KeyName: "name of " + keyID, Scope: scope, Roles: roles}
	if typ == "user" {
		p.Email, p.Name = sub+"@example.com", sub
	}
	return p
}

type rig struct {
	t   *testing.T
	st  *store.Store
	v   *stubVerifier
	mux *http.ServeMux
	srv *Server
	// events recorded by the sink (what SkyNet would receive)
	mu     sync.Mutex
	events []audit.Event
}

func newRig(t *testing.T, rate int) *rig {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r := &rig{t: t, st: st, v: &stubVerifier{who: map[string]*closeddoorapi.Principal{}}, mux: http.NewServeMux()}
	au := audit.New(st)
	au.AddSink(func(e audit.Event) { r.mu.Lock(); r.events = append(r.events, e); r.mu.Unlock() })
	cfg := &config.Config{TrustedIPHeader: "X-Test-IP", APIRatePerMinute: rate, ExtensionIDs: []string{"abcdefghijklmnopabcdefghijklmnop"}}
	r.srv, err = New(Options{Cfg: cfg, Store: st, Audit: au, Version: "test", Verifier: r.v})
	if err != nil {
		t.Fatal(err)
	}
	r.srv.Routes(r.mux)
	return r
}

func (r *rig) grant(token string, p *closeddoorapi.Principal) { r.v.who[token] = p }

func (r *rig) do(method, path, token string, body string, hdr map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	r.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "192.0.2.1:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	r.mux.ServeHTTP(w, req)
	m := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &m)
	return w, m
}

func (r *rig) eventsNamed(name string) []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, e := range r.events {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

func (r *rig) addUser(sub, role string, locked bool) {
	r.t.Helper()
	ctx := context.Background()
	if err := r.st.UpsertUser(ctx, store.User{Sub: sub, Email: sub + "@example.com", Name: sub, Role: role}); err != nil {
		r.t.Fatal(err)
	}
	if locked {
		r.st.SetUserLocked(ctx, sub, true)
	}
}

func wantStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d, want %d: %s", w.Code, want, w.Body.String())
	}
}

func wantError(t *testing.T, w *httptest.ResponseRecorder, m map[string]any, status int, code string) {
	t.Helper()
	wantStatus(t, w, status)
	if m["error"] != code || m["message"] == "" || m["message"] == nil {
		t.Fatalf("error body: %v", m)
	}
}

// ---- authentication ----

func TestMissingCredentialIsRefusedWithoutAskingClosedDoor(t *testing.T) {
	r := newRig(t, 120)
	w, m := r.do("GET", "/api/v1/whoami", "", "", nil)
	wantError(t, w, m, 401, "invalid_token")
	if w.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", w.Header())
	}
	// a cookie is not a credential
	w, m = r.do("GET", "/api/v1/whoami", "", "", map[string]string{"Cookie": "__Host-vault_session=abc; vault_session=abc", "X-Vault-CSRF": "x"})
	wantError(t, w, m, 401, "invalid_token")
	if r.v.count() != 0 || len(r.eventsNamed("api_auth_failed")) != 0 {
		t.Fatalf("no credential was presented: introspections=%d", r.v.count())
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Fatal("the API never sets cookies")
	}
}

func TestMalformedCredentialsNeverReachClosedDoor(t *testing.T) {
	r := newRig(t, 120)
	r.grant(goodKey, principal("service", "svc_1", "key_1", "status:read"))
	cases := map[string]string{
		"wrong prefix":      "cds_" + strings.Repeat("A", 43),
		"extension session": "vxs_" + strings.Repeat("A", 43),
		"too short":         "cdk_short",
		"too long":          "cdk_" + strings.Repeat("A", 44),
		"bad characters":    "cdk_" + strings.Repeat("A", 42) + "!",
		"huge":              "cdk_" + strings.Repeat("A", 5000),
		"an access token":   "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
	}
	for name, tok := range cases {
		w, m := r.do("GET", "/api/v1/whoami", tok, "", nil)
		if w.Code != 401 || m["error"] != "invalid_token" {
			t.Errorf("%s: %d %v", name, w.Code, m)
		}
	}
	// a non-Bearer scheme without X-API-Key, and an empty Bearer
	w, _ := r.do("GET", "/api/v1/whoami", "", "", map[string]string{"Authorization": "Basic dXNlcjpwYXNz"})
	wantStatus(t, w, 401)
	w, _ = r.do("GET", "/api/v1/whoami", "", "", map[string]string{"Authorization": "Bearer "})
	wantStatus(t, w, 401)
	if r.v.count() != 0 {
		t.Fatalf("ClosedDoor was asked %d times about credentials that are not shaped like keys", r.v.count())
	}
	evs := r.eventsNamed("api_auth_failed")
	if len(evs) != len(cases)+2 {
		t.Fatalf("expected an api_auth_failed per rejected credential, got %d", len(evs))
	}
	for _, e := range evs {
		if e.Details["reason"] != "malformed" || e.Outcome != "failure" || e.IP != "192.0.2.1" || e.Details["key_prefix"] != "" {
			t.Fatalf("event: %+v", e)
		}
		for _, v := range e.Details {
			if strings.Contains(v, "AAAAAAAA") || strings.Contains(v, "eyJ") {
				t.Fatalf("a credential leaked into the event: %+v", e)
			}
		}
	}
}

func TestInactiveKeyAnd401Shape(t *testing.T) {
	r := newRig(t, 120)
	w, m := r.do("GET", "/api/v1/whoami", goodKey, "", nil)
	wantError(t, w, m, 401, "invalid_token")
	if w.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatal("challenge missing")
	}
	evs := r.eventsNamed("api_auth_failed")
	if len(evs) != 1 || evs[0].Details["reason"] != "invalid_token" || evs[0].Details["key_prefix"] != goodKey[:8] {
		t.Fatalf("events: %+v", evs)
	}
	for _, v := range evs[0].Details {
		if strings.Contains(v, goodKey[8:]) {
			t.Fatal("the key leaked")
		}
	}
	// an access-token style answer is not accepted either
	p := principal("user", "u1", "key_x", "status:read", "admin")
	p.Kind = "access_token"
	r.grant(goodKey, p)
	w, m = r.do("GET", "/api/v1/whoami", goodKey, "", nil)
	wantError(t, w, m, 401, "invalid_token")
}

func TestClosedDoorUnavailableFailsClosed(t *testing.T) {
	r := newRig(t, 120)
	r.grant(goodKey, principal("service", "svc_1", "key_1", "status:read"))
	r.v.err = errors.New("closeddoorapi: SSO server unreachable: dial tcp secret-internal-host:443")
	w, m := r.do("GET", "/api/v1/status", goodKey, "", nil)
	wantError(t, w, m, 503, "authentication_unavailable")
	if strings.Contains(w.Body.String(), "secret-internal-host") || strings.Contains(w.Body.String(), "dial") {
		t.Fatalf("internals leaked: %s", w.Body.String())
	}
	evs := r.eventsNamed("api_auth_failed")
	if len(evs) != 1 || evs[0].Details["reason"] != "unavailable" {
		t.Fatalf("events: %+v", evs)
	}
	// an outage must not lock people out: unavailable answers do not count as failed authentications
	for i := 0; i < 30; i++ {
		r.do("GET", "/api/v1/status", goodKey, "", nil)
	}
	r.v.err = nil
	w, _ = r.do("GET", "/api/v1/whoami", goodKey, "", nil)
	wantStatus(t, w, 200)
}

func TestWhoamiShapes(t *testing.T) {
	r := newRig(t, 120)
	r.grant(key(1), principal("service", "svc_1", "key_1", "status:read audit:read"))
	r.grant(key(2), principal("user", "u1", "key_2", "users:read", "admin"))
	w, m := r.do("GET", "/api/v1/whoami", key(1), "", nil)
	wantStatus(t, w, 200)
	if m["sub"] != "svc_1" || m["principal"] != "service" || m["key_id"] != "key_1" || m["key_name"] != "name of key_1" {
		t.Fatalf("%v", m)
	}
	if sc := m["scopes"].([]any); len(sc) != 2 || sc[0] != "status:read" {
		t.Fatalf("scopes: %v", m["scopes"])
	}
	if roles, ok := m["roles"].([]any); !ok || len(roles) != 0 {
		t.Fatalf("roles must be an empty array, not null: %v", m["roles"])
	}
	if _, has := m["email"]; has {
		t.Fatal("service keys have no email")
	}
	w, m = r.do("GET", "/api/v1/whoami", key(2), "", nil)
	wantStatus(t, w, 200)
	if m["principal"] != "user" || m["email"] != "u1@example.com" || m["name"] != "u1" || m["roles"].([]any)[0] != "admin" {
		t.Fatalf("%v", m)
	}
	// X-API-Key works, also behind a proxy that has its own Authorization header
	w, _ = r.do("GET", "/api/v1/whoami", "", "", map[string]string{"X-API-Key": key(1), "Authorization": "Basic dXNlcjpwYXNz"})
	wantStatus(t, w, 200)
	// whoami is not audited as api_call (no scope, not mutating)
	if len(r.eventsNamed("api_call")) != 0 {
		t.Fatal("whoami must not produce api_call events")
	}
}

// ---- authorization ----

func TestScopeAndRoleChecks(t *testing.T) {
	r := newRig(t, 120)
	r.addUser("u_admin", "admin", false)
	r.addUser("u_locked_admin", "admin", true)
	r.grant(key(1), principal("service", "svc_1", "key_1", "audit:read"))
	r.grant(key(2), principal("user", "u_admin", "key_2", "audit:read users:read", "admin"))
	r.grant(key(3), principal("user", "u_member", "key_3", "audit:read"))                     // scope but no role
	r.grant(key(4), principal("user", "u_member2", "key_4", "audit:read", "editor", "Admin")) // near misses are not admin
	r.grant(key(5), principal("user", "u_locked_admin", "key_5", "audit:read", "admin"))      // locked in TheVault
	r.grant(key(6), principal("service", "svc_2", "key_6", "status:read"))

	// missing scope
	w, m := r.do("GET", "/api/v1/audit", key(6), "", nil)
	wantError(t, w, m, 403, "insufficient_scope")
	if m["needs"] != "audit:read" || w.Header().Get("WWW-Authenticate") != `Bearer error="insufficient_scope", scope="audit:read"` {
		t.Fatalf("needs/challenge: %v %v", m, w.Header())
	}
	// service key: scope alone is enough
	w, _ = r.do("GET", "/api/v1/audit", key(1), "", nil)
	wantStatus(t, w, 200)
	// user key with the admin role
	w, _ = r.do("GET", "/api/v1/audit", key(2), "", nil)
	wantStatus(t, w, 200)
	// user keys without the role: forbidden although the scope is held
	for _, k := range []byte{3, 4, 5} {
		w, m = r.do("GET", "/api/v1/audit", key(k), "", nil)
		wantError(t, w, m, 403, "forbidden")
	}
	forb := r.eventsNamed("api_forbidden")
	if len(forb) != 4 {
		t.Fatalf("expected 4 api_forbidden events, got %d", len(forb))
	}
	if forb[0].Details["reason"] != "scope" || forb[0].Details["needs"] != "audit:read" || forb[0].Details["key_id"] != "key_6" || forb[0].Details["principal"] != "service" || forb[0].Outcome != "failure" || forb[0].User != "key:name of key_6" {
		t.Fatalf("scope event: %+v", forb[0])
	}
	if forb[1].Details["reason"] != "role" || forb[1].Details["principal"] != "user" || forb[1].User != "u_member@example.com" {
		t.Fatalf("role event: %+v", forb[1])
	}
}

func TestAPICallEventsForMutationsAndSensitiveReadsOnly(t *testing.T) {
	r := newRig(t, 120)
	r.addUser("u_admin", "admin", false)
	r.addUser("u_target", "member", false)
	r.addUser("u_admin2", "admin", false)
	r.grant(key(1), principal("service", "svc_1", "key_1", "status:read users:read users:lock users:unlock"))
	r.do("GET", "/api/v1/status", key(1), "", nil) // not sensitive
	if len(r.eventsNamed("api_call")) != 0 {
		t.Fatal("status:read is not a sensitive read")
	}
	r.do("GET", "/api/v1/users", key(1), "", nil)
	r.do("POST", "/api/v1/users/u_target/lock", key(1), "", nil)
	r.do("POST", "/api/v1/users/nobody/lock", key(1), "", nil)
	evs := r.eventsNamed("api_call")
	if len(evs) != 3 {
		t.Fatalf("api_call events: %d", len(evs))
	}
	e := evs[1]
	if e.Category != "iam" || e.Outcome != "success" || e.Details["scope"] != "users:lock" || e.Details["method"] != "POST" || e.Details["target"] != "/api/v1/users/u_target/lock" ||
		e.Details["status"] != "200" || e.Details["key_id"] != "key_1" || e.Details["key_name"] != "name of key_1" || e.Details["principal"] != "service" || e.User != "key:name of key_1" || e.Actor != "svc_1" {
		t.Fatalf("event: %+v", e)
	}
	if evs[2].Outcome != "failure" || evs[2].Details["status"] != "404" {
		t.Fatalf("a failed call is recorded as a failure: %+v", evs[2])
	}
	// the domain event the person sees in their own trail
	locked := r.eventsNamed("admin_user_locked")
	if len(locked) != 1 || locked[0].Target != "u_target" || locked[0].Details["via"] == "" {
		t.Fatalf("admin_user_locked: %+v", locked)
	}
}

// ---- limits ----

func TestPerKeyRateLimit(t *testing.T) {
	r := newRig(t, 3)
	r.grant(key(1), principal("service", "svc_1", "key_1", "status:read"))
	r.grant(key(2), principal("service", "svc_2", "key_2", "status:read"))
	for i := 0; i < 3; i++ {
		w, _ := r.do("GET", "/api/v1/whoami", key(1), "", nil)
		wantStatus(t, w, 200)
	}
	w, m := r.do("GET", "/api/v1/whoami", key(1), "", nil)
	wantError(t, w, m, 429, "rate_limited")
	if ra := w.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatalf("Retry-After: %q", ra)
	}
	// other keys are unaffected; the limited key stays limited and the event is thinned
	w, _ = r.do("GET", "/api/v1/whoami", key(2), "", nil)
	wantStatus(t, w, 200)
	r.do("GET", "/api/v1/whoami", key(1), "", nil)
	r.do("GET", "/api/v1/whoami", key(1), "", nil)
	evs := r.eventsNamed("api_rate_limited")
	if len(evs) != 1 || evs[0].Details["key_id"] != "key_1" || evs[0].Details["limit"] != "3" || evs[0].Details["by"] != "key" || evs[0].Outcome != "failure" {
		t.Fatalf("events: %+v", evs)
	}
	// limited requests did not reach ClosedDoor
	if r.v.count() != 4 {
		t.Fatalf("introspections: %d", r.v.count())
	}
}

func TestFailedAuthenticationIsThrottledPerAddressBeforeClosedDoorIsAsked(t *testing.T) {
	r := newRig(t, 1000)
	r.grant(goodKey, principal("service", "svc_1", "key_1", "status:read"))
	for i := 0; i < 20; i++ {
		w, _ := r.do("GET", "/api/v1/whoami", key(byte(i+1)), "", nil) // well-formed but unknown keys
		wantStatus(t, w, 401)
	}
	if r.v.count() != 20 {
		t.Fatalf("introspections: %d", r.v.count())
	}
	// the 21st attempt from this address is refused without asking ClosedDoor, even with a good key
	w, m := r.do("GET", "/api/v1/whoami", goodKey, "", nil)
	wantError(t, w, m, 429, "rate_limited")
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After missing")
	}
	if r.v.count() != 20 {
		t.Fatalf("ClosedDoor was asked while the address was throttled: %d", r.v.count())
	}
	// another address is not affected
	w, _ = r.do("GET", "/api/v1/whoami", goodKey, "", map[string]string{"X-Test-IP": "198.51.100.9"})
	wantStatus(t, w, 200)
	evs := r.eventsNamed("api_rate_limited")
	if len(evs) != 1 || evs[0].Details["by"] != "ip" || evs[0].Details["limit"] != "20" || evs[0].IP != "192.0.2.1" {
		t.Fatalf("events: %+v", evs)
	}
}

func TestUnknownRoutesAndWrongMethodsDoNotIntrospect(t *testing.T) {
	r := newRig(t, 120)
	r.grant(goodKey, principal("service", "svc_1", "key_1", "status:read"))
	for _, c := range [][2]string{{"GET", "/api/v1/nothing"}, {"GET", "/api/v1/items"}, {"GET", "/api/v1/sync"}, {"POST", "/api/v1/whoami"}, {"PUT", "/api/v1/users/x"}, {"DELETE", "/api/v1/audit"}} {
		w, _ := r.do(c[0], c[1], goodKey, "", nil)
		if w.Code != 404 && w.Code != 405 {
			t.Errorf("%s %s: %d", c[0], c[1], w.Code)
		}
	}
	if r.v.count() != 0 {
		t.Fatalf("ClosedDoor was asked %d times for routes that do not exist", r.v.count())
	}
}

func TestNoCORS(t *testing.T) {
	r := newRig(t, 120)
	r.grant(goodKey, principal("service", "svc_1", "key_1", "status:read"))
	ext := "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
	w, _ := r.do("OPTIONS", "/api/v1/status", "", "", map[string]string{"Origin": ext, "Access-Control-Request-Method": "GET"})
	wantStatus(t, w, 405)
	for k := range w.Header() {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			t.Fatalf("CORS header %s on a preflight", k)
		}
	}
	w, _ = r.do("GET", "/api/v1/whoami", goodKey, "", map[string]string{"Origin": "https://evil.example"})
	wantStatus(t, w, 200)
	w2, _ := r.do("GET", "/api/v1/whoami", goodKey, "", map[string]string{"Origin": ext})
	for _, ww := range []*httptest.ResponseRecorder{w, w2} {
		for k := range ww.Header() {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") || k == "Vary" {
				t.Fatalf("CORS header %s", k)
			}
		}
	}
}

func TestBodiesAreBoundedJSONAndStrict(t *testing.T) {
	r := newRig(t, 1000)
	r.addUser("u_target", "member", false)
	r.grant(goodKey, principal("service", "svc_1", "key_1", "users:lock users:unlock sessions:revoke"))
	post := func(body, ct string) (*httptest.ResponseRecorder, map[string]any) {
		return r.do("POST", "/api/v1/users/u_target/unlock", goodKey, body, map[string]string{"Content-Type": ct})
	}
	w, _ := r.do("POST", "/api/v1/users/u_target/unlock", goodKey, "", nil)
	wantStatus(t, w, 200)
	w, _ = post(`{}`, "application/json")
	wantStatus(t, w, 200)
	w, _ = post(`{} `, "application/json; charset=utf-8")
	wantStatus(t, w, 200)
	for name, c := range map[string][2]string{
		"unknown field": {`{"confirm":true}`, "application/json"},
		"wrong type":    {`{}`, "text/plain"},
		"form":          {`a=b`, "application/x-www-form-urlencoded"},
		"not json":      {`nope`, "application/json"},
		"trailing":      {`{} {}`, "application/json"},
		"too big":       {`{"a":"` + strings.Repeat("x", 2<<20) + `"}`, "application/json"},
	} {
		w, m := post(c[0], c[1])
		if w.Code != 400 || m["error"] != "invalid_request" {
			t.Errorf("%s: %d %v", name, w.Code, m)
		}
	}
	w, m := r.do("DELETE", "/api/v1/users/u_target/sessions", goodKey, `{"x":1}`, nil)
	wantError(t, w, m, 400, "invalid_request")
}

func TestListParameters(t *testing.T) {
	r := newRig(t, 1000)
	r.grant(goodKey, principal("service", "svc_1", "key_1", "users:read audit:read sessions:read sessions:revoke response:read"))
	r.addUser("u1", "member", false)
	for _, q := range []string{"/api/v1/users?limit=0", "/api/v1/users?limit=abc", "/api/v1/users?limit=-4", "/api/v1/users?cursor=%20bad", "/api/v1/users?locked=maybe",
		"/api/v1/audit?cursor=abc", "/api/v1/audit?cursor=0", "/api/v1/audit?since=yesterday", "/api/v1/audit?event=DROP%20TABLE", "/api/v1/audit?actor=a%20b",
		"/api/v1/users/u1/sessions?offset=-1", "/api/v1/response/blocks?limit=x", "/api/v1/users/bad%20sub"} {
		w, m := r.do("GET", q, goodKey, "", nil)
		if w.Code != 400 || m["error"] != "invalid_request" {
			t.Errorf("%s: %d %v", q, w.Code, m)
		}
	}
	w, m := r.do("DELETE", "/api/v1/users/u1/sessions/XYZ", goodKey, "", nil)
	if w.Code != 400 || m["error"] != "invalid_request" {
		t.Errorf("a bad session id: %d %v", w.Code, m)
	}
	// a limit above the maximum is treated as the maximum, not an error
	w, _ = r.do("GET", "/api/v1/users?limit=100000", goodKey, "", nil)
	wantStatus(t, w, 200)
}

func TestPaginationOfUsersAndAudit(t *testing.T) {
	r := newRig(t, 1000)
	r.grant(goodKey, principal("service", "svc_1", "key_1", "users:read audit:read"))
	for _, s := range []string{"u1", "u2", "u3", "u4", "u5"} {
		r.addUser(s, "member", false)
	}
	var got []string
	cursor := ""
	for page := 0; page < 10; page++ {
		_, m := r.do("GET", "/api/v1/users?limit=2&cursor="+cursor, goodKey, "", nil)
		for _, u := range m["users"].([]any) {
			got = append(got, u.(map[string]any)["sub"].(string))
		}
		next, _ := m["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if strings.Join(got, ",") != "u1,u2,u3,u4,u5" {
		t.Fatalf("pages: %v", got)
	}
	_, m := r.do("GET", "/api/v1/users?limit=5", goodKey, "", nil)
	if m["next_cursor"] != nil {
		t.Fatalf("the last page has no cursor: %v", m["next_cursor"])
	}
	// audit: newest first, cursor walks backwards without repeats
	for i := 0; i < 7; i++ {
		r.srv.Audit.Log(context.Background(), audit.Event{Name: "unlock_failed", Actor: "u1", Outcome: "failure"})
	}
	seen := map[float64]bool{}
	cursor = ""
	pages := 0
	for {
		pages++
		w, m := r.do("GET", "/api/v1/audit?event=unlock_failed&limit=3&cursor="+cursor, goodKey, "", nil)
		wantStatus(t, w, 200)
		for _, e := range m["events"].([]any) {
			id := e.(map[string]any)["id"].(float64)
			if seen[id] {
				t.Fatalf("event %v repeated", id)
			}
			seen[id] = true
		}
		next, _ := m["next_cursor"].(string)
		if next == "" || pages > 10 {
			break
		}
		cursor = next
	}
	if len(seen) != 7 || pages != 3 {
		t.Fatalf("seen %d events in %d pages", len(seen), pages)
	}
}

func TestSecurityHeadersOnEveryAnswer(t *testing.T) {
	r := newRig(t, 120)
	r.grant(goodKey, principal("service", "svc_1", "key_1", "status:read"))
	for _, c := range []struct{ method, path, token string }{
		{"GET", "/api/v1/whoami", ""}, {"GET", "/api/v1/whoami", "garbage"}, {"GET", "/api/v1/status", goodKey}, {"GET", "/api/v1/audit", goodKey}, {"OPTIONS", "/api/v1/status", ""},
	} {
		w, _ := r.do(c.method, c.path, c.token, "", nil)
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s %s: %v", c.method, c.path, w.Header())
		}
	}
}

func TestWindow(t *testing.T) {
	w := newWindow(2, 50*time.Millisecond)
	if ok, _ := w.take("a"); !ok {
		t.Fatal()
	}
	w.add("a")
	if full, wait := w.full("a"); !full || wait <= 0 {
		t.Fatalf("full=%v wait=%v", full, wait)
	}
	if ok, _ := w.take("b"); !ok {
		t.Fatal("keys are independent")
	}
	time.Sleep(60 * time.Millisecond)
	if full, _ := w.full("a"); full {
		t.Fatal("hits expire")
	}
	if retrySeconds(0) != 1 || retrySeconds(1500*time.Millisecond) != 2 {
		t.Fatal("retrySeconds")
	}
}

func TestAuditDetailsCarryNoCountsOrKDFParameters(t *testing.T) {
	cases := []struct{ event, in, want string }{
		{"sync_full", "items=412 kind=web", "kind=web"},
		{"space_deleted", "items=9", ""},
		{"space_key_rotated", "items=30 members=3 version=4", "members=3"},
		{"items_imported", "count=500", ""},
		{"vault_export", "count=12", ""},
		{"vault_created", "iterations=600000", ""},
		{"ext_device_added", "label=items=5 renewed=false replaced=false", "label=items=5 renewed=false replaced=false"}, // a client-chosen label is never touched
		{"space_member_added", "member=abc role=viewer", "member=abc role=viewer"},
	}
	for _, c := range cases {
		if got := redactDetails(c.event, c.in); got != c.want {
			t.Errorf("%s %q: got %q want %q", c.event, c.in, got, c.want)
		}
	}
}

func TestSkyNetErrorsAreReducedToAFixedVocabulary(t *testing.T) {
	for in, want := range map[string]string{
		"": "",
		`send to skynet: Post "https://skynet.corp.example:8443/api/v1/ingest": dial tcp 10.1.2.3:8443: connect: connection refused`: "unreachable",
		"skynet answered HTTP 503":                     "skynet answered HTTP 503",
		"skynet refused our key (HTTP 401): re-enroll": "skynet refused our key",
		`Post "https://x": context deadline exceeded`:  "timeout",
		"skynet commands: HTTP 502":                    "skynet answered HTTP 502",
	} {
		if got := coarseError(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

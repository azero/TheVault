package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/azero/thevault/server/internal/automation"
	"github.com/azero/thevault/server/internal/store"
)

// The automation API (docs/automation-api.md), end to end: the real handler, a fake ClosedDoor that answers
// POST /api/introspect, and the fake SkyNet.

func withAPI(extra map[string]string) opt {
	return func(m map[string]string, e *env) {
		m["VAULT_API_ENABLED"] = "true"
		for k, v := range extra {
			m[k] = v
		}
	}
}

// apiClient is a script: no cookie jar, a bearer key.
type apiClient struct {
	t     *testing.T
	e     *env
	token string
	ip    string
}

var noRedirect = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (e *env) api(token string) *apiClient { return &apiClient{t: e.t, e: e, token: token} }

func (a *apiClient) do(method, path string, body any, hdr map[string]string) (int, map[string]any, http.Header, []byte) {
	a.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.e.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	if a.ip != "" {
		req.Header.Set("X-Test-IP", a.ip)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	m := map[string]any{}
	json.Unmarshal(raw, &m)
	return resp.StatusCode, m, resp.Header, raw
}

// ok does a request, expects `want`, and returns the decoded body.
func (a *apiClient) ok(method, path string, body any, want int) map[string]any {
	a.t.Helper()
	st, m, _, raw := a.do(method, path, body, nil)
	if st != want {
		a.t.Fatalf("%s %s: want %d got %d: %s", method, path, want, st, raw)
	}
	return m
}

func (a *apiClient) errCode(method, path string, body any, wantStatus int, wantCode string) map[string]any {
	a.t.Helper()
	st, m, _, raw := a.do(method, path, body, nil)
	if st != wantStatus || m["error"] != wantCode || m["message"] == nil || m["message"] == "" {
		a.t.Fatalf("%s %s: want %d %s got %d: %s", method, path, wantStatus, wantCode, st, raw)
	}
	return m
}

func (e *env) svcKey(name, scope string) string {
	return e.sso.addKey(fakeKey{Principal: "service", Sub: "svc_" + name, KeyID: "key_" + name, KeyName: name, Scope: scope})
}

func (e *env) userKey(name, sub, email, scope string, roles ...string) string {
	return e.sso.addKey(fakeKey{Principal: "user", Sub: sub, KeyID: "key_" + name, KeyName: name, Scope: scope, Roles: roles, Name: strings.Split(email, "@")[0], Email: email})
}

func allScopes() string {
	var n []string
	for _, s := range automation.Catalog {
		n = append(n, s.Name)
	}
	return strings.Join(n, " ")
}

func auditRows(e *env) []store.AuditRow {
	rows, _ := e.st.ListAudit(e.ctx, "", 1000)
	return rows
}

func auditEvents(e *env, name string) []store.AuditRow {
	var out []store.AuditRow
	for _, r := range auditRows(e) {
		if r.Event == name {
			out = append(out, r)
		}
	}
	return out
}

// ---- switch, identity ----

func TestAPIIsOffByDefault(t *testing.T) {
	e := newEnv(t)
	tok := e.svcKey("robot", allScopes())
	for _, p := range []string{"/api/v1/whoami", "/api/v1/status", "/api/v1/users", "/api/v1/audit"} {
		// 404, or 405 where the browser API's CORS preflight pattern (OPTIONS /api/v1/) claims the prefix: no handler either way
		if st, _, _, _ := e.api(tok).do("GET", p, nil, nil); st != 404 && st != 405 {
			t.Fatalf("%s should not exist while the API is off: %d", p, st)
		}
	}
	if e.sso.introspectCount() != 0 {
		t.Fatal("a disabled API must not talk to ClosedDoor")
	}
}

func TestAPIWhoami(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	svc := e.svcKey("nightly", "status:read audit:read")
	usr := e.userKey("bobs", subBob, "bob@example.com", "users:read", "admin")
	m := e.api(svc).ok("GET", "/api/v1/whoami", nil, 200)
	if m["principal"] != "service" || m["sub"] != "svc_nightly" || m["key_id"] != "key_nightly" || m["key_name"] != "nightly" || m["email"] != nil {
		t.Fatalf("service: %v", m)
	}
	if sc := m["scopes"].([]any); len(sc) != 2 || sc[0] != "status:read" || sc[1] != "audit:read" {
		t.Fatalf("scopes: %v", m["scopes"])
	}
	m = e.api(usr).ok("GET", "/api/v1/whoami", nil, 200)
	if m["principal"] != "user" || m["sub"] != subBob || m["email"] != "bob@example.com" || m["name"] != "bob" || m["roles"].([]any)[0] != "admin" {
		t.Fatalf("user: %v", m)
	}
	// X-API-Key works too
	st, _, _, _ := e.api("").do("GET", "/api/v1/whoami", nil, map[string]string{"X-API-Key": svc})
	if st != 200 {
		t.Fatalf("X-API-Key: %d", st)
	}
	// a key that expired
	old := e.sso.addKey(fakeKey{Principal: "service", Sub: "svc_old", KeyID: "key_old", KeyName: "old", Scope: "status:read", Exp: time.Now().Unix() - 5})
	e.api(old).errCode("GET", "/api/v1/whoami", nil, 401, "invalid_token")
}

// ---- scopes ----

func TestAPIScopePerEndpointMatrix(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	e.login(subAna, "ana@example.com")
	byScope := map[string]string{}
	for _, s := range automation.Catalog {
		byScope[s.Name] = e.svcKey("only_"+strings.NewReplacer(":", "_").Replace(s.Name), s.Name)
	}
	none := e.svcKey("nothing", "")
	checked := 0
	for _, ep := range automation.Endpoints() {
		path := strings.NewReplacer("{sub}", subAna, "{id}", "0123456789abcdef").Replace(ep.Pattern)
		for _, s := range automation.Catalog {
			st, m, h, raw := e.api(byScope[s.Name]).do(ep.Method, path, nil, nil)
			if s.Name == ep.Scope || ep.Scope == "" {
				if st == 401 || st == 403 || st >= 500 {
					t.Errorf("%s %s with %s: %d %s", ep.Method, path, s.Name, st, raw)
				}
				continue
			}
			if st != 403 || m["error"] != "insufficient_scope" || m["needs"] != ep.Scope || !strings.Contains(h.Get("WWW-Authenticate"), `error="insufficient_scope"`) {
				t.Errorf("%s %s with only %s: want 403 insufficient_scope needs %s, got %d %s", ep.Method, path, s.Name, ep.Scope, st, raw)
			}
			checked++
		}
		st, m, _, raw := e.api(none).do(ep.Method, path, nil, nil)
		switch {
		case ep.Scope == "" && st != 200:
			t.Errorf("%s %s needs no scope, got %d %s", ep.Method, path, st, raw)
		case ep.Scope != "" && (st != 403 || m["needs"] != ep.Scope):
			t.Errorf("%s %s with no scopes: %d %s", ep.Method, path, st, raw)
		}
	}
	if checked < 50 {
		t.Fatalf("matrix too small: %d", checked)
	}
}

// ---- who may do what ----

func TestAPIUserKeysAreLimitedByRoleAndServiceKeysByScopeOnly(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	e.login(subAna, "ana@example.com")
	e.login(subBob, "bob@example.com", "admin")
	e.login("cccccccccccccccccccccccccccccccc", "carl@example.com", "admin") // so that bob is not the last administrator
	every := allScopes()
	member := e.userKey("anas", subAna, "ana@example.com", every) // all scopes, but only a member in TheVault
	admin := e.userKey("bobs", subBob, "bob@example.com", every, "admin")
	near := e.userKey("near", subAna, "ana@example.com", every, "Admin", "administrator", "admin ")
	svc := e.svcKey("robot", every)

	for _, ep := range automation.Endpoints() {
		if ep.Scope == "" {
			continue
		}
		path := strings.NewReplacer("{sub}", subAna, "{id}", "0123456789abcdef").Replace(ep.Pattern)
		for name, tok := range map[string]string{"member": member, "near-miss roles": near} {
			st, m, _, raw := e.api(tok).do(ep.Method, path, nil, nil)
			if st != 403 || m["error"] != "forbidden" {
				t.Errorf("%s key on %s %s: want 403 forbidden, got %d %s", name, ep.Method, path, st, raw)
			}
		}
	}
	forb := auditEvents(e, "api_forbidden")
	if len(forb) == 0 || !strings.Contains(forb[0].Details, "reason=role") {
		t.Fatalf("api_forbidden rows: %+v", forb)
	}
	// admin user key and service key are both fine (users:lock on someone else)
	e.api(admin).ok("POST", "/api/v1/users/"+subAna+"/lock", nil, 200)
	e.api(svc).ok("POST", "/api/v1/users/"+subAna+"/unlock", nil, 200)
	// demotion in ClosedDoor takes effect on the next call
	e.sso.changeKey(admin, func(k *fakeKey) { k.Roles = nil })
	e.api(admin).errCode("GET", "/api/v1/users", nil, 403, "forbidden")
	e.sso.changeKey(admin, func(k *fakeKey) { k.Roles = []string{"admin"} })
	e.api(admin).ok("GET", "/api/v1/users", nil, 200)
	// an administrator that an administrator has locked in TheVault cannot administer either
	e.api(svc).ok("POST", "/api/v1/users/"+subBob+"/lock", nil, 200)
	e.api(admin).errCode("GET", "/api/v1/users", nil, 403, "forbidden")
	e.api(svc).ok("GET", "/api/v1/users", nil, 200)
}

func TestAPIUserLocksAndGuards(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	bob := e.login(subBob, "bob@example.com", "admin")
	svc := e.svcKey("robot", "users:read users:lock users:unlock sessions:read sessions:revoke")
	bobKey := e.userKey("bobs", subBob, "bob@example.com", "users:lock users:unlock users:read", "admin")
	a := e.api(svc)

	// lock ends sessions and refuses sign-in, exactly like the administration screen
	m := a.ok("POST", "/api/v1/users/"+subAna+"/lock", nil, 200)
	if m["locked"] != true || m["sessions_ended"].(float64) < 1 {
		t.Fatalf("%v", m)
	}
	if st := ana.getJSON("/api/v1/session", nil); st != 401 {
		t.Fatalf("a locked person's session must end: %d", st)
	}
	e.sso.set(func() { e.sso.Sub, e.sso.Email, e.sso.Roles = subAna, "ana@example.com", nil })
	resp, _ := e.newClient().hc.Get(e.srv.URL + "/auth/login")
	if resp.StatusCode != 403 {
		t.Fatalf("a locked person cannot sign in: %d", resp.StatusCode)
	}
	u := a.ok("GET", "/api/v1/users/"+subAna, nil, 200)
	if u["locked"] != true {
		t.Fatalf("%v", u)
	}
	if l := a.ok("GET", "/api/v1/users?locked=true", nil, 200)["users"].([]any); len(l) != 1 || l[0].(map[string]any)["sub"] != subAna {
		t.Fatalf("locked filter: %v", l)
	}
	if l := a.ok("GET", "/api/v1/users?locked=false", nil, 200)["users"].([]any); len(l) != 1 || l[0].(map[string]any)["sub"] != subBob {
		t.Fatalf("unlocked filter: %v", l)
	}
	a.ok("POST", "/api/v1/users/"+subAna+"/unlock", nil, 200)
	e.login(subAna, "ana@example.com") // can sign in again

	// guards
	a.errCode("POST", "/api/v1/users/nobody/lock", nil, 404, "not_found")
	a.errCode("POST", "/api/v1/users/nobody/unlock", nil, 404, "not_found")
	a.errCode("POST", "/api/v1/users/"+subBob+"/lock", nil, 409, "conflict") // the only administrator
	if st := bob.getJSON("/api/v1/session", nil); st != 200 {
		t.Fatalf("the refused lock must not have ended anything: %d", st)
	}
	e.api(bobKey).errCode("POST", "/api/v1/users/"+subBob+"/lock", nil, 409, "conflict") // yourself
	// with a second administrator, one of them can be locked, but never the last
	e.login("cccccccccccccccccccccccccccccccc", "carl@example.com", "admin")
	a.ok("POST", "/api/v1/users/"+subBob+"/lock", nil, 200)
	a.errCode("POST", "/api/v1/users/cccccccccccccccccccccccccccccccc/lock", nil, 409, "conflict")

	// the domain events (what the person sees in their own activity) were written with the API as the actor
	locked := auditEvents(e, "admin_user_locked")
	if len(locked) != 2 || !strings.Contains(locked[0].Details, "via=api") || !strings.Contains(locked[0].Details, "key_id=key_robot") || locked[0].Actor != "svc_robot" {
		t.Fatalf("admin_user_locked rows: %+v", locked)
	}
	if len(auditEvents(e, "admin_user_unlocked")) != 1 {
		t.Fatal("admin_user_unlocked missing")
	}
}

func TestAPISessions(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	ana := e.login(subAna, "ana@example.com")
	ana2 := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	tok, _, err := e.st.CreateSession(e.ctx, store.NewSession{Sub: subAna, Kind: "ext", Label: "Chrome on Laptop", Role: "member", IP: "203.0.113.9", Idle: time.Hour, Absolute: time.Hour,
		AccessToken: "at_secret_token", TokenExpiry: time.Now().Add(time.Hour), Prefix: "vxs_"})
	if err != nil {
		t.Fatal(err)
	}
	a := e.api(e.svcKey("robot", "sessions:read sessions:revoke"))
	m := a.ok("GET", "/api/v1/users/"+subAna+"/sessions", nil, 200)
	list := m["sessions"].([]any)
	if len(list) != 3 || m["total"].(float64) != 3 || m["next_offset"] != nil {
		t.Fatalf("%v", m)
	}
	kinds := map[string]int{}
	var extID string
	for _, x := range list {
		s := x.(map[string]any)
		kinds[s["kind"].(string)]++
		if s["kind"] == "ext" {
			extID = s["id"].(string)
			if s["label"] != "Chrome on Laptop" || s["ip"] != "203.0.113.9" {
				t.Fatalf("%v", s)
			}
		}
		if len(s["id"].(string)) != 16 {
			t.Fatalf("ids are the 16-character public handles: %v", s)
		}
	}
	if kinds["web"] != 2 || kinds["ext"] != 1 {
		t.Fatalf("%v", kinds)
	}
	_, _, _, raw := a.do("GET", "/api/v1/users/"+subAna+"/sessions", nil, nil)
	for _, secret := range []string{tok, "at_secret_token", "csrf", "access_token", "user_agent", "id_hash"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("sessions list leaks %q: %s", secret, raw)
		}
	}
	// pagination
	m = a.ok("GET", "/api/v1/users/"+subAna+"/sessions?limit=2", nil, 200)
	if len(m["sessions"].([]any)) != 2 || m["next_offset"].(float64) != 2 {
		t.Fatalf("%v", m)
	}
	if len(a.ok("GET", "/api/v1/users/"+subAna+"/sessions?limit=2&offset=2", nil, 200)["sessions"].([]any)) != 1 {
		t.Fatal("second page")
	}
	a.errCode("GET", "/api/v1/users/nobody/sessions", nil, 404, "not_found")

	// revoke one device
	a.ok("DELETE", "/api/v1/users/"+subAna+"/sessions/"+extID, nil, 200)
	a.errCode("DELETE", "/api/v1/users/"+subAna+"/sessions/"+extID, nil, 404, "not_found")
	a.errCode("DELETE", "/api/v1/users/"+subAna+"/sessions/not-an-id", nil, 400, "invalid_request")
	if _, err := e.st.GetSession(e.ctx, tok, time.Hour, time.Hour); err == nil {
		t.Fatal("the extension device must be signed out")
	}
	// somebody else's session id cannot be revoked through another person's path
	e.login(subBob, "bob@example.com")
	other := a.ok("GET", "/api/v1/users/"+subBob+"/sessions", nil, 200)["sessions"].([]any)[0].(map[string]any)["id"].(string)
	a.errCode("DELETE", "/api/v1/users/"+subAna+"/sessions/"+other, nil, 404, "not_found")
	// revoke all
	m = a.ok("DELETE", "/api/v1/users/"+subAna+"/sessions", nil, 200)
	if m["revoked"].(float64) != 2 {
		t.Fatalf("%v", m)
	}
	if ana.getJSON("/api/v1/session", nil) != 401 || ana2.getJSON("/api/v1/session", nil) != 401 {
		t.Fatal("web sessions must end")
	}
	if rows := auditEvents(e, "admin_sessions_revoked"); len(rows) != 2 {
		t.Fatalf("admin_sessions_revoked rows: %+v", rows)
	}
}

func TestAPIAuditStatusAndBlocks(t *testing.T) {
	sky := newFakeSky(t)
	e := newEnv(t, withAPI(nil), withSky(sky, nil))
	ana := e.login(subAna, "ana@example.com")
	m := setupVault(t, ana)
	ana.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": envelope()}, 200, nil)
	a := e.api(e.svcKey("robot", "audit:read status:read response:read users:read"))

	// audit: newest first, paging, filters
	all := a.ok("GET", "/api/v1/audit?limit=200", nil, 200)["events"].([]any)
	if len(all) < 3 {
		t.Fatalf("expected the login, vault and item events: %d", len(all))
	}
	prev := 1e18
	for _, x := range all {
		id := x.(map[string]any)["id"].(float64)
		if id >= prev {
			t.Fatal("newest first")
		}
		prev = id
	}
	page := a.ok("GET", "/api/v1/audit?limit=2", nil, 200)
	if len(page["events"].([]any)) != 2 || page["next_cursor"] == nil {
		t.Fatalf("%v", page)
	}
	page2 := a.ok("GET", "/api/v1/audit?limit=2&cursor="+page["next_cursor"].(string), nil, 200)
	if page2["events"].([]any)[0].(map[string]any)["id"].(float64) >= page["events"].([]any)[1].(map[string]any)["id"].(float64) {
		t.Fatal("the cursor must continue after the first page")
	}
	one := a.ok("GET", "/api/v1/audit?event=item_created", nil, 200)["events"].([]any)
	if len(one) != 1 {
		t.Fatalf("event filter: %v", one)
	}
	row := one[0].(map[string]any)
	if row["actor"] != subAna || len(row["target"].(string)) != 12 || row["outcome"] != "success" || row["created_at"].(float64) == 0 {
		t.Fatalf("an item id is shortened to 12 characters, as the administration screen does: %v", row)
	}
	if n := len(a.ok("GET", "/api/v1/audit?actor="+subAna+"&event=login", nil, 200)["events"].([]any)); n != 1 {
		t.Fatalf("actor filter: %d", n)
	}
	if n := len(a.ok("GET", "/api/v1/audit?since="+itoaT(time.Now().Unix()+3600), nil, 200)["events"].([]any)); n != 0 {
		t.Fatalf("since filter: %d", n)
	}

	// status
	waitFor(t, "a heartbeat", func() bool { return len(sky.events("heartbeat")) > 0 })
	if _, err := e.st.Backup(e.ctx); err != nil {
		t.Fatal(err)
	}
	s := a.ok("GET", "/api/v1/status", nil, 200)
	if s["status"] != "ok" || s["version"] != "test" || s["time"].(float64) == 0 {
		t.Fatalf("%v", s)
	}
	schema := s["schema"].(map[string]any)
	if schema["current"] != schema["latest"] || schema["current"].(float64) < 2 {
		t.Fatalf("schema: %v", schema)
	}
	if s["database"].(map[string]any)["bytes"].(float64) <= 0 {
		t.Fatal("database size")
	}
	counts := s["counts"].(map[string]any)
	if counts["users"].(float64) != 1 || counts["vaults"].(float64) != 1 || counts["sessions"].(float64) != 1 {
		t.Fatalf("counts: %v", counts)
	}
	if _, has := counts["items"]; has {
		t.Fatal("no item counts")
	}
	sk := s["skynet"].(map[string]any)
	if sk["enabled"] != true || sk["commands_enabled"] != true || sk["last_send"].(float64) == 0 || sk["agent_id"] != nil || sk["url"] != nil || sk["deny"] != nil {
		t.Fatalf("skynet: %v", sk)
	}
	b := s["backups"].(map[string]any)
	if b["total"].(float64) != 1 {
		t.Fatalf("backups: %v", b)
	}
	bk := b["latest"].([]any)[0].(map[string]any)
	if !strings.HasPrefix(bk["name"].(string), "vault-") || strings.Contains(bk["name"].(string), "/") || bk["bytes"].(float64) <= 0 {
		t.Fatalf("backup: %v", bk)
	}

	// response blocks
	bl := a.ok("GET", "/api/v1/response/blocks", nil, 200)
	if len(bl["blocks"].([]any)) != 0 || bl["enforced"] != true || bl["commands_enabled"] != true {
		t.Fatalf("%v", bl)
	}
	until := time.Now().Add(time.Hour).Unix()
	e.st.DenyAdd(e.ctx, store.Deny{IP: "198.51.100.77", Until: until, Reason: "spray", CommandID: 5})
	e.st.DenyAdd(e.ctx, store.Deny{IP: "198.51.100.78", Until: until + 10, Reason: "spray2", CommandID: 6})
	bl = a.ok("GET", "/api/v1/response/blocks?limit=1", nil, 200)
	first := bl["blocks"].([]any)[0].(map[string]any)
	if bl["total"].(float64) != 2 || bl["next_offset"].(float64) != 1 || first["ip"] != "198.51.100.78" || first["reason"] != "spray2" || first["until"].(float64) != float64(until+10) {
		t.Fatalf("%v", bl)
	}
	if len(a.ok("GET", "/api/v1/response/blocks?offset=1", nil, 200)["blocks"].([]any)) != 1 {
		t.Fatal("offset")
	}
	_ = m
}

func itoaT(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestAPIStatusWithoutSkyNetAndDegraded(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	a := e.api(e.svcKey("robot", "status:read response:read"))
	s := a.ok("GET", "/api/v1/status", nil, 200)
	if s["skynet"].(map[string]any)["enabled"] != false || s["status"] != "ok" {
		t.Fatalf("%v", s)
	}
	if bl := a.ok("GET", "/api/v1/response/blocks", nil, 200); bl["enforced"] != false || bl["commands_enabled"] != false {
		t.Fatalf("%v", bl)
	}
	// SkyNet configured but not accepting events: degraded
	sky := newFakeSky(t)
	sky.Status = 503
	e2 := newEnv(t, withAPI(nil), withSky(sky, nil))
	a2 := e2.api(e2.svcKey("robot", "status:read"))
	waitFor(t, "degraded", func() bool {
		s := a2.ok("GET", "/api/v1/status", nil, 200)
		return s["status"] == "degraded" && len(s["problems"].([]any)) > 0
	})
}

// ---- revocation, caching, outages ----

func TestAPIRevokedKeyStopsImmediatelyWithoutCache(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	tok := e.svcKey("robot", "status:read")
	a := e.api(tok)
	a.ok("GET", "/api/v1/status", nil, 200)
	e.sso.changeKey(tok, func(k *fakeKey) { k.Disabled = true })
	a.errCode("GET", "/api/v1/status", nil, 401, "invalid_token")
	e.sso.changeKey(tok, func(k *fakeKey) { k.Disabled = false; k.Scope = "audit:read" }) // a scope removed in ClosedDoor
	a.errCode("GET", "/api/v1/status", nil, 403, "insufficient_scope")
	if n := e.sso.introspectCount(); n != 3 {
		t.Fatalf("with no cache every request is verified: %d", n)
	}
}

func TestAPICacheTTL(t *testing.T) {
	e := newEnv(t, withAPI(map[string]string{"VAULT_API_CACHE_SECONDS": "1"}))
	tok := e.svcKey("robot", "status:read")
	a := e.api(tok)
	a.ok("GET", "/api/v1/status", nil, 200)
	a.ok("GET", "/api/v1/status", nil, 200)
	if n := e.sso.introspectCount(); n != 1 {
		t.Fatalf("the second request should come from the cache: %d introspections", n)
	}
	e.sso.changeKey(tok, func(k *fakeKey) { k.Disabled = true })
	a.ok("GET", "/api/v1/status", nil, 200) // still cached: this is the documented cost of a cache
	time.Sleep(1100 * time.Millisecond)
	a.errCode("GET", "/api/v1/status", nil, 401, "invalid_token")
}

func TestAPIFailsClosedWhenClosedDoorIsUnavailableOrRejectsUs(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	tok := e.svcKey("robot", "status:read")
	a := e.api(tok)
	a.ok("GET", "/api/v1/status", nil, 200)
	e.sso.set(func() { e.sso.IntrospectDown = true })
	m := a.errCode("GET", "/api/v1/status", nil, 503, "authentication_unavailable")
	if strings.Contains(m["message"].(string), e.sso.srv.URL) {
		t.Fatal("upstream address leaked")
	}
	e.sso.set(func() { e.sso.IntrospectDown = false })
	a.ok("GET", "/api/v1/status", nil, 200)
	if rows := auditEvents(e, "api_auth_failed"); len(rows) != 1 || !strings.Contains(rows[0].Details, "reason=unavailable") {
		t.Fatalf("%+v", rows)
	}

	// ClosedDoor rejecting this application's own credentials is a 503 too (never "invalid key", never allowed)
	bad := newEnv(t, withAPI(map[string]string{"VAULT_OIDC_CLIENT_SECRET": "cds_wrong"}))
	tok2 := bad.svcKey("robot", "status:read")
	bad.api(tok2).errCode("GET", "/api/v1/status", nil, 503, "authentication_unavailable")
}

// ---- separation from the web UI ----

func TestAPICookiesCORSAndCredentialsAreSeparate(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	web := e.login(subBob, "bob@example.com", "admin")
	tok := e.svcKey("robot", allScopes())
	before := e.sso.introspectCount()

	// a signed-in browser (cookie) is not a credential for the API
	for _, p := range []string{"/api/v1/whoami", "/api/v1/status", "/api/v1/users", "/api/v1/audit"} {
		st, raw, _ := web.do("GET", p, nil, nil)
		m := map[string]any{}
		json.Unmarshal(raw, &m)
		if st != 401 || m["error"] != "invalid_token" {
			t.Fatalf("%s with a web session: %d %v", p, st, m)
		}
	}
	if e.sso.introspectCount() != before {
		t.Fatal("a cookie must not even trigger an introspection")
	}
	// an API key does not open the web API (neither as bearer nor anywhere else)
	for _, p := range []string{"/api/v1/session", "/api/v1/sessions", "/api/v1/admin/overview", "/api/v1/admin/audit", "/api/v1/sync", "/api/v1/directory"} {
		st, _, _, _ := e.api(tok).do("GET", p, nil, nil)
		if st != 401 {
			t.Fatalf("an API key on the web API %s: %d", p, st)
		}
	}
	// nothing sets cookies
	_, _, h, _ := e.api(tok).do("GET", "/api/v1/status", nil, nil)
	if h.Get("Set-Cookie") != "" || h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(h.Get("Content-Type"), "application/json") {
		t.Fatalf("headers: %v", h)
	}
	// no CORS: not on the API, while the extension's preflight on the web API keeps working
	origin := "chrome-extension://" + extID
	st, _, h, _ := e.api(tok).do("GET", "/api/v1/status", nil, map[string]string{"Origin": origin})
	if st != 200 || h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("CORS on the automation API: %d %v", st, h)
	}
	st, _, h, _ = e.api("").do("OPTIONS", "/api/v1/status", nil, map[string]string{"Origin": origin, "Access-Control-Request-Method": "GET"})
	if st != 405 || h.Get("Access-Control-Allow-Origin") != "" || h.Get("Access-Control-Allow-Methods") != "" {
		t.Fatalf("preflight on the automation API: %d %v", st, h)
	}
	st, _, h, _ = e.api("").do("OPTIONS", "/api/v1/sync", nil, map[string]string{"Origin": origin, "Access-Control-Request-Method": "GET"})
	if st != 204 || h.Get("Access-Control-Allow-Origin") != origin {
		t.Fatalf("the extension's preflight must be untouched: %d %v", st, h)
	}
	// unknown routes and wrong methods answer without asking ClosedDoor
	before = e.sso.introspectCount()
	for _, c := range [][2]string{{"GET", "/api/v1/items"}, {"GET", "/api/v1/nope"}, {"POST", "/api/v1/whoami"}, {"DELETE", "/api/v1/audit"}, {"PUT", "/api/v1/users/x"}} {
		if st, _, _, _ := e.api(tok).do(c[0], c[1], nil, nil); st != 404 && st != 405 && st != 401 {
			t.Fatalf("%v: %d", c, st)
		}
	}
	// (the web API's own routes answer 401 to a cdk_ bearer without anything reaching ClosedDoor either)
	if e.sso.introspectCount() != before {
		t.Fatal("unknown routes must not cause introspections")
	}
}

func TestAPIBodiesAndLimits(t *testing.T) {
	e := newEnv(t, withAPI(map[string]string{"VAULT_API_RATE_PER_MINUTE": "4"}))
	e.login(subAna, "ana@example.com")
	a := e.api(e.svcKey("robot", "users:lock users:unlock"))
	a.errCode("POST", "/api/v1/users/"+subAna+"/unlock", map[string]any{"force": true}, 400, "invalid_request")
	st, m, _, _ := a.do("POST", "/api/v1/users/"+subAna+"/unlock", nil, map[string]string{"Content-Type": "text/plain"})
	if st != 200 { // no body at all: the content type does not matter
		t.Fatalf("%d %v", st, m)
	}
	// per-key rate limit
	for i := 0; i < 2; i++ {
		a.ok("POST", "/api/v1/users/"+subAna+"/unlock", nil, 200)
	}
	st, m, h, _ := a.do("POST", "/api/v1/users/"+subAna+"/unlock", nil, nil)
	if st != 429 || m["error"] != "rate_limited" || h.Get("Retry-After") == "" {
		t.Fatalf("%d %v %v", st, m, h)
	}
	// other keys have their own allowance
	e.api(e.svcKey("other", "users:unlock")).ok("POST", "/api/v1/users/"+subAna+"/unlock", nil, 200)
	if rows := auditEvents(e, "api_rate_limited"); len(rows) != 1 || !strings.Contains(rows[0].Details, "key_id=key_robot") || !strings.Contains(rows[0].Details, "limit=4") {
		t.Fatalf("%+v", rows)
	}
}

func TestAPIFailedAuthenticationThrottleByAddress(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	good := e.svcKey("robot", "status:read")
	attacker := e.api("")
	attacker.ip = "203.0.113.200"
	for i := 0; i < 20; i++ {
		attacker.token = "cdk_" + strings.Repeat(string(rune('A'+i)), 43)
		attacker.errCode("GET", "/api/v1/whoami", nil, 401, "invalid_token")
	}
	n := e.sso.introspectCount()
	attacker.token = good
	st, m, h, _ := attacker.do("GET", "/api/v1/whoami", nil, nil)
	if st != 429 || m["error"] != "rate_limited" || h.Get("Retry-After") == "" {
		t.Fatalf("%d %v", st, m)
	}
	if e.sso.introspectCount() != n {
		t.Fatal("a throttled address must not cause further introspections")
	}
	friend := e.api(good)
	friend.ip = "203.0.113.201"
	friend.ok("GET", "/api/v1/whoami", nil, 200)
	rows := auditEvents(e, "api_rate_limited")
	if len(rows) != 1 || !strings.Contains(rows[0].Details, "by=ip") || rows[0].IP != "203.0.113.200" {
		t.Fatalf("%+v", rows)
	}
}

// ---- monitoring ----

func TestAPIEventsReachSkyNetAndTheAuditLogWithoutSecrets(t *testing.T) {
	sky := newFakeSky(t)
	e := newEnv(t, withAPI(map[string]string{"VAULT_API_RATE_PER_MINUTE": "6"}), withSky(sky, nil))
	e.login(subAna, "ana@example.com")
	e.login(subBob, "bob@example.com", "admin")
	svc := e.svcKey("nightly", "users:read users:lock")
	member := e.userKey("anas", subAna, "ana@example.com", "audit:read")
	admin := e.userKey("bobs", subBob, "bob@example.com", "users:read sessions:read audit:read", "admin")
	dead := "cdk_" + strings.Repeat("Z", 43)
	a := e.api(svc)
	a.ip = "198.51.100.10"

	e.api(dead).errCode("GET", "/api/v1/whoami", nil, 401, "invalid_token")        // api_auth_failed invalid_token
	e.api("not a key").errCode("GET", "/api/v1/whoami", nil, 401, "invalid_token") // api_auth_failed malformed
	a.errCode("GET", "/api/v1/audit", nil, 403, "insufficient_scope")              // api_forbidden scope
	e.api(member).errCode("GET", "/api/v1/audit", nil, 403, "forbidden")           // api_forbidden role
	a.ok("POST", "/api/v1/users/"+subAna+"/lock", nil, 200)                        // api_call mutating + admin_user_locked
	e.api(admin).ok("GET", "/api/v1/users", nil, 200)                              // api_call sensitive read, user key
	e.api(admin).ok("GET", "/api/v1/users/"+subAna+"/sessions", nil, 200)          // api_call
	for i := 0; i < 8; i++ {                                                       // api_rate_limited
		a.do("GET", "/api/v1/whoami", nil, nil)
	}
	e.sso.set(func() { e.sso.IntrospectDown = true })
	e.api(e.svcKey("other", "users:read")).errCode("GET", "/api/v1/whoami", nil, 503, "authentication_unavailable") // api_auth_failed unavailable
	e.sso.set(func() { e.sso.IntrospectDown = false })

	waitFor(t, "all vocabulary entries", func() bool {
		return len(sky.events("api_auth_failed")) == 3 && len(sky.events("api_forbidden")) == 2 && len(sky.events("api_rate_limited")) >= 1 && len(sky.events("api_call")) == 3
	})
	get := func(action string, i int) map[string]any { return sky.events(action)[i] }
	fields := func(ev map[string]any) map[string]any { f, _ := ev["fields"].(map[string]any); return f }

	af := sky.events("api_auth_failed")
	reasons := map[string]map[string]any{}
	for _, ev := range af {
		if ev["category"] != "authentication" || ev["outcome"] != "failure" || ev["source"] != "thevault" || ev["src_ip"] == nil {
			t.Fatalf("api_auth_failed: %v", ev)
		}
		reasons[fields(ev)["reason"].(string)] = ev
	}
	if reasons["invalid_token"] == nil || reasons["malformed"] == nil || reasons["unavailable"] == nil {
		t.Fatalf("reasons: %v", reasons)
	}
	if fields(reasons["invalid_token"])["key_prefix"] != dead[:8] || fields(reasons["malformed"])["key_prefix"] != nil {
		t.Fatalf("key_prefix: %v / %v", fields(reasons["invalid_token"]), fields(reasons["malformed"]))
	}
	fs := sky.events("api_forbidden")
	sc, ro := fs[0], fs[1]
	if sc["category"] != "authorization" || sc["outcome"] != "failure" || sc["user"] != "key:nightly" || fields(sc)["reason"] != "scope" || fields(sc)["needs"] != "audit:read" ||
		fields(sc)["key_id"] != "key_nightly" || fields(sc)["key_name"] != "nightly" || fields(sc)["principal"] != "service" || sc["src_ip"] != "198.51.100.10" {
		t.Fatalf("scope: %v", sc)
	}
	if ro["user"] != "ana@example.com" || fields(ro)["reason"] != "role" || fields(ro)["principal"] != "user" || fields(ro)["needs"] != "audit:read" {
		t.Fatalf("role: %v", ro)
	}
	rl := get("api_rate_limited", 0)
	if rl["category"] != "web" || rl["outcome"] != "failure" || fields(rl)["limit"] != "6" || fields(rl)["key_id"] != "key_nightly" {
		t.Fatalf("rate limited: %v", rl)
	}
	calls := sky.events("api_call")
	lock := calls[0]
	if lock["category"] != "iam" || lock["outcome"] != "success" || lock["user"] != "key:nightly" || fields(lock)["scope"] != "users:lock" || fields(lock)["method"] != "POST" ||
		fields(lock)["target"] != "/api/v1/users/"+subAna+"/lock" || fields(lock)["status"] != "200" || fields(lock)["principal"] != "service" || fields(lock)["key_id"] != "key_nightly" {
		t.Fatalf("api_call: %v", lock)
	}
	if calls[1]["user"] != "bob@example.com" || fields(calls[1])["principal"] != "user" || fields(calls[1])["scope"] != "users:read" || fields(calls[1])["method"] != "GET" {
		t.Fatalf("user key call: %v", calls[1])
	}
	if len(sky.events("admin_user_locked")) != 1 {
		t.Fatal("the domain event is shipped too")
	}

	// the same events are in the audit log
	for _, name := range []string{"api_auth_failed", "api_forbidden", "api_rate_limited", "api_call", "admin_user_locked"} {
		if len(auditEvents(e, name)) == 0 {
			t.Errorf("no %s row in the audit log", name)
		}
	}
	// no key, no secret anywhere: only the 8-character prefix of a rejected key may appear
	sky.mu.Lock()
	blob, _ := json.Marshal(sky.Events)
	sky.mu.Unlock()
	var rows strings.Builder
	for _, r := range auditRows(e) {
		rows.WriteString(r.Event + "|" + r.Actor + "|" + r.Target + "|" + r.IP + "|" + r.UserAgent + "|" + r.Details + "\n")
	}
	for name, tok := range map[string]string{"svc": svc, "member": member, "admin": admin, "dead": dead} {
		for where, text := range map[string]string{"skynet": string(blob), "audit": rows.String()} {
			if strings.Contains(text, tok[8:]) || strings.Contains(text, tok) {
				t.Errorf("the %s key leaked into %s", name, where)
			}
		}
	}
	if strings.Contains(string(blob), "Bearer") || strings.Contains(rows.String(), "Bearer") {
		t.Fatal("an Authorization header leaked")
	}
}

// ---- zero-knowledge ----

// The whole point: with every scope, as an administrator, nothing about anyone's vault content or key material is
// reachable. This seeds a vault full of recognisable strings and fetches every endpoint.
func TestAPIExposesNoVaultContentInAnyForm(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	ana := e.login(subAna, "ana@example.com")
	mat := setupVault(t, ana)
	itemBlob, itemID := envelope(), hexID()
	ana.call("PUT", "/api/v1/items/"+itemID, map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": itemBlob}, 200, nil)
	spaceID, nameBlob := hexID(), envelope()
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": spaceID, "name_blob": nameBlob, "wrap": wrap()}, 200, nil)
	ana.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": spaceID, "base_seq": 0, "key_version": 1, "blob": itemBlob + "x"}, 200, nil)
	e.login(subBob, "bob@example.com", "admin")

	secrets := []string{itemBlob, itemID, spaceID, nameBlob, mat.Auth, mat.RecoveryProof}
	for k, v := range mat.Setup {
		if s, ok := v.(string); ok && len(s) > 20 {
			secrets = append(secrets, s)
		}
		if k == "recovery" {
			for _, rv := range v.(map[string]any) {
				secrets = append(secrets, rv.(string))
			}
		}
	}
	forbiddenKeys := []string{"blob", "items", "spaces", "wrapped_uk", "enc_priv", "sig_priv", "enc_pub", "sig_pub", "salt", "iterations", "kdf", "key_version", "vault_id", "name_blob", "wrap", "recovery", "folders", "tags", "data"}

	bodies := map[string][]byte{}
	for who, tok := range map[string]string{"service": e.svcKey("robot", allScopes()), "admin user": e.userKey("bobs", subBob, "bob@example.com", allScopes(), "admin")} {
		a := e.api(tok)
		paths := []string{"/api/v1/whoami", "/api/v1/status", "/api/v1/users", "/api/v1/users/" + subAna, "/api/v1/users/" + subAna + "/sessions", "/api/v1/audit?limit=200", "/api/v1/response/blocks"}
		for _, p := range paths {
			st, _, _, raw := a.do("GET", p, nil, nil)
			if st != 200 {
				t.Fatalf("%s %s: %d %s", who, p, st, raw)
			}
			bodies[who+" "+p] = raw
		}
		// and the vault API routes are simply not there for a key
		for _, p := range []string{"/api/v1/sync", "/api/v1/items", "/api/v1/items/" + itemID, "/api/v1/spaces", "/api/v1/vault/prelogin", "/api/v1/vault/unlock", "/api/v1/directory", "/api/v1/users/" + subAna + "/keys", "/api/v1/export", "/api/v1/backup", "/api/v1/backups"} {
			if st, _, _, _ := a.do("GET", p, nil, nil); st != 401 && st != 404 && st != 405 {
				t.Fatalf("%s %s: %d", who, p, st)
			}
			if st, _, _, _ := a.do("POST", p, map[string]any{}, nil); st != 401 && st != 404 && st != 405 {
				t.Fatalf("%s POST %s: %d", who, p, st)
			}
		}
	}
	for name, raw := range bodies {
		for _, s := range secrets {
			if strings.Contains(string(raw), s) {
				t.Errorf("%s contains %q", name, s)
			}
		}
		var v any
		json.Unmarshal(raw, &v)
		walkKeys(v, func(k string) {
			for _, bad := range forbiddenKeys {
				if k == bad {
					t.Errorf("%s has a %q field", name, k)
				}
			}
		})
	}
}

func walkKeys(v any, f func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			f(k)
			walkKeys(c, f)
		}
	case []any:
		for _, c := range x {
			walkKeys(c, f)
		}
	}
}

// A block ordered by SkyNet applies to the whole server, including the automation API, and shows up in the block list.
func TestAPIHonoursSkyNetBlocksAndListsThem(t *testing.T) {
	sky := newFakeSky(t)
	e := newEnv(t, withAPI(nil), withSky(sky, nil))
	tok := e.svcKey("robot", "response:read")
	attacker := "203.0.113.55"
	now := time.Now().Unix()
	sky.command(77, sky.agentID, "block_ip", map[string]any{"ip": attacker, "ttl_seconds": 600}, false, now, now+300)
	waitFor(t, "the block", func() bool {
		sky.mu.Lock()
		defer sky.mu.Unlock()
		_, ok := sky.Results[77]
		return ok
	})
	blocked := e.api(tok)
	blocked.ip = attacker
	if st, _, _, _ := blocked.do("GET", "/api/v1/whoami", nil, nil); st != 403 {
		t.Fatalf("a blocked address must be refused by the API too: %d", st)
	}
	friend := e.api(tok)
	friend.ip = "203.0.113.56"
	bl := friend.ok("GET", "/api/v1/response/blocks", nil, 200)
	got := bl["blocks"].([]any)
	if len(got) != 1 || got[0].(map[string]any)["ip"] != attacker {
		t.Fatalf("%v", bl)
	}
}

func TestAPILockingAnAlreadyLockedAccountIsHarmless(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	e.login(subAna, "ana@example.com")
	e.login(subBob, "bob@example.com", "admin")
	a := e.api(e.svcKey("robot", "users:lock users:unlock"))
	a.ok("POST", "/api/v1/users/"+subAna+"/lock", nil, 200)
	m := a.ok("POST", "/api/v1/users/"+subAna+"/lock", nil, 200)
	if m["sessions_ended"].(float64) != 0 {
		t.Fatalf("%v", m)
	}
	a.ok("POST", "/api/v1/users/"+subAna+"/unlock", nil, 200)
	a.ok("POST", "/api/v1/users/"+subAna+"/unlock", nil, 200)
}

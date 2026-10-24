package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	oc "github.com/azero/thevault/server/internal/omniconnect"
)

const (
	omniKeyID  = "ocr_test1"
	omniSecret = "ocs_0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
)

var omniKey = oc.Key{ID: omniKeyID, Secret: []byte(omniSecret)}

func withOmni(extra ...string) opt {
	return func(m map[string]string, e *env) {
		m["VAULT_OMNICORE_KEYS"] = omniKeyID + ":" + omniSecret
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i]] = extra[i+1]
		}
	}
}

// omniDo sends a correctly signed request as OmniCore would (user "" = none).
func omniDo(e *env, path, user string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	oc.SignRequest(omniKey, req, user, time.Now())
	return omniSend(e, req)
}

func omniSend(e *env, req *http.Request) (int, []byte) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		e.t.Errorf("%s: missing no-store/nosniff headers: %v", req.URL.Path, resp.Header)
	}
	return resp.StatusCode, b
}

func omniWidget(e *env, id, user, query string) (int, oc.Widget, string) {
	e.t.Helper()
	st, b := omniDo(e, oc.Prefix+"/widgets/"+id+query, user)
	var w oc.Widget
	if st == 200 {
		if err := json.Unmarshal(b, &w); err != nil {
			e.t.Fatalf("widget %s: %v: %s", id, err, b)
		}
	}
	return st, w, string(b)
}

func TestOmniCoreNotMountedWithoutKeys(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.srv.URL+oc.Prefix+"/manifest", nil)
	oc.SignRequest(omniKey, req, "", time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 || strings.Contains(string(b), "widgets") {
		t.Fatalf("the endpoints must not exist without VAULT_OMNICORE_KEYS: %d %s", resp.StatusCode, b)
	}
}

func TestOmniCoreRejectsUnauthenticatedRequests(t *testing.T) {
	e := newEnv(t, withOmni())
	e.login(subAna, "ana@example.com")
	now := time.Now()
	path := oc.Prefix + "/widgets/vault_status"
	signed := func(k oc.Key, p, user string, at time.Time) *http.Request {
		req, _ := http.NewRequest("GET", e.srv.URL+p, nil)
		oc.SignRequest(k, req, user, at)
		return req
	}
	cases := map[string]*http.Request{}
	unsigned, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	cases["unsigned"] = unsigned
	cases["forged signature"] = func() *http.Request {
		r := signed(omniKey, path, subAna, now)
		r.Header.Set(oc.HeaderSignature, "v1="+strings.Repeat("a", 64))
		return r
	}()
	cases["wrong secret"] = signed(oc.Key{ID: omniKeyID, Secret: []byte("ocs_wrong_wrong_wrong_wrong_wrong_wrong_1")}, path, subAna, now)
	cases["wrong key id"] = signed(oc.Key{ID: "ocr_other", Secret: []byte(omniSecret)}, path, subAna, now)
	cases["stale"] = signed(omniKey, path, subAna, now.Add(-10*time.Minute))
	cases["future"] = signed(omniKey, path, subAna, now.Add(10*time.Minute))
	cases["tampered user"] = func() *http.Request {
		r := signed(omniKey, path, subAna, now)
		r.Header.Set(oc.HeaderUser, subBob)
		return r
	}()
	cases["tampered path"] = func() *http.Request {
		r := signed(omniKey, path, subAna, now)
		r.URL.Path = oc.Prefix + "/widgets/security_events"
		return r
	}()
	cases["tampered query"] = func() *http.Request {
		r := signed(omniKey, path+"?cfg.days=7", subAna, now)
		r.URL.RawQuery = "cfg.days=90"
		return r
	}()
	cases["POST"] = func() *http.Request { r := signed(omniKey, path, subAna, now); r.Method = "POST"; return r }()
	cases["a session cookie is not a credential"] = func() *http.Request {
		c := e.login(subAna, "ana@example.com")
		r, _ := http.NewRequest("GET", e.srv.URL+path, nil)
		for _, ck := range c.hc.Jar.Cookies(r.URL) {
			r.AddCookie(ck)
		}
		r.Header.Set(oc.HeaderUser, subAna)
		return r
	}()
	var first string
	for name, req := range cases {
		st, b := omniSend(e, req)
		if st != 401 {
			t.Errorf("%s: status %d, want 401: %s", name, st, b)
		}
		if first == "" {
			first = string(b)
		} else if string(b) != first {
			t.Errorf("%s: body differs from the others (must not say why): %s vs %s", name, b, first)
		}
	}
	if strings.TrimSpace(first) != `{"error":"unauthorized"}` {
		t.Errorf("unexpected 401 body %q", first)
	}

	// replay: a captured valid request works once and never again
	r := signed(omniKey, oc.Prefix+"/manifest", "", now)
	if st, _ := omniSend(e, r); st != 200 {
		t.Fatalf("first use: %d", st)
	}
	if st, _ := omniSend(e, r); st != 401 {
		t.Fatalf("replay: %d", st)
	}
	// a request that failed the signature does not burn its nonce
	r2 := signed(omniKey, oc.Prefix+"/manifest", "", now)
	good := r2.Header.Get(oc.HeaderSignature)
	r2.Header.Set(oc.HeaderSignature, "v1="+strings.Repeat("b", 64))
	omniSend(e, r2)
	r2.Header.Set(oc.HeaderSignature, good)
	if st, _ := omniSend(e, r2); st != 200 {
		t.Fatalf("a failed signature must not consume the nonce: %d", st)
	}

	// audited as omnicore_auth_failed, thinned to one row a minute per address, without any secret
	rows, _ := e.st.ListAudit(e.ctx, "", 1000)
	n := 0
	for _, row := range rows {
		if row.Event == "omnicore_auth_failed" {
			n++
			if row.Outcome != "failure" || !regexp.MustCompile(`^reason=[a-z_]+$`).MatchString(row.Details) {
				t.Errorf("audit row shape: %+v", row)
			}
		}
		if strings.Contains(row.Details+row.Target+row.Actor, omniSecret) || strings.Contains(row.Details, omniKeyID) {
			t.Errorf("secret or key id in the audit log: %+v", row)
		}
	}
	if n != 1 {
		t.Errorf("want exactly one thinned omnicore_auth_failed row from one address, got %d", n)
	}
}

var (
	reSlug  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	reWID   = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
	reColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	icons   = map[string]bool{}
)

func init() {
	for _, i := range strings.Fields("home folder image doc sheet lock shield mail bell film tv board check cart calendar link user users settings chart server key alert clock search star tag list cloud globe") {
		icons[i] = true
	}
}

func TestOmniCoreManifestAndEveryWidget(t *testing.T) {
	e := newEnv(t, withOmni())
	adm := e.login(subBob, "bob@example.com", "admin")
	setupVault(t, adm)
	e.login(subAna, "ana@example.com")

	st, b := omniDo(e, oc.Prefix+"/manifest", "")
	if st != 200 {
		t.Fatalf("manifest %d %s", st, b)
	}
	var m oc.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Protocol != 1 || !reSlug.MatchString(m.App.ID) || m.App.ID != "thevault" || !icons[m.App.Icon] || !reColor.MatchString(m.App.Accent) || m.App.PublicURL != e.srv.URL {
		t.Fatalf("app info: %+v", m.App)
	}
	if n := len(m.Widgets); n < 6 || n > 12 {
		t.Fatalf("%d widgets, want 6-12", n)
	}
	kinds := map[string]bool{"stat": true, "list": true, "table": true, "series": true, "progress": true, "status": true, "agenda": true, "text": true, "notice": true}
	ids := map[string]bool{}
	adminOnly := 0
	for _, w := range m.Widgets {
		if !reWID.MatchString(w.ID) || ids[w.ID] || w.Title == "" || !kinds[w.Kind] || w.Default.W < 1 || w.Default.H < 1 || w.Default.W > 12 {
			t.Errorf("widget spec: %+v", w)
		}
		if w.Min != nil && (w.Min.W > w.Default.W || w.Min.H > w.Default.H) || w.Max != nil && (w.Max.W < w.Default.W || w.Max.H < w.Default.H || w.Max.W > 12) {
			t.Errorf("%s: min/default/max out of order", w.ID)
		}
		for _, f := range w.Config {
			if !regexp.MustCompile(`^[a-z0-9_]{1,40}$`).MatchString(f.Key) || (f.Type != "select" && f.Type != "text" && f.Type != "number" && f.Type != "bool") {
				t.Errorf("%s config %+v", w.ID, f)
			}
		}
		if len(w.Roles) > 0 {
			adminOnly++
			if len(w.Roles) != 1 || w.Roles[0] != "admin" {
				t.Errorf("%s roles %v", w.ID, w.Roles)
			}
		}
		ids[w.ID] = true
	}
	if adminOnly == 0 {
		t.Error("expected administrator widgets")
	}
	if len(m.Overview.Widgets) == 0 {
		t.Error("overview is empty")
	}
	sum := 0
	for _, o := range m.Overview.Widgets {
		if !ids[o.Widget] {
			t.Errorf("overview names unknown widget %s", o.Widget)
		}
		sum += o.W
	}
	if sum%12 != 0 {
		t.Errorf("overview widths sum to %d, rows should fill 12 columns", sum)
	}
	if n := len(m.Notifications.Categories); n < 4 || n > 12 {
		t.Errorf("%d categories", n)
	}
	mandatory := map[string]bool{}
	for _, c := range m.Notifications.Categories {
		if !regexp.MustCompile(`^[a-z0-9_]{1,40}$`).MatchString(c.ID) || c.Title == "" || (c.Level != "info" && c.Level != "notice" && c.Level != "important" && c.Level != "critical") {
			t.Errorf("category %+v", c)
		}
		if c.Mandatory {
			mandatory[c.ID] = true
		}
	}
	for _, want := range []string{"new_device", "master_password_changed", "recovery_key_used", "unlock_failed"} {
		if !mandatory[want] {
			t.Errorf("%s must be mandatory", want)
		}
	}
	if mandatory["space_invitation"] || mandatory["admin_security"] || mandatory["member_removed_rotate"] {
		t.Error("only security events about the recipient's own account may be mandatory")
	}

	if st, b := omniDo(e, oc.Prefix+"/status", ""); st != 200 || !strings.Contains(string(b), `"protocol":1`) {
		t.Errorf("status %d %s", st, b)
	}

	// every widget answers for an administrator, passes Sanitize unchanged, and is refused to a member where it is restricted
	for _, w := range m.Widgets {
		st, got, raw := omniWidget(e, w.ID, subBob, "")
		if st != 200 {
			t.Errorf("%s as admin: %d %s", w.ID, st, raw)
			continue
		}
		again, err := oc.Sanitize(got)
		if err != nil {
			t.Errorf("%s: %v", w.ID, err)
		}
		a, _ := json.Marshal(got)
		bb, _ := json.Marshal(again)
		if string(a) != string(bb) {
			t.Errorf("%s: payload changes when sanitised again", w.ID)
		}
		stM, _, rawM := omniWidget(e, w.ID, subAna, "")
		if len(w.Roles) > 0 {
			if stM != 403 || !strings.Contains(rawM, `"forbidden"`) {
				t.Errorf("%s as member: %d %s (want 403 forbidden)", w.ID, stM, rawM)
			}
		} else if stM != 200 {
			t.Errorf("%s as member: %d %s", w.ID, stM, rawM)
		}
	}
	if st, _, _ := omniWidget(e, "nope", subBob, ""); st != 404 {
		t.Errorf("unknown widget: %d", st)
	}
	// hostile configuration falls back to defaults
	if st, w, _ := omniWidget(e, "security_events", subBob, "?cfg.days=%27%3Bdrop&cfg.x=1"); st != 200 || w.Kind != oc.KindList {
		t.Errorf("hostile cfg: %d", st)
	}
	if st, _ := omniDo(e, oc.Prefix+"/widgets/vault_status", ""); st != 401 {
		t.Errorf("a widget request without a person must be refused, got %d", st)
	}
}

func TestOmniCoreLinkingRolesAndLocks(t *testing.T) {
	e := newEnv(t, withOmni())
	adm := e.login(subBob, "bob@example.com", "admin")
	setupVault(t, adm)
	ana := e.login(subAna, "ana@example.com")

	if st, _, raw := omniWidget(e, "vault_status", subCat, ""); st != 403 || !strings.Contains(raw, `"not_linked"`) {
		t.Fatalf("unknown person: %d %s", st, raw)
	}
	if st, _, _ := omniWidget(e, "vault_status", subAna, ""); st != 200 {
		t.Fatalf("known person: %d", st)
	}
	if st, _, _ := omniWidget(e, "sessions", subAna, ""); st != 403 {
		t.Fatalf("member on an admin widget: %d", st)
	}
	if st, _, _ := omniWidget(e, "sessions", subBob, ""); st != 200 {
		t.Fatalf("admin on an admin widget: %d", st)
	}
	// a person locked by an administrator has no access to TheVault, so none to its widgets
	adm.call("POST", "/api/v1/admin/users/"+subAna+"/lock", struct{}{}, 200, nil)
	if st, _, _ := omniWidget(e, "vault_status", subAna, ""); st != 403 {
		t.Fatalf("locked person: %d", st)
	}
	adm.call("POST", "/api/v1/admin/users/"+subAna+"/unlock", struct{}{}, 200, nil)
	if st, _, _ := omniWidget(e, "vault_status", subAna, ""); st != 200 {
		t.Fatalf("unlocked again: %d", st)
	}
	// a live session that ClosedDoor has already re-validated down to member outweighs the role recorded at sign-in
	if _, err := e.st.DB.Exec(`UPDATE sessions SET role='member' WHERE sub=?`, subBob); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := omniWidget(e, "sessions", subBob, ""); st != 403 {
		t.Fatalf("a demoted administrator keeps admin widgets: %d", st)
	}
	_ = ana
}

// A person's data never reaches anyone else, no widget needs the vault to be unlocked, and no widget carries anything the
// server could not already show: ciphertext, space names, item data, other people's addresses.
func TestOmniCoreIsolationAndZeroKnowledge(t *testing.T) {
	e := newEnv(t, withOmni())
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	bob := e.login(subBob, "bob@example.com")
	setupVault(t, bob)

	// recognisable ciphertext everywhere
	secretEnv := func(tag string) string {
		return "1." + b64(randBytes(12)) + "." + b64([]byte("SECRET-"+tag+"-"+strings.Repeat("x", 30)))
	}
	space := hexID()
	nameBlob := secretEnv("spacename")
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": space, "name_blob": nameBlob, "wrap": wrap()}, 200, nil)
	ana.call("POST", "/api/v1/spaces/"+space+"/members", map[string]any{"sub": subBob, "role": "editor", "key_version": 1, "wrap": wrap()}, 200, nil)
	itemBlob := secretEnv("item")
	ana.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": itemBlob}, 200, nil)
	ana.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": space, "base_seq": 0, "key_version": 1, "blob": secretEnv("spaceitem")}, 200, nil)
	// wrong passwords on Ana's vault only
	ana.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	for i := 0; i < 2; i++ {
		ana.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": proof()})
	}
	// Ana's extension device with a name only she chose
	e.sso.set(func() { e.sso.Sub, e.sso.Email, e.sso.Roles = subAna, "ana@example.com", nil })
	redirect := "https://" + extID + ".chromiumapp.org/cb"
	verifier := b64(randBytes(48))
	_, loc := startExt(t, e, redirect, challengeFor(verifier), "")
	x := e.newClient()
	x.call("POST", "/api/v1/ext/token", map[string]any{"code": loc.Query().Get("code"), "verifier": verifier, "redirect_uri": redirect, "label": "Ana-laptop-UNIQUE"}, 200, nil)

	var before int64
	e.st.DB.QueryRow(`SELECT COALESCE(SUM(unlocked_until),0) FROM sessions`).Scan(&before)

	ids := []string{"vault_status", "vault_size", "spaces", "my_devices", "security_events", "unlock_failures"}
	got := map[string]map[string]string{subAna: {}, subBob: {}}
	for _, sub := range []string{subAna, subBob} {
		for _, id := range ids {
			st, _, raw := omniWidget(e, id, sub, "")
			if st != 200 {
				t.Fatalf("%s for %s: %d %s", id, sub, st, raw)
			}
			got[sub][id] = raw
		}
	}
	for sub, m := range got {
		for id, raw := range m {
			for _, forbidden := range []string{nameBlob, itemBlob, "SECRET-", b64([]byte("SECRET-")), "wrap", "enc_pub", "kdf", "auth_hash", "access_token", "vxs_", "cds_secret", "vault_session"} {
				if strings.Contains(raw, forbidden) {
					t.Errorf("%s for %s leaks %q: %s", id, sub, forbidden, raw)
				}
			}
			if sub == subBob {
				for _, other := range []string{"Ana-laptop-UNIQUE", "ana@example.com", subAna} {
					if strings.Contains(raw, other) {
						t.Errorf("Bob's %s contains Ana's data %q: %s", id, other, raw)
					}
				}
			}
			if strings.Contains(raw, "@example.com") {
				t.Errorf("%s for %s shows an e-mail address: %s", id, sub, raw)
			}
		}
	}
	// Ana sees her device, her wrong passwords and her two spaces numbers; Bob sees none of them
	if !strings.Contains(got[subAna]["my_devices"], "Ana-laptop-UNIQUE") {
		t.Errorf("Ana's own device name should be shown: %s", got[subAna]["my_devices"])
	}
	if !strings.Contains(got[subAna]["security_events"], "Wrong master password") || !strings.Contains(got[subAna]["security_events"], "New extension device authorised") {
		t.Errorf("Ana's security events: %s", got[subAna]["security_events"])
	}
	if strings.Contains(got[subBob]["security_events"], "Wrong master password") {
		t.Errorf("Bob sees Ana's failed unlocks: %s", got[subBob]["security_events"])
	}
	_, wf, _ := omniWidget(e, "unlock_failures", subAna, "")
	tot := 0.0
	for _, p := range wf.Series[0].Points {
		tot += p.V
	}
	_, wfb, _ := omniWidget(e, "unlock_failures", subBob, "")
	totB := 0.0
	for _, p := range wfb.Series[0].Points {
		totB += p.V
	}
	if tot != 2 || totB != 0 {
		t.Errorf("failed unlock series: ana %v bob %v, want 2 and 0", tot, totB)
	}
	_, sp, _ := omniWidget(e, "spaces", subAna, "")
	if sp.Value != "1" {
		t.Errorf("spaces value %q", sp.Value)
	}
	_, sz, _ := omniWidget(e, "vault_size", subAna, "")
	if sz.Value != "1" {
		t.Errorf("items value %q (only the personal vault is counted)", sz.Value)
	}

	// answering widgets never unlocks anything, and they work while the vault is locked
	var after int64
	e.st.DB.QueryRow(`SELECT COALESCE(SUM(unlocked_until),0) FROM sessions`).Scan(&after)
	if after != before {
		t.Errorf("unlock state changed by widget requests: %d -> %d", before, after)
	}
	if st, _ := ana.status("GET", "/api/v1/sync?since=0", nil); st != 403 && st != 401 && st != 423 {
		t.Errorf("the vault must still be locked after widget requests, sync gave %d", st)
	}
}

func TestOmniCoreAdminWidgetsShowOperationalNumbersOnly(t *testing.T) {
	sky := newFakeSky(t)
	e := newEnv(t, withOmni(), withSky(sky, nil))
	adm := e.login(subBob, "bob@example.com", "admin")
	setupVault(t, adm)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	ana.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	ana.ip = "203.0.113.9"
	ana.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": proof()})
	now := time.Now().Unix()
	sky.command(7, sky.agentID, "block_ip", map[string]any{"ip": "203.0.113.50", "ttl_seconds": 600}, false, now, now+300)
	waitFor(t, "block applied", func() bool {
		_, _, raw := omniWidget(e, "blocked_ips", subBob, "")
		return strings.Contains(raw, "203.0.113.50")
	})

	for _, id := range []string{"users", "failed_unlocks", "blocked_ips", "sessions"} {
		st, _, raw := omniWidget(e, id, subBob, "")
		if st != 200 {
			t.Fatalf("%s: %d", id, st)
		}
		for _, bad := range []string{"ana@example.com", "bob@example.com", subAna, subBob, "203.0.113.9"} {
			if strings.Contains(raw, bad) {
				t.Errorf("%s shows %q: %s", id, bad, raw)
			}
		}
	}
	_, w, _ := omniWidget(e, "failed_unlocks", subBob, "?cfg.hours=24")
	tot := 0.0
	for _, p := range w.Series[0].Points {
		tot += p.V
	}
	if tot != 1 || len(w.Series[0].Points) != 24 {
		t.Errorf("failed unlocks per hour: total %v over %d points", tot, len(w.Series[0].Points))
	}
	_, u, _ := omniWidget(e, "users", subBob, "")
	if u.Value != "2" {
		t.Errorf("users value %q", u.Value)
	}
}

// ---- notifications ----

type fakeBeacon struct {
	srv  *httptest.Server
	mu   sync.Mutex
	cat  map[string]any
	msgs []map[string]any
	fail bool
	auth []string
}

func newFakeBeacon(t *testing.T) *fakeBeacon {
	b := &fakeBeacon{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b.mu.Lock()
		defer b.mu.Unlock()
		b.auth = append(b.auth, r.Header.Get("Authorization"))
		if b.fail {
			w.WriteHeader(503)
			return
		}
		var m map[string]any
		json.Unmarshal(body, &m)
		switch {
		case r.Method == "PUT" && r.URL.Path == "/api/v1/sources/thevault":
			b.cat = m
			w.WriteHeader(200)
		case r.Method == "POST" && r.URL.Path == "/api/v1/messages":
			b.msgs = append(b.msgs, m)
			w.WriteHeader(202)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func withBeacon(b *fakeBeacon, extra ...string) opt {
	return func(m map[string]string, e *env) {
		m["VAULT_BEACON_URL"] = b.srv.URL
		m["VAULT_BEACON_KEY"] = "key_1.beaconsecret0123456789"
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i]] = extra[i+1]
		}
	}
}

func (b *fakeBeacon) messages(category string) []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, m := range b.msgs {
		if m["category"] == category {
			out = append(out, m)
		}
	}
	return out
}

func (b *fakeBeacon) all() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	j, _ := json.Marshal(b.msgs)
	return string(j)
}

func (b *fakeBeacon) count() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.msgs) }

func recipients(m map[string]any) []string {
	var out []string
	for _, r := range m["to"].([]any) {
		for k, v := range r.(map[string]any) {
			out = append(out, k+"="+v.(string))
		}
	}
	return out
}

func addExtDevice(t *testing.T, e *env, sub, email, label, oldToken string) string {
	t.Helper()
	e.sso.set(func() { e.sso.Sub, e.sso.Email, e.sso.Roles = sub, email, nil })
	redirect := "https://" + extID + ".chromiumapp.org/cb"
	verifier := b64(randBytes(48))
	_, loc := startExt(t, e, redirect, challengeFor(verifier), "")
	x := e.newClient()
	x.bearer = oldToken
	var out struct{ Token string }
	x.call("POST", "/api/v1/ext/token", map[string]any{"code": loc.Query().Get("code"), "verifier": verifier, "redirect_uri": redirect, "label": label}, 200, &out)
	return out.Token
}

func TestNotificationsFollowSecurityEvents(t *testing.T) {
	bc := newFakeBeacon(t)
	sky := newFakeSky(t)
	e := newEnv(t, withBeacon(bc), withSky(sky, nil))
	ana := e.login(subAna, "ana@example.com")
	m := setupVault(t, ana)
	bob := e.login(subBob, "bob@example.com", "admin")
	setupVault(t, bob)

	// the catalog reaches Beacon with the mandatory flags
	waitFor(t, "catalog", func() bool { bc.mu.Lock(); defer bc.mu.Unlock(); return bc.cat != nil })
	bc.mu.Lock()
	cats := map[string]map[string]any{}
	for _, c := range bc.cat["categories"].([]any) {
		cats[c.(map[string]any)["id"].(string)] = c.(map[string]any)
	}
	bc.mu.Unlock()
	for id, want := range map[string]bool{"new_device": true, "master_password_changed": true, "recovery_key_used": true, "unlock_failed": true, "space_invitation": false, "member_removed_rotate": false, "admin_security": false} {
		c, ok := cats[id]
		if !ok || (c["mandatory"] == true) != want {
			t.Errorf("catalog %s: %v", id, c)
		}
	}

	// a new extension device: critical, to that person only; a renewal is not news
	tok := addExtDevice(t, e, subAna, "ana@example.com", "Ana-laptop-UNIQUE", "")
	waitFor(t, "new_device", func() bool { return len(bc.messages("new_device")) == 1 })
	nd := bc.messages("new_device")[0]
	if nd["source"] != "thevault" || nd["level"] != "critical" || fmt.Sprint(recipients(nd)) != "[user="+subAna+"]" || !strings.HasPrefix(nd["idempotency_key"].(string), "thevault:new_device:") {
		t.Fatalf("new_device message: %v", nd)
	}
	addExtDevice(t, e, subAna, "ana@example.com", "Ana-laptop-UNIQUE", tok) // renewal with the previous token
	time.Sleep(200 * time.Millisecond)
	if n := len(bc.messages("new_device")); n != 1 {
		t.Fatalf("a renewal produced a notification (%d messages)", n)
	}

	// master password change
	change := map[string]any{"auth_old": m.Auth, "auth_new": proof(), "kdf": "pbkdf2-sha256", "iterations": 1000000, "salt": b64(randBytes(32)), "wrapped_uk": envelope()}
	ana.call("POST", "/api/v1/vault/password", change, 200, nil)
	waitFor(t, "master_password_changed", func() bool { return len(bc.messages("master_password_changed")) == 1 })
	if mp := bc.messages("master_password_changed")[0]; mp["level"] != "critical" || fmt.Sprint(recipients(mp)) != "[user="+subAna+"]" {
		t.Fatalf("password message: %v", mp)
	}

	// recovery
	freshAuth, freshRec := proof(), proof()
	ana.call("POST", "/api/v1/vault/recovery/start", map[string]any{"proof": m.RecoveryProof}, 200, nil)
	ana.call("POST", "/api/v1/vault/recovery/finish", map[string]any{"proof": m.RecoveryProof, "auth_new": freshAuth, "kdf": "pbkdf2-sha256", "iterations": 1000000, "salt": b64(randBytes(32)), "wrapped_uk": envelope(),
		"recovery": map[string]any{"proof": freshRec, "wrapped_uk": envelope()}}, 200, nil)
	waitFor(t, "recovery_key_used", func() bool { return len(bc.messages("recovery_key_used")) == 1 })

	// repeated wrong master passwords: one message per 15 minutes, only from the third failure
	ana2 := e.login(subAna, "ana@example.com")
	ana2.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	for i := 0; i < 2; i++ {
		ana2.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": proof()})
	}
	time.Sleep(150 * time.Millisecond)
	if n := len(bc.messages("unlock_failed")); n != 0 {
		t.Fatalf("typos must not notify: %d", n)
	}
	for i := 0; i < 4; i++ {
		ana2.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": proof()})
	}
	waitFor(t, "unlock_failed", func() bool { return len(bc.messages("unlock_failed")) >= 1 })
	time.Sleep(200 * time.Millisecond)
	if n := len(bc.messages("unlock_failed")); n != 1 {
		t.Fatalf("an attacker could spam the owner: %d messages", n)
	}
	if uf := bc.messages("unlock_failed")[0]; uf["level"] != "important" || fmt.Sprint(recipients(uf)) != "[user="+subAna+"]" {
		t.Fatalf("unlock_failed: %v", uf)
	}

	// spaces: the person added is told (no name), the owner is told to rotate after a removal
	cat := e.login(subCat, "cat@example.com")
	setupVault(t, cat)
	dan := "dddddddddddddddddddddddddddddddd"
	dc := e.login(dan, "dan@example.com")
	setupVault(t, dc)
	space := hexID()
	dc.call("POST", "/api/v1/spaces", map[string]any{"id": space, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
	dc.call("POST", "/api/v1/spaces/"+space+"/members", map[string]any{"sub": subCat, "role": "viewer", "key_version": 1, "wrap": wrap()}, 200, nil)
	waitFor(t, "space_invitation", func() bool { return len(bc.messages("space_invitation")) == 1 })
	inv := bc.messages("space_invitation")[0]
	if inv["level"] != "notice" || fmt.Sprint(recipients(inv)) != "[user="+subCat+"]" {
		t.Fatalf("invitation: %v", inv)
	}
	dc.call("DELETE", "/api/v1/spaces/"+space+"/members/"+subCat, nil, 200, nil)
	waitFor(t, "member_removed_rotate", func() bool { return len(bc.messages("member_removed_rotate")) == 1 })
	if rm := bc.messages("member_removed_rotate")[0]; rm["level"] != "important" || fmt.Sprint(recipients(rm)) != "[user="+dan+"]" {
		t.Fatalf("rotation message: %v", rm)
	}

	// administrators: a lock and a signed block_ip go to the admin group
	bob.call("POST", "/api/v1/admin/users/"+subCat+"/lock", struct{}{}, 200, nil)
	waitFor(t, "admin lock", func() bool { return len(bc.messages("admin_security")) == 1 })
	now := time.Now().Unix()
	sky.command(11, sky.agentID, "block_ip", map[string]any{"ip": "203.0.113.50", "ttl_seconds": 600}, false, now, now+300)
	waitFor(t, "admin block", func() bool { return len(bc.messages("admin_security")) == 2 })
	for _, am := range bc.messages("admin_security") {
		if fmt.Sprint(recipients(am)) != "[group=admins]" || am["level"] != "important" {
			t.Fatalf("admin message: %v", am)
		}
	}

	// every message: no secret, no content, no e-mail address, no device name, and the right authorisation
	all := bc.all()
	for _, bad := range []string{"@example.com", "Ana-laptop-UNIQUE", "cds_secret", "key_1.beaconsecret", "SECRET", m.Auth, freshAuth, freshRec, "vxs_", "name_blob", "wrap", "ocs_"} {
		if strings.Contains(all, bad) {
			t.Errorf("a notification contains %q: %s", bad, all)
		}
	}
	bc.mu.Lock()
	defer bc.mu.Unlock()
	for _, a := range bc.auth {
		if a != "Bearer key_1.beaconsecret0123456789" {
			t.Errorf("Authorization header %q", a)
		}
	}
	for _, msg := range bc.msgs {
		if len(msg["subject"].(string)) > 120 || len(msg["text"].(string)) > 1000 || msg["category"] == "" || msg["level"] == "" {
			t.Errorf("message shape: %v", msg)
		}
	}
}

func TestNotificationFloorKeepsMandatoryEvents(t *testing.T) {
	bc := newFakeBeacon(t)
	e := newEnv(t, withBeacon(bc, "VAULT_NOTIFY_MIN_LEVEL", "critical"))
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	bob := e.login(subBob, "bob@example.com")
	setupVault(t, bob)
	space := hexID()
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": space, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
	ana.call("POST", "/api/v1/spaces/"+space+"/members", map[string]any{"sub": subBob, "role": "viewer", "key_version": 1, "wrap": wrap()}, 200, nil)
	ana.call("DELETE", "/api/v1/spaces/"+space+"/members/"+subBob, nil, 200, nil)
	ana.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	for i := 0; i < 3; i++ {
		ana.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": proof()})
	}
	waitFor(t, "mandatory unlock_failed despite the floor", func() bool { return len(bc.messages("unlock_failed")) == 1 })
	time.Sleep(200 * time.Millisecond)
	if n := len(bc.messages("space_invitation")) + len(bc.messages("member_removed_rotate")); n != 0 {
		t.Fatalf("events below the floor were sent: %d", n)
	}
}

func TestBeaconDownNeverAffectsRequests(t *testing.T) {
	bc := newFakeBeacon(t)
	bc.fail = true
	e := newEnv(t, withBeacon(bc))
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	ana.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	start := time.Now()
	for i := 0; i < 8; i++ {
		ana.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": proof()})
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("requests were slowed by an unreachable Beacon: %v", d)
	}
	if bc.count() != 0 {
		t.Fatal("nothing can have been delivered")
	}
	bc.srv.Close() // gone entirely
	addExtDevice(t, e, subAna, "ana@example.com", "x", "")
	if st := ana.getJSON("/api/v1/session", nil); st != 200 {
		t.Fatalf("session after Beacon vanished: %d", st)
	}
}

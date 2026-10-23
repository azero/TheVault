package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	subAna = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	subBob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	subCat = "cccccccccccccccccccccccccccccccc"
)

type sessionResp struct {
	User  struct{ Sub, Email, Name, Role string }
	CSRF  string
	Kind  string
	Vault struct {
		State          string
		Unlocked_until int64
	}
	SSO struct{ Fresh bool }
}

// setupVault creates the vault for a freshly logged-in client and returns its proofs.
func setupVault(t *testing.T, c *client) vaultMaterial {
	m := newMaterial()
	c.call("POST", "/api/v1/vault/setup", m.Setup, 200, nil)
	return m
}

func TestLoginSessionAndHeaders(t *testing.T) {
	e := newEnv(t)
	anon := e.newClient()
	if st := anon.getJSON("/api/v1/session", nil); st != 401 {
		t.Fatalf("anonymous session: %d", st)
	}
	// the shell redirects to /login, the login page renders
	anon.hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, _ := anon.hc.Get(e.srv.URL + "/")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/login" {
		t.Fatalf("shell without session: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = anon.hc.Get(e.srv.URL + "/login")
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "require-trusted-types-for 'script'", "frame-ancestors 'none'", "connect-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe") || strings.Contains(csp, "form-action") {
		t.Errorf("CSP must not contain unsafe-* or form-action: %s", csp)
	}
	for h, want := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Referrer-Policy": "same-origin"} {
		if resp.Header.Get(h) != want {
			t.Errorf("%s = %q, want %q", h, resp.Header.Get(h), want)
		}
	}

	c := e.login(subAna, "ana@example.com")
	var s sessionResp
	c.call("GET", "/api/v1/session", nil, 200, &s)
	if s.User.Sub != subAna || s.User.Role != "member" || s.Vault.State != "none" || !s.SSO.Fresh || s.Kind != "web" || len(s.CSRF) < 20 {
		t.Fatalf("session: %+v", s)
	}
	_, _, h := c.do("GET", "/api/v1/session", nil, nil)
	if h.Get("Cache-Control") != "no-store" {
		t.Errorf("API responses must be no-store, got %q", h.Get("Cache-Control"))
	}
	ck := e.srv.Client().Jar
	_ = ck

	// admin label from the SSO's roles claim
	adm := e.login(subBob, "bob@example.com", "admin")
	adm.call("GET", "/api/v1/session", nil, 200, &s)
	if s.User.Role != "admin" {
		t.Fatalf("role: %+v", s.User)
	}
}

func TestStaticAssetsAndEtag(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()
	st, _, h := c.do("GET", "/static/app.css", nil, nil)
	if st != 200 && st != 404 {
		t.Fatalf("static: %d", st)
	}
	if st == 200 {
		etag := h.Get("ETag")
		st2, _, _ := c.do("GET", "/static/app.css", nil, map[string]string{"If-None-Match": etag})
		if st2 != 304 {
			t.Errorf("etag revalidation: %d", st2)
		}
	}
	if st, _, _ := c.do("GET", "/static/downloads/thevault-extension.zip", nil, nil); st != 404 {
		t.Errorf("downloads must only be served through the authenticated route, got %d", st)
	}
	if st, _, _ := c.do("GET", "/static/../../go.mod", nil, nil); st == 200 {
		t.Errorf("path traversal")
	}
}

func TestSetupUnlockLockAndThrottle(t *testing.T) {
	e := newEnv(t)
	c := e.login(subAna, "ana@example.com")
	var pre map[string]any
	if st := c.getJSON("/api/v1/vault/prelogin", &pre); st != 404 {
		t.Fatalf("prelogin before setup: %d", st)
	}
	// malformed setups are refused
	bad := newMaterial()
	bad.Setup["iterations"] = 1000
	c.call("POST", "/api/v1/vault/setup", bad.Setup, 400, nil)
	bad = newMaterial()
	bad.Setup["enc_pub"] = "short"
	c.call("POST", "/api/v1/vault/setup", bad.Setup, 400, nil)
	bad = newMaterial()
	bad.Setup["wrapped_uk"] = "plaintext secret"
	c.call("POST", "/api/v1/vault/setup", bad.Setup, 400, nil)
	bad = newMaterial()
	bad.Setup["recovery"] = map[string]any{"proof": bad.Auth, "wrapped_uk": envelope()}
	c.call("POST", "/api/v1/vault/setup", bad.Setup, 400, nil)

	m := setupVault(t, c)
	c.call("POST", "/api/v1/vault/setup", newMaterial().Setup, 409, nil) // only once
	var s sessionResp
	c.call("GET", "/api/v1/session", nil, 200, &s)
	if s.Vault.State != "unlocked" {
		t.Fatalf("setup should leave the session unlocked: %s", s.Vault.State)
	}

	// the database must not hold the proofs themselves
	vk, _ := e.st.GetVaultKeys(e.ctx, subAna)
	if vk.AuthHash == m.Auth || vk.RecoveryHash == m.RecoveryProof || len(vk.AuthHash) != 64 {
		t.Fatalf("proofs must be stored peppered: %q", vk.AuthHash)
	}

	c.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	if st, _ := c.status("GET", "/api/v1/sync", nil); st != 423 {
		t.Fatalf("sync while locked: %d", st)
	}
	var un map[string]any
	c.call("POST", "/api/v1/vault/unlock", map[string]any{"auth": m.Auth}, 200, &un)
	if un["wrapped_uk"] == "" || un["enc_priv"] == nil || un["salt"] == nil {
		t.Fatalf("unlock response: %v", un)
	}
	c.call("GET", "/api/v1/sync", nil, 200, nil)

	// four wrong proofs are free, the fifth locks
	c.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	for i := 1; i <= 4; i++ {
		st, body := c.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": proof()})
		if st != 401 || body["error"] != "bad_password" {
			t.Fatalf("wrong proof %d: %d %v", i, st, body)
		}
	}
	st, body := c.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": proof()})
	if st != 401 || body["retry_after"] == nil {
		t.Fatalf("fifth failure should report a lockout: %d %v", st, body)
	}
	st, _ = c.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": m.Auth})
	if st != 429 {
		t.Fatalf("even the right proof is refused during a lockout: %d", st)
	}
	// lockout events were audited
	rows, _ := e.st.ListAudit(e.ctx, "", 100)
	var failed, lockout int
	for _, r := range rows {
		switch r.Event {
		case "unlock_failed":
			failed++
		case "unlock_lockout":
			lockout++
		}
	}
	if failed != 5 || lockout != 1 {
		t.Fatalf("audit: failed=%d lockout=%d", failed, lockout)
	}
	// after the lockout expires, the right proof works and resets the counter
	e.st.DB.Exec(`UPDATE vault_keys SET locked_until = 0`)
	c.call("POST", "/api/v1/vault/unlock", map[string]any{"auth": m.Auth}, 200, nil)
	vk, _ = e.st.GetVaultKeys(e.ctx, subAna)
	if vk.FailedUnlocks != 0 {
		t.Fatalf("counter not reset: %d", vk.FailedUnlocks)
	}
}

func TestVerifyPasswordIsThrottledLikeUnlock(t *testing.T) {
	e := newEnv(t)
	c := e.login(subAna, "ana@example.com")
	m := setupVault(t, c)
	c.call("POST", "/api/v1/vault/verify", map[string]any{"auth": m.Auth}, 200, nil)
	for i := 0; i < 4; i++ {
		c.call("POST", "/api/v1/vault/verify", map[string]any{"auth": proof()}, 401, nil)
	}
	st, body := c.status("POST", "/api/v1/vault/verify", map[string]any{"auth": proof()})
	if st != 401 || body["retry_after"] == nil {
		t.Fatalf("the fifth wrong proof must start a lockout: %d %v", st, body)
	}
	c.call("POST", "/api/v1/vault/verify", map[string]any{"auth": m.Auth}, 429, nil)
	var s map[string]any
	c.call("GET", "/api/v1/session", nil, 200, &s)
	if ids, ok := s["extension_ids"].([]any); !ok || len(ids) != 1 {
		t.Fatalf("extension_ids must always be a list: %v", s["extension_ids"])
	}
}

func TestIdleLockAndSSOExpiry(t *testing.T) {
	e := newEnv(t)
	c := e.login(subAna, "ana@example.com")
	m := setupVault(t, c)
	c.call("GET", "/api/v1/sync", nil, 200, nil)
	// idle: the unlock grant has run out
	e.st.DB.Exec(`UPDATE sessions SET unlocked_until = ?`, time.Now().Unix()-1)
	if st, _ := c.status("GET", "/api/v1/sync", nil); st != 423 {
		t.Fatalf("expired unlock: %d", st)
	}
	// the SSO token has expired: unlocking needs a fresh sign-in first
	e.st.DB.Exec(`UPDATE sessions SET token_expiry = ?`, time.Now().Unix()-10)
	st, body := c.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": m.Auth})
	if st != 401 || body["error"] != "sso_expired" {
		t.Fatalf("unlock with an expired SSO token: %d %v", st, body)
	}
	// sign in again silently: a new session, unlock works
	c2 := e.login(subAna, "ana@example.com")
	c2.call("POST", "/api/v1/vault/unlock", map[string]any{"auth": m.Auth}, 200, nil)
}

func TestSSORevocationAndOutage(t *testing.T) {
	e := newEnv(t)
	c := e.login(subAna, "ana@example.com")
	setupVault(t, c)
	// an SSO outage keeps the session
	e.sso.set(func() { e.sso.Down = true })
	e.st.DB.Exec(`UPDATE sessions SET checked_at = 0`)
	c.call("GET", "/api/v1/sync", nil, 200, nil)
	// ClosedDoor removing the user's access ends the session at the next re-validation
	e.sso.set(func() { e.sso.Down = false; e.sso.Revoke = true })
	e.st.DB.Exec(`UPDATE sessions SET checked_at = 0`)
	st, body := c.status("GET", "/api/v1/sync", nil)
	if st != 401 || body["error"] != "session_revoked" {
		t.Fatalf("revoked: %d %v", st, body)
	}
	if st := c.getJSON("/api/v1/session", nil); st != 401 {
		t.Fatalf("session must be gone: %d", st)
	}
}

func TestCSRFOriginAndContentType(t *testing.T) {
	e := newEnv(t)
	c := e.login(subAna, "ana@example.com")
	m := setupVault(t, c)
	c.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	body := map[string]any{"auth": m.Auth}
	if st, b, _ := c.do("POST", "/api/v1/vault/unlock", body, map[string]string{"X-Vault-CSRF": ""}); st != 403 {
		t.Errorf("missing csrf header: %d %s", st, b)
	}
	if st, _, _ := c.do("POST", "/api/v1/vault/unlock", body, map[string]string{"X-Vault-CSRF": "nope"}); st != 403 {
		t.Errorf("wrong csrf: %d", st)
	}
	if st, _, _ := c.do("POST", "/api/v1/vault/unlock", body, map[string]string{"Origin": "https://evil.example"}); st != 403 {
		t.Errorf("foreign origin: %d", st)
	}
	if st, _, _ := c.do("POST", "/api/v1/vault/unlock", body, map[string]string{"Origin": "chrome-extension://" + extID}); st != 403 {
		t.Errorf("cookie sessions must not accept the extension origin: %d", st)
	}
	if st, _, _ := c.do("POST", "/api/v1/vault/unlock", body, map[string]string{"Sec-Fetch-Site": "cross-site"}); st != 403 {
		t.Errorf("cross-site fetch metadata: %d", st)
	}
	if st, _, _ := c.do("POST", "/api/v1/vault/unlock", body, map[string]string{"Content-Type": "text/plain"}); st != 400 {
		t.Errorf("content type: %d", st)
	}
	if st, _, _ := c.do("POST", "/api/v1/vault/unlock", body, map[string]string{"Origin": e.srv.URL}); st != 200 {
		t.Errorf("same origin must work: %d", st)
	}
	rows, _ := e.st.ListAudit(e.ctx, "", 50)
	var csrf, origin int
	for _, r := range rows {
		switch r.Event {
		case "csrf_failed":
			csrf++
		case "origin_refused":
			origin++
		}
	}
	if csrf < 2 || origin < 1 {
		t.Errorf("refusals should be audited (csrf=%d origin=%d)", csrf, origin)
	}
	// unknown JSON fields are refused
	if st, _ := c.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": m.Auth, "extra": 1}); st != 400 {
		t.Errorf("unknown field: %d", st)
	}
}

func TestItemsLifecycle(t *testing.T) {
	e := newEnv(t)
	c := e.login(subAna, "ana@example.com")
	setupVault(t, c)
	id := hexID()
	put := func(base int64, want int) map[string]any {
		var out map[string]any
		c.call("PUT", "/api/v1/items/"+id, map[string]any{"vault_id": "personal", "base_seq": base, "key_version": 1, "blob": envelope()}, want, &out)
		return out
	}
	// validation
	c.call("PUT", "/api/v1/items/not-an-id", map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": envelope()}, 400, nil)
	c.call("PUT", "/api/v1/items/"+id, map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": "plaintext"}, 400, nil)
	c.call("PUT", "/api/v1/items/"+id, map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": "1." + b64(randBytes(12)) + "." + strings.Repeat("A", 262200)}, 400, nil)
	c.call("PUT", "/api/v1/items/"+id, map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 7, "blob": envelope()}, 400, nil) // wrong key version

	first := put(0, 200)
	seq1 := int64(first["seq"].(float64))
	put(0, 409) // creating over an id that exists must never overwrite it
	conflict := put(seq1+5, 409)
	if conflict["current"] == nil {
		t.Fatal("conflict must carry the current copy")
	}
	second := put(seq1, 200)
	seq2 := int64(second["seq"].(float64))
	if seq2 <= seq1 {
		t.Fatal("seq must grow")
	}
	var vers struct{ Versions []map[string]any }
	c.call("GET", "/api/v1/items/"+id+"/versions", nil, 200, &vers)
	if len(vers.Versions) != 1 {
		t.Fatalf("versions: %d", len(vers.Versions))
	}

	// sync
	var full struct {
		Seq   int64
		More  bool
		Items []map[string]any
	}
	c.call("GET", "/api/v1/sync?since=0", nil, 200, &full)
	if len(full.Items) != 1 || full.Items[0]["blob"] == "" {
		t.Fatalf("full sync: %+v", full)
	}
	var inc struct{ Items []map[string]any }
	c.call("GET", "/api/v1/sync?since="+itoa(full.Seq), nil, 200, &inc)
	if len(inc.Items) != 0 {
		t.Fatalf("incremental sync should be empty: %+v", inc)
	}

	// trash, restore, purge
	c.call("DELETE", "/api/v1/items/"+id, nil, 200, nil)
	c.call("PUT", "/api/v1/items/"+id, map[string]any{"vault_id": "personal", "base_seq": seq2 + 1, "key_version": 1, "blob": envelope()}, 400, nil) // restore from the trash first
	var tr struct{ Items []struct{ Deleted_at int64 } }
	c.call("GET", "/api/v1/sync?since="+itoa(full.Seq), nil, 200, &tr)
	if len(tr.Items) != 1 || tr.Items[0].Deleted_at == 0 {
		t.Fatalf("trashed item must show up in an incremental sync: %+v", tr)
	}
	c.call("POST", "/api/v1/items/"+id+"/restore", struct{}{}, 200, nil)
	c.call("DELETE", "/api/v1/items/"+id+"?purge=1", nil, 200, nil)
	var after struct{ Items []map[string]any }
	c.call("GET", "/api/v1/sync?since=0", nil, 200, &after)
	if len(after.Items) != 1 || after.Items[0]["purged"] != true || after.Items[0]["blob"] != nil && after.Items[0]["blob"] != "" {
		t.Fatalf("purged tombstone should carry no ciphertext: %+v", after.Items)
	}
	c.call("POST", "/api/v1/items/"+id+"/restore", struct{}{}, 404, nil)

	// import is all-or-nothing
	items := []map[string]any{{"id": hexID(), "blob": envelope()}, {"id": hexID(), "blob": envelope()}}
	c.call("POST", "/api/v1/items/import", map[string]any{"key_version": 1, "items": items}, 200, nil)
	dup := []map[string]any{{"id": hexID(), "blob": envelope()}, {"id": items[0]["id"], "blob": envelope()}}
	before := countItems(e)
	c.call("POST", "/api/v1/items/import", map[string]any{"key_version": 1, "items": dup}, 409, nil)
	if countItems(e) != before {
		t.Fatal("a failed import must not store anything")
	}
}

func countItems(e *env) int {
	var n int
	e.st.DB.QueryRow(`SELECT COUNT(*) FROM items`).Scan(&n)
	return n
}

func itoa(n int64) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestUsersCannotSeeEachOther(t *testing.T) {
	e := newEnv(t)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	id := hexID()
	ana.call("PUT", "/api/v1/items/"+id, map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": envelope()}, 200, nil)

	bob := e.login(subBob, "bob@example.com")
	setupVault(t, bob)
	var s struct{ Items []map[string]any }
	bob.call("GET", "/api/v1/sync?since=0", nil, 200, &s)
	if len(s.Items) != 0 {
		t.Fatal("bob sees ana's items")
	}
	bob.call("PUT", "/api/v1/items/"+id, map[string]any{"vault_id": "personal", "base_seq": 1, "key_version": 1, "blob": envelope()}, 404, nil)
	bob.call("DELETE", "/api/v1/items/"+id, nil, 404, nil)
	bob.call("GET", "/api/v1/items/"+id+"/versions", nil, 404, nil)
	bob.call("POST", "/api/v1/items/"+id+"/restore", struct{}{}, 404, nil)
	// nor can bob write into a space he is not in
	bob.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": hexID(), "base_seq": 0, "key_version": 1, "blob": envelope()}, 404, nil)
	// ana's item is untouched
	var a struct{ Items []map[string]any }
	ana.call("GET", "/api/v1/sync?since=0", nil, 200, &a)
	if len(a.Items) != 1 {
		t.Fatal("ana's item changed")
	}
}

func TestPasswordChangeAndRecovery(t *testing.T) {
	e := newEnv(t)
	c := e.login(subAna, "ana@example.com")
	m := setupVault(t, c)
	other := e.login(subAna, "ana@example.com") // a second session of the same user
	other.call("POST", "/api/v1/vault/unlock", map[string]any{"auth": m.Auth}, 200, nil)

	newAuth := proof()
	change := map[string]any{"auth_old": proof(), "auth_new": newAuth, "kdf": "pbkdf2-sha256", "iterations": 1000000, "salt": b64(randBytes(32)), "wrapped_uk": envelope()}
	c.call("POST", "/api/v1/vault/password", change, 401, nil) // wrong old password
	change["auth_old"] = m.Auth
	c.call("POST", "/api/v1/vault/password", change, 200, nil)
	if st := other.getJSON("/api/v1/session", nil); st != 401 {
		t.Fatalf("other sessions must end after a password change: %d", st)
	}
	c.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	c.call("POST", "/api/v1/vault/unlock", map[string]any{"auth": m.Auth}, 401, nil)
	c.call("POST", "/api/v1/vault/unlock", map[string]any{"auth": newAuth}, 200, nil)

	// recovery: wrong key is refused and counted; the right one resets the password and rotates the recovery key
	c.call("POST", "/api/v1/vault/recovery/start", map[string]any{"proof": proof()}, 401, nil)
	var start map[string]any
	c.call("POST", "/api/v1/vault/recovery/start", map[string]any{"proof": m.RecoveryProof}, 200, &start)
	if start["wrapped_uk"] == nil {
		t.Fatal("recovery start must return the recovery-wrapped key")
	}
	freshAuth, freshRec := proof(), proof()
	fin := map[string]any{"proof": m.RecoveryProof, "auth_new": freshAuth, "kdf": "pbkdf2-sha256", "iterations": 1000000, "salt": b64(randBytes(32)), "wrapped_uk": envelope(),
		"recovery": map[string]any{"proof": freshRec, "wrapped_uk": envelope()}}
	c.call("POST", "/api/v1/vault/recovery/finish", fin, 200, nil)
	c.call("POST", "/api/v1/vault/recovery/start", map[string]any{"proof": m.RecoveryProof}, 401, nil) // old recovery key is dead
	c.call("POST", "/api/v1/vault/recovery/start", map[string]any{"proof": freshRec}, 200, nil)
	c.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	c.call("POST", "/api/v1/vault/unlock", map[string]any{"auth": freshAuth}, 200, nil)

	// five wrong recovery keys lock recovery
	for i := 0; i < 5; i++ {
		c.status("POST", "/api/v1/vault/recovery/start", map[string]any{"proof": proof()})
	}
	if st, _ := c.status("POST", "/api/v1/vault/recovery/start", map[string]any{"proof": freshRec}); st != 429 {
		t.Fatalf("recovery lockout: %d", st)
	}
	names := auditNames(e)
	for _, want := range []string{"master_password_changed", "recovery_failed", "recovery_started", "recovery_used"} {
		if !names[want] {
			t.Errorf("missing audit event %s", want)
		}
	}
}

func auditNames(e *env) map[string]bool {
	rows, _ := e.st.ListAudit(e.ctx, "", 1000)
	m := map[string]bool{}
	for _, r := range rows {
		m[r.Event] = true
	}
	return m
}

func TestDevicesAndActivity(t *testing.T) {
	e := newEnv(t)
	c := e.login(subAna, "ana@example.com")
	setupVault(t, c)
	other := e.login(subAna, "ana@example.com")
	var list struct {
		Sessions []struct {
			ID      string
			Current bool
			Kind    string
		}
	}
	c.call("GET", "/api/v1/sessions", nil, 200, &list)
	if len(list.Sessions) != 2 {
		t.Fatalf("sessions: %+v", list)
	}
	var cur, oth string
	for _, s := range list.Sessions {
		if s.Current {
			cur = s.ID
		} else {
			oth = s.ID
		}
	}
	c.call("DELETE", "/api/v1/sessions/"+oth, nil, 200, nil)
	if st := other.getJSON("/api/v1/session", nil); st != 401 {
		t.Fatal("revoked session still works")
	}
	c.call("DELETE", "/api/v1/sessions/"+oth, nil, 404, nil)
	var act struct{ Events []map[string]any }
	c.call("GET", "/api/v1/activity", nil, 200, &act)
	if len(act.Events) == 0 {
		t.Fatal("expected activity")
	}
	c.call("POST", "/api/v1/audit/client", map[string]any{"event": "vault_export", "count": 12}, 200, nil)
	c.call("POST", "/api/v1/audit/client", map[string]any{"event": "item_deleted", "count": 1}, 400, nil) // only an allow-list
	_ = cur
	c.call("PUT", "/api/v1/settings", map[string]any{"idle_lock_minutes": 0}, 400, nil)
	c.call("PUT", "/api/v1/settings", map[string]any{"idle_lock_minutes": 30}, 200, nil)
	var s map[string]any
	c.call("GET", "/api/v1/session", nil, 200, &s)
	if s["idle_lock_minutes"].(float64) != 30 {
		t.Fatalf("idle setting: %v", s["idle_lock_minutes"])
	}
	c.call("POST", "/api/v1/session/logout", struct{}{}, 200, nil)
	if st := c.getJSON("/api/v1/session", nil); st != 401 {
		t.Fatal("logout did not end the session")
	}
}

func TestAdmin(t *testing.T) {
	e := newEnv(t)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	ana.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": envelope()}, 200, nil)
	if st, _ := ana.status("GET", "/api/v1/admin/overview", nil); st != 403 {
		t.Fatalf("members must not reach admin: %d", st)
	}
	adm := e.login(subBob, "bob@example.com", "admin")
	var ov struct {
		Stats struct{ Users, Vaults, Items int }
		Users []struct {
			Sub      string
			Items    int
			HasVault bool `json:"has_vault"`
		}
	}
	adm.call("GET", "/api/v1/admin/overview", nil, 200, &ov)
	if ov.Stats.Users != 2 || ov.Stats.Items != 1 {
		t.Fatalf("overview: %+v", ov)
	}
	// admins see counts, never content: the overview has no blob anywhere
	_, raw, _ := adm.do("GET", "/api/v1/admin/overview", nil, nil)
	if strings.Contains(string(raw), "blob") || strings.Contains(string(raw), "wrapped_uk") {
		t.Fatal("admin overview leaks ciphertext")
	}
	adm.call("POST", "/api/v1/admin/users/"+subBob+"/lock", struct{}{}, 409, nil) // not yourself
	adm.call("POST", "/api/v1/admin/users/"+subAna+"/lock", struct{}{}, 200, nil)
	if st := ana.getJSON("/api/v1/session", nil); st != 401 {
		t.Fatalf("locked user's sessions must end: %d", st)
	}
	// a locked user cannot sign back in
	e.sso.set(func() { e.sso.Sub, e.sso.Email, e.sso.Roles = subAna, "ana@example.com", nil })
	c := e.newClient()
	resp, _ := c.hc.Get(e.srv.URL + "/auth/login")
	if resp.StatusCode != 403 {
		t.Fatalf("locked login: %d", resp.StatusCode)
	}
	adm.call("POST", "/api/v1/admin/users/"+subAna+"/unlock", struct{}{}, 200, nil)
	ana2 := e.login(subAna, "ana@example.com")
	// erasing needs the confirmation
	adm.call("POST", "/api/v1/admin/users/"+subAna+"/erase-vault", map[string]any{"confirm": "wrong"}, 400, nil)
	adm.call("POST", "/api/v1/admin/users/"+subAna+"/erase-vault", map[string]any{"confirm": "ana@example.com"}, 200, nil)
	if st := ana2.getJSON("/api/v1/session", nil); st != 401 {
		t.Fatal("erase must end the sessions")
	}
	if countItems(e) != 0 {
		t.Fatal("erase left ciphertext behind")
	}
	var au struct{ Events []map[string]any }
	adm.call("GET", "/api/v1/admin/audit?limit=50", nil, 200, &au)
	names := auditNames(e)
	for _, want := range []string{"admin_user_locked", "admin_user_unlocked", "admin_vault_erased", "login_denied"} {
		if !names[want] {
			t.Errorf("missing audit event %s", want)
		}
	}
}

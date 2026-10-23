package e2e

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// An administrator whose ClosedDoor access token has expired cannot be re-validated, so administration waits for a
// fresh sign-in instead of trusting a role that may have been revoked.
func TestAdminNeedsFreshSSOToken(t *testing.T) {
	e := newEnv(t)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	adm := e.login(subBob, "bob@example.com", "admin")
	e.sso.set(func() { e.sso.Revoke = true })
	e.st.DB.Exec(`UPDATE sessions SET token_expiry = ?, checked_at = 0 WHERE sub = ?`, time.Now().Unix()-10, subBob)
	for _, p := range []struct{ method, path string }{
		{"GET", "/api/v1/admin/overview"},
		{"GET", "/api/v1/admin/audit"},
		{"POST", "/api/v1/admin/users/" + subAna + "/erase-vault"},
	} {
		st, _ := adm.status(p.method, p.path, map[string]any{"confirm": "ana@example.com"})
		if st != 401 {
			t.Fatalf("%s %s with an expired token = %d, want 401", p.method, p.path, st)
		}
	}
	var n int
	e.st.DB.QueryRow(`SELECT COUNT(*) FROM vault_keys WHERE sub = ?`, subAna).Scan(&n)
	if n != 1 {
		t.Fatal("the vault was erased")
	}
}

// Parallel wrong guesses must not all be evaluated against the same "not locked yet" snapshot.
func TestParallelGuessesAreSerialised(t *testing.T) {
	e := newEnv(t)
	c := e.login(subAna, "ana@example.com")
	setupVault(t, c)
	var wg sync.WaitGroup
	var evaluated int32
	start := make(chan struct{})
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			st, _, _ := c.do("POST", "/api/v1/vault/verify", map[string]any{"auth": proof()}, nil)
			if st == 401 {
				atomic.AddInt32(&evaluated, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	// 4 free guesses, the 5th trips the first lockout; one more may slip in between reading and recording nothing else.
	if evaluated > 6 {
		t.Fatalf("%d guesses were evaluated before the lockout took effect", evaluated)
	}
}

// Erasing a vault must not quietly leave other members' spaces unrotated, ownerless or unverifiable.
func TestEraseVaultKeepsSharedSpacesSafe(t *testing.T) {
	e := newEnv(t)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	bob := e.login(subBob, "bob@example.com")
	setupVault(t, bob)
	space := hexID()
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": space, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
	ana.call("POST", "/api/v1/spaces/"+space+"/members", map[string]any{"sub": subBob, "role": "editor", "key_version": 1, "wrap": wrap()}, 200, nil)
	adm := e.login(subCat, "cat@example.com", "admin")
	adm.call("POST", "/api/v1/admin/users/"+subAna+"/erase-vault", map[string]any{"confirm": "ana@example.com"}, 200, nil)

	var nr, owners int
	e.st.DB.QueryRow(`SELECT needs_rotation FROM spaces WHERE id=?`, space).Scan(&nr)
	e.st.DB.QueryRow(`SELECT COUNT(*) FROM space_members WHERE space_id=? AND role='owner'`, space).Scan(&owners)
	if nr != 1 {
		t.Fatal("the space was not flagged for rotation after a member's vault was erased")
	}
	if owners != 1 {
		t.Fatalf("owners = %d, want the remaining member promoted", owners)
	}
	var out struct {
		Spaces []struct {
			Role          string
			WrapByEncPub  string `json:"wrap_by_enc_pub"`
			WrapBySigPub  string `json:"wrap_by_sig_pub"`
			NeedsRotation bool   `json:"needs_rotation"`
			Wrap          struct{ By string }
		}
	}
	bob.call("GET", "/api/v1/sync?since=0", nil, 200, &out)
	if len(out.Spaces) != 1 {
		t.Fatalf("spaces = %d", len(out.Spaces))
	}
	sp := out.Spaces[0]
	if sp.WrapByEncPub == "" || sp.WrapBySigPub == "" {
		t.Fatal("the departed sharer's public keys were not retained, so Bob cannot verify his wrap")
	}
	if sp.Wrap.By == subAna || sp.Role != "owner" || !sp.NeedsRotation {
		t.Fatalf("unexpected space state: %+v", sp)
	}
	bob.call("POST", "/api/v1/spaces/"+space+"/rotate", map[string]any{"key_version": 2, "name_blob": envelope(), "items": []any{}, "members": []any{map[string]any{"sub": subBob, "wrap": wrap()}}}, 200, nil)
}

// A flood of bogus callbacks must not grow the audit log without bound.
func TestCallbackFloodIsLimited(t *testing.T) {
	e := newEnv(t)
	anon := e.newClient()
	for i := 0; i < 300; i++ {
		anon.do("GET", "/auth/callback?code=x&state=y", nil, nil)
	}
	var n int
	e.st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event='login_failed'`).Scan(&n)
	if n > 5 {
		t.Fatalf("%d audit rows from 300 anonymous requests", n)
	}
}

// Incremental syncs carry only changed items; the client re-syncs in full when it sees a new space (see sync() in the
// clients). The server contract: a full sync returns the pre-existing items of a newly joined space.
func TestFullSyncReturnsItemsOfNewlyJoinedSpace(t *testing.T) {
	e := newEnv(t)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	bob := e.login(subBob, "bob@example.com")
	setupVault(t, bob)
	space := hexID()
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": space, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
	ana.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": space, "base_seq": 0, "key_version": 1, "blob": envelope()}, 200, nil)
	var first syncSpaces
	bob.call("GET", "/api/v1/sync?since=0", nil, 200, &first)
	ana.call("POST", "/api/v1/spaces/"+space+"/members", map[string]any{"sub": subBob, "role": "editor", "key_version": 1, "wrap": wrap()}, 200, nil)
	var inc, full syncSpaces
	bob.call("GET", "/api/v1/sync?since="+strconv.FormatInt(first.Seq, 10), nil, 200, &inc)
	bob.call("GET", "/api/v1/sync?since=0", nil, 200, &full)
	if len(inc.Spaces) != 1 {
		t.Fatalf("the incremental sync must list the new space (the client keys its re-sync on that), got %d", len(inc.Spaces))
	}
	if len(full.Items) != 1 {
		t.Fatalf("full sync items = %d, want 1", len(full.Items))
	}
}

// /login?msg= is a link anyone can craft: only our own messages are shown.
func TestLoginPageShowsOnlyKnownMessages(t *testing.T) {
	e := newEnv(t)
	anon := e.newClient()
	_, body, _ := anon.do("GET", "/login?msg=Call+0800+EVIL+to+verify+your+account", nil, nil)
	if strings.Contains(string(body), "EVIL") {
		t.Fatal("arbitrary text was rendered on the sign-in page")
	}
	_, body, _ = anon.do("GET", "/login?msg=Your+session+ended.+Sign+in+again.", nil, nil)
	if !strings.Contains(string(body), "Your session ended") {
		t.Fatal("our own message was not shown")
	}
}

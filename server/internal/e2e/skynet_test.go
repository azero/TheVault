package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/azero/thevault/server/internal/app"
	"github.com/azero/thevault/server/internal/config"
	"github.com/azero/thevault/server/internal/store"
)

func withSky(f *fakeSky, extra map[string]string) opt {
	return func(m map[string]string, e *env) {
		m["VAULT_SKYNET_URL"] = f.srv.URL
		m["VAULT_SKYNET_ENROLL_TOKEN"] = "skyenr_ok"
		m["VAULT_SKYNET_HOST"] = "vault-test"
		for k, v := range extra {
			m[k] = v
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestSkyNetEventsAreShippedWithoutSecrets(t *testing.T) {
	sky := newFakeSky(t)
	e := newEnv(t, withSky(sky, nil))
	if sky.Enrolled != 1 {
		t.Fatalf("enrolled %d times", sky.Enrolled)
	}
	c := e.login(subAna, "ana@example.com")
	c.ip = "203.0.113.7"
	m := setupVault(t, c)
	c.call("POST", "/api/v1/vault/lock", struct{}{}, 200, nil)
	badProof := proof()
	c.status("POST", "/api/v1/vault/unlock", map[string]any{"auth": badProof})
	c.call("POST", "/api/v1/vault/unlock", map[string]any{"auth": m.Auth}, 200, nil)
	c.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": envelope()}, 200, nil)

	waitFor(t, "unlock_failed and heartbeat", func() bool {
		return len(sky.events("unlock_failed")) == 1 && len(sky.events("heartbeat")) >= 1 && len(sky.events("item_created")) == 1
	})
	f := sky.events("unlock_failed")[0]
	if f["source"] != "thevault" || f["category"] != "authentication" || f["outcome"] != "failure" || f["host"] != "vault-test" || f["user"] != "ana@example.com" {
		t.Fatalf("event shape: %v", f)
	}
	if f["src_ip"] != "203.0.113.7" {
		t.Fatalf("src_ip should come from the trusted header: %v", f["src_ip"])
	}
	if ev := sky.events("item_created")[0]; ev["category"] != "vault" {
		t.Fatalf("item event: %v", ev)
	}
	// nothing secret ever leaves: not the proofs, not blobs, not wrapped keys
	sky.mu.Lock()
	defer sky.mu.Unlock()
	all, _ := json.Marshal(sky.Events)
	for _, secret := range []string{m.Auth, badProof, m.RecoveryProof, "wrapped_uk", "blob", "enc_priv", "\"password\""} {
		if strings.Contains(string(all), secret) {
			t.Fatalf("SkyNet events contain %q", secret)
		}
	}
}

func TestSkyNetOutboxSurvivesAnOutage(t *testing.T) {
	sky := newFakeSky(t)
	sky.Status = 503
	e := newEnv(t, withSky(sky, nil))
	c := e.login(subAna, "ana@example.com")
	setupVault(t, c)
	waitFor(t, "events in the outbox", func() bool { return e.st.OutboxCount(e.ctx) >= 2 })
	if len(sky.events("login")) != 0 {
		t.Fatal("nothing should have been accepted yet")
	}
	sky.mu.Lock()
	sky.Status = 0
	sky.mu.Unlock()
	// the sender backs off after a failure (1 s first), so allow for that
	waitFor(t, "backlog delivery", func() bool { return len(sky.events("login")) == 1 && len(sky.events("vault_created")) == 1 })
	waitFor(t, "outbox drained", func() bool { return e.st.OutboxCount(e.ctx) == 0 })
}

func TestSkyNetKeyedWithoutEnrollmentCannotRunCommands(t *testing.T) {
	sky := newFakeSky(t)
	e := newEnv(t, func(m map[string]string, e *env) {
		m["VAULT_SKYNET_URL"] = sky.srv.URL
		m["VAULT_SKYNET_KEY"] = sky.apiKey
	})
	st := e.app.Sky.Status(e.ctx).(map[string]any)
	if st["commands_enabled"] != false {
		t.Fatalf("without a pinned command key, commands must be off: %v", st)
	}
}

func TestSkyNetBadEnrollmentTokenFailsStartup(t *testing.T) {
	sky := newFakeSky(t)
	sso := newFakeSSO(t)
	m := map[string]string{"VAULT_DATA_DIR": t.TempDir(), "VAULT_PUBLIC_URL": "http://localhost:1", "VAULT_OIDC_ISSUER": sso.srv.URL, "VAULT_OIDC_CLIENT_ID": "app_test",
		"VAULT_OIDC_CLIENT_SECRET": "x", "VAULT_SKYNET_URL": sky.srv.URL, "VAULT_SKYNET_ENROLL_TOKEN": "nope"}
	cfg, err := config.Load(func(k string) string { return m[k] })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := app.New(cfg, st, "test"); err == nil || !strings.Contains(err.Error(), "enroll") {
		t.Fatalf("a refused enrollment must stop the server from starting silently unmonitored: %v", err)
	}
}

func TestSkyNetBlockIPCommands(t *testing.T) {
	sky := newFakeSky(t)
	e := newEnv(t, withSky(sky, map[string]string{"VAULT_RESPONSE_ALLOWLIST": "198.51.100.0/24"}))
	c := e.login(subAna, "ana@example.com")
	setupVault(t, c)
	now := time.Now().Unix()
	attacker := "203.0.113.50"
	req := func(ip string) int {
		cl := e.newClient()
		cl.ip = ip
		st, _, _ := cl.do("GET", "/login", nil, nil)
		return st
	}
	if req(attacker) != 200 {
		t.Fatal("precondition")
	}
	result := func(id int64) [2]string {
		var r [2]string
		waitFor(t, "result for command", func() bool {
			sky.mu.Lock()
			defer sky.mu.Unlock()
			var ok bool
			r, ok = sky.Results[id]
			return ok
		})
		return r
	}

	// a dry run only reports
	sky.command(1, sky.agentID, "block_ip", map[string]any{"ip": attacker, "ttl_seconds": 600}, true, now, now+300)
	if r := result(1); r[0] != "skipped" || !strings.Contains(r[1], "dry-run") {
		t.Fatalf("dry run: %v", r)
	}
	if req(attacker) != 200 {
		t.Fatal("a dry run must not block")
	}

	// live: blocked at once, everyone else unaffected, health check exempt
	sky.command(2, sky.agentID, "block_ip", map[string]any{"ip": attacker, "ttl_seconds": 600}, false, now, now+300)
	if r := result(2); r[0] != "succeeded" {
		t.Fatalf("block: %v", r)
	}
	if req(attacker) != 403 {
		t.Fatal("the address should be denied")
	}
	if req("203.0.113.51") != 200 {
		t.Fatal("other addresses must not be affected")
	}
	cl := e.newClient()
	cl.ip = attacker
	if st, _, _ := cl.do("GET", "/healthz", nil, nil); st != 200 {
		t.Fatal("/healthz stays reachable")
	}
	if st, _, _ := cl.do("GET", "/api/v1/session", nil, nil); st != 403 {
		t.Fatal("API is denied too")
	}
	waitFor(t, "blocked_request event", func() bool { return len(sky.events("blocked_request")) >= 1 })
	// and it is visible to admins
	adm := e.login(subBob, "bob@example.com", "admin")
	var ov struct {
		Skynet struct{ Deny []struct{ IP string } }
	}
	adm.call("GET", "/api/v1/admin/overview", nil, 200, &ov)
	if len(ov.Skynet.Deny) != 1 || ov.Skynet.Deny[0].IP != attacker {
		t.Fatalf("admin overview deny list: %+v", ov)
	}

	// replay of the same signed command is refused and does not extend anything
	sky.command(2, sky.agentID, "block_ip", map[string]any{"ip": "203.0.113.99", "ttl_seconds": 600}, false, now, now+300)
	waitFor(t, "replay report", func() bool {
		sky.mu.Lock()
		defer sky.mu.Unlock()
		return strings.Contains(sky.Results[2][1], "replay")
	})
	if req("203.0.113.99") != 200 {
		t.Fatal("a replayed command must not be executed")
	}

	// never-block rules
	for i, ip := range []string{"127.0.0.1", "::1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "198.51.100.77", "not-an-ip", "::ffff:127.0.0.1"} {
		id := int64(100 + i)
		sky.command(id, sky.agentID, "block_ip", map[string]any{"ip": ip, "ttl_seconds": 600}, false, now, now+300)
		if r := result(id); r[0] != "skipped" || !strings.Contains(r[1], "refused") {
			t.Fatalf("%s must be refused: %v", ip, r)
		}
	}
	// the SkyNet server itself
	sky.command(120, sky.agentID, "block_ip", map[string]any{"ip": "127.0.0.1"}, false, now, now+300)
	_ = result(120)

	// other agents' commands, expired, over-long, wrong actions
	sky.command(130, "agt_other", "block_ip", map[string]any{"ip": "203.0.113.60"}, false, now, now+300)
	sky.command(131, sky.agentID, "block_ip", map[string]any{"ip": "203.0.113.61"}, false, now-1000, now-10)
	sky.command(132, sky.agentID, "block_ip", map[string]any{"ip": "203.0.113.62"}, false, now, now+3600)
	sky.command(133, sky.agentID, "isolate", map[string]any{}, false, now, now+300)
	sky.command(134, sky.agentID, "kill_process", map[string]any{"pid": 1234}, false, now, now+300)
	for _, id := range []int64{130, 131, 132, 133, 134} {
		if r := result(id); r[0] != "skipped" {
			t.Fatalf("command %d should have been refused: %v", id, r)
		}
	}
	for _, ip := range []string{"203.0.113.60", "203.0.113.61", "203.0.113.62"} {
		if req(ip) != 200 {
			t.Fatalf("%s was blocked by a command that should have been refused", ip)
		}
	}

	// a forged signature is dropped silently (never reported, never executed)
	sky.mu.Lock()
	sky.pending = append(sky.pending, map[string]string{"payload": "eyJ2IjoxLCJpZCI6OTk5fQ==", "sig": strings.Repeat("A", 86) + "=="})
	sky.mu.Unlock()
	time.Sleep(600 * time.Millisecond)
	sky.mu.Lock()
	if _, ok := sky.Results[999]; ok {
		t.Fatal("a command with a bad signature must not be reported or executed")
	}
	sky.mu.Unlock()

	// unblock
	sky.command(200, sky.agentID, "unblock_ip", map[string]any{"ip": attacker}, false, now, now+300)
	if r := result(200); r[0] != "succeeded" {
		t.Fatalf("unblock: %v", r)
	}
	if req(attacker) != 200 {
		t.Fatal("unblocked address should work again")
	}
	waitFor(t, "response_applied events", func() bool { return len(sky.events("response_applied")) >= 2 })
}

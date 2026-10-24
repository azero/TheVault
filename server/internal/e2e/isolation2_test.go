package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Second isolation round: the automation API, OmniCore and Beacon surfaces.

// The automation API promises no per-person item or space counts and no KDF parameters. The audit log it serves must
// not bring them back in through the details of the events that carry them (the administration screen shows them).
func TestAutomationAuditHidesItemCountsAndKDFParameters(t *testing.T) {
	e := newEnv(t, withAPI(nil))
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana) // vault_created (iterations=...)
	for i := 0; i < 3; i++ {
		ana.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": envelope()}, 200, nil)
	}
	ana.call("GET", "/api/v1/sync?since=0", nil, 200, nil) // sync_full (items=N)
	ana.call("POST", "/api/v1/items/import", map[string]any{"key_version": 1, "items": []map[string]any{{"id": hexID(), "blob": envelope()}, {"id": hexID(), "blob": envelope()}}}, 200, nil)
	ana.call("POST", "/api/v1/audit/client", map[string]any{"event": "vault_export", "count": 777}, 200, nil)
	space := hexID()
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": space, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
	ana.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": space, "base_seq": 0, "key_version": 1, "blob": envelope()}, 200, nil)
	ana.call("DELETE", "/api/v1/spaces/"+space, nil, 200, nil) // space_deleted (items=N)
	e.login(subBob, "bob@example.com", "admin")

	// the stored rows do carry the numbers (this is what the administration screen shows) ...
	stored := map[string]string{}
	for _, r := range auditRows(e) {
		stored[r.Event] = r.Details
	}
	for ev, key := range map[string]string{"vault_created": "iterations=", "sync_full": "items=", "items_imported": "count=", "vault_export": "count=", "space_deleted": "items="} {
		if !strings.Contains(stored[ev], key) {
			t.Fatalf("test premise: %s should store %q, has %q", ev, key, stored[ev])
		}
	}

	// ... and the API leaves them out, for a service key and for an administrator's user key, while the rest stays.
	for who, tok := range map[string]string{"service key": e.svcKey("audit", "audit:read"), "admin user key": e.userKey("bobs", subBob, "bob@example.com", "audit:read", "admin")} {
		var out struct {
			Events []struct{ Event, Details string }
		}
		_, _, _, raw := e.api(tok).do("GET", "/api/v1/audit?limit=200", nil, nil)
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, ev := range out.Events {
			seen[ev.Event] = true
			for _, bad := range []string{"iterations=", "items=", "count=", "version="} {
				if strings.Contains(ev.Details, bad) {
					t.Errorf("%s: %s row exposes %q: %q", who, ev.Event, bad, ev.Details)
				}
			}
			if ev.Event == "sync_full" && ev.Details != "kind=web" {
				t.Errorf("%s: sync_full should keep its kind: %q", who, ev.Details)
			}
		}
		for _, ev := range []string{"vault_created", "sync_full", "items_imported", "vault_export", "space_deleted"} {
			if !seen[ev] {
				t.Errorf("%s: %s is missing from the audit log", who, ev)
			}
		}
	}
}

// Error text from the SkyNet client names the address it failed to reach; the API passes on a reason only.
func TestAutomationStatusDoesNotRevealTheSkyNetAddress(t *testing.T) {
	sky := newFakeSky(t)
	e := newEnv(t, withAPI(nil), withSky(sky, nil))
	a := e.api(e.svcKey("robot", "status:read"))
	waitFor(t, "enrolled", func() bool { return sky.Enrolled > 0 })
	sky.srv.Listener.Close() // new connections are now refused
	sky.srv.CloseClientConnections()
	e.login(subAna, "ana@example.com") // produces an event to ship
	var raw []byte
	waitFor(t, "degraded", func() bool {
		_, _, _, raw = a.do("GET", "/api/v1/status", nil, nil)
		var s struct{ Skynet map[string]any }
		json.Unmarshal(raw, &s)
		le, _ := s.Skynet["last_error"].(string)
		return le != ""
	})
	for _, bad := range []string{"127.0.0.1", "http://", "https://", "dial tcp", sky.srv.URL} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("status reveals %q: %s", bad, raw)
		}
	}
	if !strings.Contains(string(raw), `"last_error":"unreachable"`) {
		t.Errorf("expected the coarse reason: %s", raw)
	}
}

// Anyone with a space can add anyone who has a vault, and each addition would otherwise message that person through
// Beacon. One sender reaches a person at most twice an hour and all senders together five times; the additions
// themselves still happen.
func TestSpaceInvitationMessagesCannotBeUsedToSpamSomeone(t *testing.T) {
	bc := newFakeBeacon(t)
	e := newEnv(t, withBeacon(bc))
	cat := e.login(subCat, "cat@example.com")
	setupVault(t, cat)
	dan := "dddddddddddddddddddddddddddddddd"
	dc := e.login(dan, "dan@example.com")
	setupVault(t, dc)

	spaces := []string{}
	for i := 0; i < 6; i++ {
		id := hexID()
		spaces = append(spaces, id)
		dc.call("POST", "/api/v1/spaces", map[string]any{"id": id, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
		dc.call("POST", "/api/v1/spaces/"+id+"/members", map[string]any{"sub": subCat, "role": "viewer", "key_version": 1, "wrap": wrap()}, 200, nil)
	}
	waitFor(t, "first invitations", func() bool { return len(bc.messages("space_invitation")) >= 2 })
	time.Sleep(300 * time.Millisecond)
	if n := len(bc.messages("space_invitation")); n != 2 {
		t.Fatalf("one sender reached cat %d times in an hour, want 2", n)
	}

	// other senders are bounded by the per-recipient cap (5 in all)
	for i := 0; i < 5; i++ {
		sub := strings.Repeat(string(rune('e'+i)), 32)
		sc := e.login(sub, string(rune('e'+i))+"@example.com")
		setupVault(t, sc)
		id := hexID()
		sc.call("POST", "/api/v1/spaces", map[string]any{"id": id, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
		sc.call("POST", "/api/v1/spaces/"+id+"/members", map[string]any{"sub": subCat, "role": "viewer", "key_version": 1, "wrap": wrap()}, 200, nil)
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(bc.messages("space_invitation")); n != 5 {
		t.Fatalf("cat received %d invitation messages from several senders, want the cap of 5", n)
	}
	for _, m := range bc.messages("space_invitation") {
		if got := recipients(m); len(got) != 1 || got[0] != "user="+subCat {
			t.Fatalf("recipients %v", got)
		}
	}

	// the additions themselves were not blocked
	var sp struct{ Spaces []struct{ ID string } }
	cat.call("GET", "/api/v1/sync?since=0", nil, 200, &sp)
	have := map[string]bool{}
	for _, s := range sp.Spaces {
		have[s.ID] = true
	}
	for _, id := range spaces {
		if !have[id] {
			t.Errorf("cat is not in space %s although the add succeeded", id)
		}
	}
}

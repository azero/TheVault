package e2e

import (
	"testing"
)

type activityResp struct {
	Events []struct {
		Event, Actor, Target, IP string
	}
}

// ClosedDoor subs are 32 hex characters: the same shape as item and space ids. Whatever the server records as the
// "target" of an action must therefore never be able to land in someone else's activity feed just because a caller
// chose an id that equals that person's sub.
func TestActivityFeedCannotBePollutedByAnotherUser(t *testing.T) {
	e := newEnv(t)
	adm := e.login(subCat, "cat@example.com", "admin")
	setupVault(t, adm)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	mal := e.login(subBob, "bob@example.com")
	setupVault(t, mal)

	// bob picks ana's sub as the id of an item and of a space (both are audited with the id as target)
	mal.call("PUT", "/api/v1/items/"+subAna, map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": envelope()}, 200, nil)
	mal.call("POST", "/api/v1/spaces", map[string]any{"id": subAna, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
	mal.call("DELETE", "/api/v1/items/"+subAna, nil, 200, nil)

	// ana does something of her own, and an administrator acts on her account
	ana.call("PUT", "/api/v1/items/"+hexID(), map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": envelope()}, 200, nil)
	adm.call("POST", "/api/v1/admin/users/"+subAna+"/unlock", struct{}{}, 200, nil)

	var act activityResp
	ana.call("GET", "/api/v1/activity", nil, 200, &act)
	var own, admin bool
	for _, ev := range act.Events {
		if ev.Actor == subBob {
			t.Fatalf("ana's activity feed shows another person's action: %+v", ev)
		}
		switch {
		case ev.Event == "item_created" && ev.Actor == subAna:
			own = true
		case ev.Event == "admin_user_unlocked" && ev.Target == subAna:
			admin = true
			if ev.IP != "" {
				t.Fatalf("the administrator's address must stay hidden: %+v", ev)
			}
		}
	}
	if !own || !admin {
		t.Fatalf("the feed must still show ana's own actions (%v) and what an administrator did to her account (%v): %+v", own, admin, act.Events)
	}

	// bob's own feed holds his actions and nothing of ana's
	var bact activityResp
	mal.call("GET", "/api/v1/activity", nil, 200, &bact)
	for _, ev := range bact.Events {
		if ev.Actor != subBob {
			t.Fatalf("bob sees someone else's event: %+v", ev)
		}
	}
}

// The people lookup is how sharing finds a colleague; it must not be a free enumeration tool.
func TestPublicKeyLookupIsRateLimited(t *testing.T) {
	e := newEnv(t)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	bob := e.login(subBob, "bob@example.com")
	setupVault(t, bob)
	limited := false
	for i := 0; i < 40; i++ {
		st, _ := ana.status("GET", "/api/v1/users/"+subBob+"/keys", nil)
		if st == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("GET /users/{sub}/keys has no rate limit")
	}
	// the limit is per session, not global: bob is unaffected
	bob.call("GET", "/api/v1/users/"+subAna+"/keys", nil, 200, nil)
}

// Everything a person owns or shares is reachable only through their own membership: other people's sessions, items,
// versions and spaces answer "not found", and leaving a space ends access to what is in it.
func TestOtherPeopleCannotReachMyThings(t *testing.T) {
	e := newEnv(t)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	bob := e.login(subBob, "bob@example.com")
	setupVault(t, bob)

	// sessions: bob cannot list or revoke ana's
	var anaSessions, bobSessions struct{ Sessions []struct{ ID string } }
	ana.call("GET", "/api/v1/sessions", nil, 200, &anaSessions)
	bob.call("GET", "/api/v1/sessions", nil, 200, &bobSessions)
	for _, s := range bobSessions.Sessions {
		for _, a := range anaSessions.Sessions {
			if s.ID == a.ID {
				t.Fatal("sessions of two people overlap")
			}
		}
	}
	bob.call("DELETE", "/api/v1/sessions/"+anaSessions.Sessions[0].ID, nil, 404, nil)
	ana.call("GET", "/api/v1/session", nil, 200, nil)

	// a shared space: bob is an editor until he leaves
	space := hexID()
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": space, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
	ana.call("POST", "/api/v1/spaces/"+space+"/members", map[string]any{"sub": subBob, "role": "editor", "key_version": 1, "wrap": wrap()}, 200, nil)
	item := hexID()
	ana.call("PUT", "/api/v1/items/"+item, map[string]any{"vault_id": space, "base_seq": 0, "key_version": 1, "blob": envelope()}, 200, nil)
	bob.call("GET", "/api/v1/items/"+item+"/versions", nil, 200, nil)
	bob.call("DELETE", "/api/v1/spaces/"+space+"/members/"+subBob, nil, 200, nil)

	var s syncSpaces
	bob.call("GET", "/api/v1/sync?since=0", nil, 200, &s)
	if len(s.Spaces) != 0 || len(s.Items) != 0 {
		t.Fatalf("a member who left still receives the space: %+v", s)
	}
	bob.call("GET", "/api/v1/items/"+item+"/versions", nil, 404, nil)
	bob.call("DELETE", "/api/v1/items/"+item, nil, 404, nil)
	bob.call("POST", "/api/v1/items/"+item+"/restore", struct{}{}, 404, nil)
	bob.call("PUT", "/api/v1/items/"+item, map[string]any{"vault_id": space, "base_seq": 1, "key_version": 1, "blob": envelope()}, 404, nil)
	bob.call("PUT", "/api/v1/spaces/"+space, map[string]any{"name_blob": envelope()}, 404, nil)
	bob.call("POST", "/api/v1/spaces/"+space+"/rotate", map[string]any{"key_version": 2, "name_blob": envelope(), "items": []any{}, "members": []any{map[string]any{"sub": subBob, "wrap": wrap()}}}, 404, nil)

	// the same item id cannot be claimed in bob's personal vault to reach ana's data
	bob.call("PUT", "/api/v1/items/"+item, map[string]any{"vault_id": "personal", "base_seq": 0, "key_version": 1, "blob": envelope()}, 404, nil)
}

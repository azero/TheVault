package e2e

import (
	"testing"
)

type syncSpaces struct {
	Seq    int64
	Items  []map[string]any
	Spaces []struct {
		ID             string
		Role           string
		Key_version    int
		Needs_rotation bool
		Members        []struct{ Sub, Role string }
	}
}

func seqOf(it map[string]any) int64 { return int64(it["seq"].(float64)) }

func TestSpacesSharingAndRotation(t *testing.T) {
	e := newEnv(t)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	bob := e.login(subBob, "bob@example.com")
	setupVault(t, bob)
	cat := e.login(subCat, "cat@example.com")
	setupVault(t, cat)

	// directory: needs 2+ characters, finds people with vaults, never yourself
	var dir struct{ Users []struct{ Sub, Email string } }
	ana.call("GET", "/api/v1/directory?q=b", nil, 200, &dir)
	if len(dir.Users) != 0 {
		t.Fatal("one-letter searches must return nothing")
	}
	ana.call("GET", "/api/v1/directory?q=bob", nil, 200, &dir)
	if len(dir.Users) != 1 || dir.Users[0].Sub != subBob {
		t.Fatalf("directory: %+v", dir)
	}
	ana.call("GET", "/api/v1/directory?q=%25%25", nil, 200, &dir) // LIKE wildcards are escaped
	if len(dir.Users) != 0 {
		t.Fatalf("wildcard injection: %+v", dir)
	}
	ana.call("GET", "/api/v1/users/"+subBob+"/keys", nil, 200, nil)
	ana.call("GET", "/api/v1/users/nobody/keys", nil, 404, nil)

	space := hexID()
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": space, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": space, "name_blob": envelope(), "wrap": wrap()}, 409, nil)
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": hexID(), "name_blob": "plain", "wrap": wrap()}, 400, nil)

	// nobody else can see it, write to it, or manage it
	var bs syncSpaces
	bob.call("GET", "/api/v1/sync?since=0", nil, 200, &bs)
	if len(bs.Spaces) != 0 {
		t.Fatal("bob sees a space he is not in")
	}
	bob.call("POST", "/api/v1/spaces/"+space+"/members", map[string]any{"sub": subCat, "role": "viewer", "key_version": 1, "wrap": wrap()}, 404, nil)
	bob.call("DELETE", "/api/v1/spaces/"+space, nil, 404, nil)

	// ana adds bob as editor and cat as viewer
	member := func(c *client, sub, role string, kv, want int) {
		c.call("POST", "/api/v1/spaces/"+space+"/members", map[string]any{"sub": sub, "role": role, "key_version": kv, "wrap": wrap()}, want, nil)
	}
	member(ana, subBob, "editor", 1, 200)
	member(ana, subBob, "editor", 1, 409)
	member(ana, subCat, "viewer", 1, 200)
	member(ana, "ghost", "viewer", 1, 404)
	member(ana, subCat, "viewer", 9, 400)
	member(ana, subAna, "viewer", 1, 400) // cannot add yourself

	// items in the space: owner and editor write, viewer reads only
	put := func(c *client, id string, base int64, want int) {
		c.call("PUT", "/api/v1/items/"+id, map[string]any{"vault_id": space, "base_seq": base, "key_version": 1, "blob": envelope()}, want, nil)
	}
	item := hexID()
	put(ana, item, 0, 200)
	put(cat, hexID(), 0, 403)
	var cs syncSpaces
	cat.call("GET", "/api/v1/sync?since=0", nil, 200, &cs)
	if len(cs.Items) != 1 || len(cs.Spaces) != 1 || cs.Spaces[0].Role != "viewer" || len(cs.Spaces[0].Members) != 3 {
		t.Fatalf("viewer sync: %+v", cs)
	}
	put(cat, item, seqOf(cs.Items[0]), 403)
	cat.call("DELETE", "/api/v1/items/"+item, nil, 403, nil)
	var bsync syncSpaces
	bob.call("GET", "/api/v1/sync?since=0", nil, 200, &bsync)
	put(bob, item, seqOf(bsync.Items[0]), 200) // an editor may edit

	// a viewer cannot manage the space
	cat.call("PUT", "/api/v1/spaces/"+space+"/members/"+subBob, map[string]any{"role": "owner"}, 403, nil)
	cat.call("POST", "/api/v1/spaces/"+space+"/rotate", map[string]any{}, 400, nil)
	bob.call("DELETE", "/api/v1/spaces/"+space+"/members/"+subCat, nil, 403, nil)

	// the last owner cannot leave or be demoted
	ana.call("DELETE", "/api/v1/spaces/"+space+"/members/"+subAna, nil, 409, nil)
	ana.call("PUT", "/api/v1/spaces/"+space+"/members/"+subAna, map[string]any{"role": "editor"}, 409, nil)

	// removing cat flags the space for rotation and blocks adding anyone until it is rotated
	ana.call("DELETE", "/api/v1/spaces/"+space+"/members/"+subCat, nil, 200, nil)
	var as syncSpaces
	ana.call("GET", "/api/v1/sync?since=0", nil, 200, &as)
	if !as.Spaces[0].Needs_rotation || len(as.Spaces[0].Members) != 2 {
		t.Fatalf("expected a rotation flag: %+v", as.Spaces[0])
	}
	member(ana, subCat, "viewer", 1, 400)
	cat.call("GET", "/api/v1/sync?since=0", nil, 200, &cs)
	if len(cs.Spaces) != 0 {
		t.Fatal("removed member still sees the space")
	}
	if st, _ := cat.status("PUT", "/api/v1/items/"+item, map[string]any{"vault_id": space, "base_seq": 1, "key_version": 1, "blob": envelope()}); st != 404 {
		t.Fatalf("removed member can still write: %d", st)
	}

	// rotation must cover every live item and every member, at the sequence the owner saw
	seq := seqOf(as.Items[0])
	var cur syncSpaces
	ana.call("GET", "/api/v1/sync?since=0", nil, 200, &cur)
	seq = seqOf(cur.Items[0])
	rot := func(items []map[string]any, members []map[string]any, version int, want int) {
		ana.call("POST", "/api/v1/spaces/"+space+"/rotate", map[string]any{"key_version": version, "name_blob": envelope(), "items": items, "members": members}, want, nil)
	}
	goodItems := []map[string]any{{"id": item, "base_seq": seq, "blob": envelope()}}
	goodMembers := []map[string]any{{"sub": subAna, "wrap": wrap()}, {"sub": subBob, "wrap": wrap()}}
	rot(nil, goodMembers, 2, 400)                                                                     // forgot an item
	rot(goodItems, goodMembers[:1], 2, 400)                                                           // forgot a member
	rot(goodItems, append(goodMembers, map[string]any{"sub": subCat, "wrap": wrap()}), 2, 400)        // wrapped for a removed member
	rot([]map[string]any{{"id": item, "base_seq": seq + 3, "blob": envelope()}}, goodMembers, 2, 409) // stale
	rot(goodItems, goodMembers, 5, 400)                                                               // must be exactly the next version
	rot(goodItems, goodMembers, 2, 200)

	ana.call("GET", "/api/v1/sync?since=0", nil, 200, &cur)
	if cur.Spaces[0].Key_version != 2 || cur.Spaces[0].Needs_rotation || len(cur.Items) != 1 {
		t.Fatalf("after rotation: %+v", cur)
	}
	// writes now need the new key version
	ana.call("PUT", "/api/v1/items/"+item, map[string]any{"vault_id": space, "base_seq": seqOf(cur.Items[0]), "key_version": 1, "blob": envelope()}, 400, nil)
	ana.call("PUT", "/api/v1/items/"+item, map[string]any{"vault_id": space, "base_seq": seqOf(cur.Items[0]), "key_version": 2, "blob": envelope()}, 200, nil)
	// old versions are undecryptable after rotation and are not kept
	var vers struct{ Versions []any }
	ana.call("GET", "/api/v1/items/"+item+"/versions", nil, 200, &vers)
	if len(vers.Versions) != 1 { // only the version created by the write just above
		t.Fatalf("versions after rotation: %d", len(vers.Versions))
	}
	member(ana, subCat, "viewer", 2, 200) // adding works again, at the new version

	// only owners delete spaces; deleting leaves tombstones so members' devices drop the items
	bob.call("DELETE", "/api/v1/spaces/"+space, nil, 403, nil)
	ana.call("DELETE", "/api/v1/spaces/"+space, nil, 200, nil)
	bob.call("GET", "/api/v1/sync?since=0", nil, 200, &bsync)
	if len(bsync.Spaces) != 0 {
		t.Fatal("deleted space still listed")
	}
	for _, it := range bsync.Items {
		if it["blob"] != nil && it["blob"] != "" {
			t.Fatal("deleted space left ciphertext behind")
		}
	}
	names := auditNames(e)
	for _, want := range []string{"space_created", "space_member_added", "space_member_removed", "space_key_rotated", "space_deleted"} {
		if !names[want] {
			t.Errorf("missing audit event %s", want)
		}
	}
}

func TestMemberCanLeave(t *testing.T) {
	e := newEnv(t)
	ana := e.login(subAna, "ana@example.com")
	setupVault(t, ana)
	bob := e.login(subBob, "bob@example.com")
	setupVault(t, bob)
	space := hexID()
	ana.call("POST", "/api/v1/spaces", map[string]any{"id": space, "name_blob": envelope(), "wrap": wrap()}, 200, nil)
	ana.call("POST", "/api/v1/spaces/"+space+"/members", map[string]any{"sub": subBob, "role": "editor", "key_version": 1, "wrap": wrap()}, 200, nil)
	bob.call("DELETE", "/api/v1/spaces/"+space+"/members/"+subBob, nil, 200, nil)
	if !auditNames(e)["space_left"] {
		t.Error("leaving must be audited as space_left")
	}
}

package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestUserSummariesPageBySubAndCarryNoContentCounts(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	for _, s := range []string{"c", "a", "b", "d"} {
		if err := st.UpsertUser(ctx, User{Sub: s, Email: s + "@example.com", Name: s, Role: "member"}); err != nil {
			t.Fatal(err)
		}
	}
	st.SetUserLocked(ctx, "b", true)
	page, err := st.UserSummaries(ctx, "", 2, nil)
	if err != nil || len(page) != 2 || page[0].Sub != "a" || page[1].Sub != "b" || !page[1].Locked {
		t.Fatalf("%v %+v", err, page)
	}
	page, _ = st.UserSummaries(ctx, "b", 10, nil)
	if len(page) != 2 || page[0].Sub != "c" || page[1].Sub != "d" {
		t.Fatalf("%+v", page)
	}
	yes := true
	if l, _ := st.UserSummaries(ctx, "", 10, &yes); len(l) != 1 || l[0].Sub != "b" {
		t.Fatalf("%+v", l)
	}
	if u, err := st.UserSummaryBySub(ctx, "a"); err != nil || u.Email != "a@example.com" || u.HasVault {
		t.Fatalf("%v %+v", err, u)
	}
	if _, err := st.UserSummaryBySub(ctx, "zzz"); err != ErrNotFound {
		t.Fatalf("%v", err)
	}
}

func TestOtherActiveAdmins(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	st.UpsertUser(ctx, User{Sub: "a1", Role: "admin"})
	st.UpsertUser(ctx, User{Sub: "a2", Role: "admin"})
	st.UpsertUser(ctx, User{Sub: "m1", Role: "member"})
	if n, _ := st.OtherActiveAdmins(ctx, "a1"); n != 1 {
		t.Fatalf("%d", n)
	}
	st.SetUserLocked(ctx, "a2", true)
	if n, _ := st.OtherActiveAdmins(ctx, "a1"); n != 0 {
		t.Fatalf("a locked administrator does not count: %d", n)
	}
}

func TestAuditPageFiltersAndKeyset(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		st.InsertAudit(ctx, AuditRow{Event: "unlock_failed", Actor: "u1"})
	}
	st.InsertAudit(ctx, AuditRow{Event: "login", Actor: "u2", Target: "u1"})
	all, _ := st.AuditPage(ctx, AuditFilter{Limit: 100})
	if len(all) != 6 || all[0].Event != "login" {
		t.Fatalf("%+v", all)
	}
	if rows, _ := st.AuditPage(ctx, AuditFilter{Event: "unlock_failed", Limit: 2}); len(rows) != 2 {
		t.Fatalf("%+v", rows)
	}
	if rows, _ := st.AuditPage(ctx, AuditFilter{Actor: "u1"}); len(rows) != 6 { // actor or target, like the admin screen
		t.Fatalf("%d", len(rows))
	}
	older, _ := st.AuditPage(ctx, AuditFilter{BeforeID: all[2].ID, Limit: 100})
	if len(older) != 3 || older[0].ID >= all[2].ID {
		t.Fatalf("%+v", older)
	}
	if rows, _ := st.AuditPage(ctx, AuditFilter{Since: 1 << 40}); len(rows) != 0 {
		t.Fatalf("%+v", rows)
	}
}

func TestSchemaVersionsAndBackups(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	cur, latest, err := st.SchemaVersions(ctx)
	if err != nil || cur != latest || cur < 2 {
		t.Fatalf("%d %d %v", cur, latest, err)
	}
	if b, err := st.ListBackups(); err != nil || len(b) != 0 {
		t.Fatalf("%v %v", b, err)
	}
	p, err := st.Backup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(st.Dir(), "backups", "notes.txt"), []byte("x"), 0o600) // not a snapshot
	b, err := st.ListBackups()
	if err != nil || len(b) != 1 || b[0].Name != filepath.Base(p) || b[0].Bytes <= 0 || b[0].Modified == 0 {
		t.Fatalf("%v %+v", err, b)
	}
}

package store

import (
	"context"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestLockoutSchedule(t *testing.T) {
	want := map[int]time.Duration{1: 0, 4: 0, 5: 30 * time.Second, 6: time.Minute, 7: 2 * time.Minute, 9: 8 * time.Minute, 10: 15 * time.Minute, 50: 15 * time.Minute}
	for n, d := range want {
		if got := lockoutFor(n); got != d {
			t.Errorf("lockoutFor(%d) = %v, want %v", n, got, d)
		}
	}
}

func TestMigrationsAreIdempotentAndNewerSchemaRefused(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.DB.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (999, 0)`)
	st.Close()
	if _, err := Open(dir); err == nil {
		t.Fatal("an older build must refuse to open a database from a newer schema")
	}
}

func TestSessionLifecycle(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	tok, _, err := st.CreateSession(ctx, NewSession{Sub: "u", Kind: "web", Role: "member", Idle: time.Minute, Absolute: time.Hour, TokenExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	st.DB.QueryRow(`SELECT id_hash FROM sessions`).Scan(&stored)
	if stored == tok || stored != Hash(tok) {
		t.Fatal("only the hash of a session token may be stored")
	}
	if _, err := st.GetSession(ctx, tok, time.Minute, time.Hour); err != nil {
		t.Fatal(err)
	}
	st.DB.Exec(`UPDATE sessions SET last_seen = ?`, time.Now().Add(-2*time.Minute).Unix())
	if _, err := st.GetSession(ctx, tok, time.Minute, time.Hour); err == nil {
		t.Fatal("idle web session must expire")
	}
	if _, err := st.GetSession(ctx, "", time.Minute, time.Hour); err == nil {
		t.Fatal("empty token")
	}
}

func TestEraseKeepsOtherUsersData(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	for _, sub := range []string{"a", "b"} {
		st.UpsertUser(ctx, User{Sub: sub, Role: "member"})
		if err := st.CreateVaultKeys(ctx, VaultKeys{Sub: sub, KDF: "k", KDFIter: 1, KDFSalt: "s", AuthHash: "h", WrappedUK: "w", EncPub: "e", SigPub: "s", EncPriv: "p", SigPriv: "p", RecoveryHash: "r", RecoveryWrappedUK: "w"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.PutItem(ctx, PutItem{Sub: sub, ID: sub + "item", VaultID: PersonalVault, Blob: "x", KeyVersion: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.EraseVault(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM items`).Scan(&n)
	if n != 1 {
		t.Fatalf("items left: %d", n)
	}
	if _, err := st.GetVaultKeys(ctx, "b"); err != nil {
		t.Fatal("b's keys must survive")
	}
}

func TestOutboxIsBounded(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		st.OutboxPush(ctx, "x", 10)
	}
	if n := st.OutboxCount(ctx); n != 10 {
		t.Fatalf("outbox holds %d, want 10", n)
	}
}

func TestExtCodeIsSingleUse(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	code, _ := st.CreateExtCode(ctx, ExtCode{Sub: "u", Role: "member", Challenge: "c", Redirect: "r"})
	if _, err := st.ConsumeExtCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConsumeExtCode(ctx, code); err == nil {
		t.Fatal("a code must work once")
	}
	code, _ = st.CreateExtCode(ctx, ExtCode{Sub: "u", Role: "member"})
	st.DB.Exec(`UPDATE ext_codes SET expires_at = 1`)
	if _, err := st.ConsumeExtCode(ctx, code); err == nil {
		t.Fatal("an expired code must not work")
	}
}

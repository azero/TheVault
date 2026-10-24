package store

import (
	"context"
	"testing"
	"time"
)

func TestOmniCoreReadModels(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	now := time.Now()
	if _, err := st.VaultMeta(ctx, "nobody"); err != ErrNotFound {
		t.Fatalf("no vault: %v", err)
	}
	for _, sub := range []string{"aaa", "bbb"} {
		if err := st.UpsertUser(ctx, User{Sub: sub, Email: sub + "@example.com", Role: "member"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.DB.ExecContext(ctx, `INSERT INTO vault_keys(sub,kdf,kdf_iter,kdf_salt,auth_hash,wrapped_uk,enc_pub,sig_pub,enc_priv,sig_priv,recovery_hash,recovery_wrapped_uk,created_at,updated_at,failed_unlocks,last_unlock)
		VALUES ('aaa','k',1,'s','h','w','e','s','e','s','r','w',100,200,2,300)`); err != nil {
		t.Fatal(err)
	}
	m, err := st.VaultMeta(ctx, "aaa")
	if err != nil || !m.RecoveryConfigured || m.CreatedAt != 100 || m.LastUnlock != 300 || m.FailedUnlocks != 2 {
		t.Fatalf("%+v %v", m, err)
	}
	st.DB.ExecContext(ctx, `UPDATE vault_keys SET recovery_hash='' WHERE sub='aaa'`)
	if m, _ := st.VaultMeta(ctx, "aaa"); m.RecoveryConfigured {
		t.Fatal("an empty recovery hash is not a configured recovery key")
	}

	// spaces: counts, owners that need to rotate
	for _, q := range []string{
		`INSERT INTO spaces(id,name_blob,created_by,created_at,needs_rotation) VALUES ('s1','x','aaa',1,1),('s2','x','bbb',1,0)`,
		`INSERT INTO space_members(space_id,sub,role,key_version,wrap_eph,wrap_ct,wrap_sig,wrapped_by,added_at) VALUES
		 ('s1','aaa','owner',1,'','','','aaa',1),('s1','bbb','editor',1,'','','','aaa',1),('s2','bbb','owner',1,'','','','bbb',1),('s2','aaa','viewer',1,'','','','bbb',1)`} {
		if _, err := st.DB.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	c, err := st.SpaceCountsFor(ctx, "aaa")
	if err != nil || c != (SpaceCounts{Member: 2, Owned: 1, NeedRotation: 1}) {
		t.Fatalf("%+v %v", c, err)
	}
	if c, _ := st.SpaceCountsFor(ctx, "bbb"); c != (SpaceCounts{Member: 2, Owned: 1, NeedRotation: 0}) {
		t.Fatalf("an editor's flagged space does not count for them: %+v", c)
	}
	if o, _ := st.SpaceOwnersNeedingRotation(ctx, "s1", "bbb"); len(o) != 1 || o[0] != "aaa" {
		t.Fatalf("owners %v", o)
	}
	if o, _ := st.SpaceOwnersNeedingRotation(ctx, "s1", "aaa"); len(o) != 0 {
		t.Fatalf("the person who left is not told: %v", o)
	}
	if o, _ := st.SpaceOwnersNeedingRotation(ctx, "s2", ""); len(o) != 0 {
		t.Fatalf("a rotated space needs nothing: %v", o)
	}

	// items: personal only; trash separate
	st.DB.ExecContext(ctx, `INSERT INTO items(id,owner_sub,vault_id,seq,blob,created_at,updated_at,deleted_at,updated_by) VALUES
		('i1','aaa','personal',1,'b',1,1,0,'aaa'),('i2','aaa','personal',2,'b',1,1,5,'aaa'),('i3','aaa','s1',3,'b',1,1,0,'aaa'),('i4','bbb','personal',4,'b',1,1,0,'bbb')`)
	if ic, err := st.PersonalItemCounts(ctx, "aaa"); err != nil || ic != (ItemCounts{Active: 1, Trashed: 1}) {
		t.Fatalf("%+v %v", ic, err)
	}

	// sessions carry no address, agent or token
	if _, _, err := st.CreateSession(ctx, NewSession{Sub: "aaa", Kind: "ext", Label: "Laptop", Role: "member", IP: "203.0.113.1", UserAgent: "UA", AccessToken: "tok", TokenExpiry: now.Add(time.Hour), Idle: time.Hour, Absolute: time.Hour}); err != nil {
		t.Fatal(err)
	}
	ss, err := st.SessionMetas(ctx, "aaa", 10)
	if err != nil || len(ss) != 1 || ss[0].Label != "Laptop" || ss[0].Kind != "ext" {
		t.Fatalf("%+v %v", ss, err)
	}

	// audit buckets and brief rows
	for i, ev := range []string{"unlock_failed", "unlock_failed", "unlock_failed", "master_password_changed"} {
		actor := "aaa"
		if i == 2 {
			actor = "bbb"
		}
		st.DB.ExecContext(ctx, `INSERT INTO audit_log(created_at,event,actor,ip,user_agent,outcome,details) VALUES (?,?,?,'203.0.113.9','UA','failure','failed=1')`, now.Unix()-int64(i)*10, ev, actor)
	}
	b, err := st.CountAuditBuckets(ctx, "unlock_failed", "aaa", now.Unix()-86400, 3600)
	tot := 0
	for _, n := range b {
		tot += n
	}
	if err != nil || tot != 2 {
		t.Fatalf("per person %v %v", b, err)
	}
	b, _ = st.CountAuditBuckets(ctx, "unlock_failed", "", now.Unix()-86400, 3600)
	tot = 0
	for _, n := range b {
		tot += n
	}
	if tot != 3 {
		t.Fatalf("everyone %v", b)
	}
	rows, err := st.RecentAuditByEvents(ctx, "aaa", []string{"unlock_failed", "master_password_changed"}, now.Unix()-86400, 10)
	if err != nil || len(rows) != 3 || rows[0].CreatedAt < rows[1].CreatedAt {
		t.Fatalf("%+v %v", rows, err)
	}
	if rows, _ := st.RecentAuditByEvents(ctx, "aaa", []string{"unlock_failed"}, now.Unix()-86400, 1); len(rows) != 1 {
		t.Fatalf("limit: %+v", rows)
	}

	oc, err := st.OperationalCounts(ctx)
	if err != nil || oc.Active != 2 || oc.Vaults != 1 || oc.ExtSessions != 1 || oc.WebSessions != 0 {
		t.Fatalf("%+v %v", oc, err)
	}
	// the index the widgets rely on exists
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='audit_event_created'`).Scan(&n)
	if n != 1 {
		t.Fatal("audit_event_created index missing")
	}
}

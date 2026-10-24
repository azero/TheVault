package e2e

import (
	"context"
	"strings"
	"testing"
)

func TestLockedSessionAppGrantsRefreshAndDownloadAuth(t *testing.T) {
	e := newEnv(t)
	e.sso.set(func() {
		e.sso.Apps = []map[string]string{{"client_id": "app_notes", "name": "Notes", "launch_url": "https://notes.example/"}, {"client_id": "app_test", "name": "Own", "launch_url": "https://own.example/"}, {"client_id": "bad", "name": "Bad", "launch_url": "javascript:bad"}}
	})
	c := e.login(subAna, "ana@example.com")
	var session struct {
		Apps []map[string]string `json:"apps"`
	}
	check := func(want int) {
		t.Helper()
		if st := c.getJSON("/api/v1/session", &session); st != 200 || len(session.Apps) != want {
			t.Fatalf("locked session grants: status %d count %d", st, len(session.Apps))
		}
	}
	check(1)
	if session.Apps[0]["client_id"] != "app_notes" {
		t.Fatal("wrong grant")
	}
	expire := func() {
		if _, err := e.st.DB.ExecContext(context.Background(), `UPDATE sessions SET checked_at=0`); err != nil {
			t.Fatal(err)
		}
	}
	e.sso.set(func() { e.sso.Down = true })
	expire()
	check(1)
	e.sso.set(func() { e.sso.Down = false; e.sso.Apps = nil })
	expire()
	check(0)
	anon := e.newClient()
	status, _, _ := anon.do("GET", "/download/extension.zip", nil, nil)
	if status != 401 {
		t.Fatalf("anonymous package status %d", status)
	}
	status, raw, _ := c.do("GET", "/download/extension.zip", nil, nil)
	if status != 200 && status != 404 {
		t.Fatalf("locked package status %d", status)
	}
	if status == 200 && !strings.HasPrefix(string(raw), "PK") {
		t.Fatal("download is not a zip")
	}
	e.sso.set(func() { e.sso.Revoke = true })
	expire()
	if c.getJSON("/api/v1/session", nil) != 401 {
		t.Fatal("revoked SSO session survived")
	}
}

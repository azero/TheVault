package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/notify"
)

func TestNilAndUnconfiguredAreNoOps(t *testing.T) {
	var a *Alerts
	a.Sink(audit.Event{Name: "master_password_changed", Actor: "x", Outcome: "success"}) // must not panic
	a.OnResponse("block", "203.0.113.1", 60)
	New(Options{}).Sink(audit.Event{Name: "master_password_changed", Actor: "x", Outcome: "success"}) // no notifier: nothing happens
}

func TestCatalogIsConsistent(t *testing.T) {
	if n := len(Categories); n < 4 || n > 12 {
		t.Fatalf("%d categories", n)
	}
	seen := map[string]bool{}
	for _, c := range Categories {
		if seen[c.ID] || c.Title == "" || c.Level.Rank() == 0 {
			t.Errorf("category %+v", c)
		}
		seen[c.ID] = true
		if c.Mandatory && c.ID == SpaceInvitation || c.Mandatory && c.ID == AdminSecurity || c.Mandatory && c.ID == MemberRemoved {
			t.Errorf("%s must not be mandatory: only security events about the recipient's own account are", c.ID)
		}
	}
	for _, id := range []string{NewDevice, PasswordChanged, RecoveryUsed, UnlockFailed} {
		for _, c := range Categories {
			if c.ID == id && !c.Mandatory {
				t.Errorf("%s must be mandatory", id)
			}
		}
	}
	if n := New(Options{Notifier: notify.New(Config("", "", notify.Info, nil))}); n.o.Notifier != nil {
		t.Error("no URL and key means notifications are off")
	}
}

func TestHelpers(t *testing.T) {
	if from("") != "" || from("a b") != "" || from("203.0.113.5") != " from 203.0.113.5" {
		t.Error("from")
	}
	k := key("x", "sub", time.Unix(5, 0), "")
	if k != "x:sub:5" || !strings.HasPrefix(key("x", "s", time.Unix(5, 0), "e"), "x:s:5:") {
		t.Error(k)
	}
}

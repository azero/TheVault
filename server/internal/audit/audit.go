// Package audit is the one place security-relevant events are recorded: into the local audit log (what admins and
// users see in the UI) and, when configured, out to SkyNet. Events carry ids, counts and addresses: never anything
// from an encrypted blob, and never a secret.
package audit

import (
	"context"
	"net/mail"
	"strings"
	"sync"

	"github.com/azero/thevault/server/internal/store"
)

type Event struct {
	Name    string // snake_case, listed in docs/security.md
	Actor   string // user sub ("" for anonymous)
	Email   string // only kept if it is a valid address
	Target  string // item/space/session id, or another user's sub
	IP      string
	UA      string
	Outcome string // "success" | "failure" | ""
	Details map[string]string

	// Optional overrides for what SkyNet receives (the local audit row is unaffected). Category replaces the default
	// derived from Name (the automation API reports one api_call event in the natural category of each resource);
	// User replaces the person shown on the event (for example "key:nightly-report" for a service key, which has no email).
	Category string
	User     string
}

type Auditor struct {
	Store *store.Store
	mu    sync.RWMutex
	sinks []func(Event)
}

func New(st *store.Store) *Auditor { return &Auditor{Store: st} }

// AddSink registers a consumer (the SkyNet shipper). Sinks must not block.
func (a *Auditor) AddSink(f func(Event)) {
	a.mu.Lock()
	a.sinks = append(a.sinks, f)
	a.mu.Unlock()
}

func (a *Auditor) Log(ctx context.Context, e Event) {
	if e.Email != "" {
		if addr, err := mail.ParseAddress(e.Email); err != nil || addr.Address != e.Email {
			e.Email = ""
		}
	}
	a.Store.InsertAudit(ctx, store.AuditRow{Event: e.Name, Actor: e.Actor, Target: e.Target, IP: e.IP, UserAgent: e.UA, Outcome: e.Outcome, Details: flatten(e.Details)})
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, s := range a.sinks {
		s(e)
	}
}

func flatten(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// stable output
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k + "=" + strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, m[k]))
	}
	return b.String()
}

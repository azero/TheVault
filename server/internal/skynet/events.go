package skynet

import (
	"strings"
	"time"

	"github.com/azero/thevault/server/internal/audit"
)

// category maps an audit event name to SkyNet's category vocabulary (docs/event-schema.md in SkyNet).
func category(name string) string {
	switch {
	case name == "login" || name == "login_failed" || name == "login_denied" || strings.HasPrefix(name, "unlock") || name == "lock" ||
		strings.HasPrefix(name, "recovery_") || name == "master_password_changed" || name == "logout" || name == "bearer_failed" || name == "ext_token_failed":
		return "authentication"
	case strings.HasPrefix(name, "space_") || strings.HasPrefix(name, "admin_") || strings.HasPrefix(name, "session") || name == "ext_device_added" || name == "role_changed":
		return "iam"
	case name == "csrf_failed" || name == "origin_refused" || name == "blocked_request":
		return "web"
	case name == "heartbeat" || name == "response_applied" || name == "events_dropped":
		return "system"
	}
	return "vault"
}

// Event is the SkyNet envelope (docs/event-schema.md).
type Event struct {
	TS       string            `json:"ts"`
	Host     string            `json:"host"`
	Source   string            `json:"source"`
	Category string            `json:"category"`
	Action   string            `json:"action"`
	Outcome  string            `json:"outcome,omitempty"`
	User     string            `json:"user,omitempty"`
	SrcIP    string            `json:"src_ip,omitempty"`
	Message  string            `json:"message,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// FromAudit converts an audit event. It carries ids, counts and addresses only: the audit.Event never holds vault content.
func FromAudit(e audit.Event, host string, now time.Time) Event {
	f := map[string]string{}
	for k, v := range e.Details {
		f[k] = v
	}
	if e.Actor != "" {
		f["sub"] = e.Actor
	}
	if e.Target != "" {
		f["target"] = e.Target
	}
	if e.UA != "" {
		f["user_agent"] = trunc(e.UA, 200)
	}
	user := e.Email
	if user == "" && e.Actor != "" {
		user = "uid:" + e.Actor
	}
	return Event{TS: now.UTC().Format(time.RFC3339Nano), Host: host, Source: "thevault", Category: category(e.Name), Action: e.Name,
		Outcome: e.Outcome, User: user, SrcIP: e.IP, Fields: f}
}

func trunc(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "")
	}
	return s
}

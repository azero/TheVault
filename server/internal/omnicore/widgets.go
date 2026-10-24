package omnicore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/azero/thevault/server/internal/alerts"
	"github.com/azero/thevault/server/internal/config"
	oc "github.com/azero/thevault/server/internal/omniconnect"
	"github.com/azero/thevault/server/internal/store"
)

type spec struct {
	oc.WidgetSpec
	admin bool
	build func(p *Provider, ctx context.Context, pr person, cfg map[string]string) (oc.Widget, error)
}

var daysOptions = []oc.Option{{Value: "7", Label: "7 days"}, {Value: "14", Label: "14 days"}, {Value: "30", Label: "30 days"}}

// order is the order of the manifest; specs is the lookup.
var order = []string{"vault_status", "vault_size", "spaces", "my_devices", "security_events", "unlock_failures", "users", "failed_unlocks", "blocked_ips", "sessions"}

var specs = map[string]spec{
	"vault_status": {oc.WidgetSpec{ID: "vault_status", Title: "Vault status", Description: "Whether your vault and recovery key are set up, your last unlock and your extension devices",
		Kind: oc.KindStatus, Default: oc.Size{W: 4, H: 3}, Min: &oc.Size{W: 3, H: 2}, Max: &oc.Size{W: 6, H: 4}, RefreshSeconds: 60}, false, buildStatus},
	"vault_size": {oc.WidgetSpec{ID: "vault_size", Title: "Items", Description: "How many items are in your personal vault and in its trash (counts only)",
		Kind: oc.KindStat, Default: oc.Size{W: 3, H: 2}, Min: &oc.Size{W: 2, H: 2}, Max: &oc.Size{W: 4, H: 3}, RefreshSeconds: 300}, false, buildSize},
	"spaces": {oc.WidgetSpec{ID: "spaces", Title: "Shared spaces", Description: "How many shared spaces you belong to and how many of yours need a key rotation (counts only; space names are encrypted)",
		Kind: oc.KindStat, Default: oc.Size{W: 3, H: 2}, Min: &oc.Size{W: 2, H: 2}, Max: &oc.Size{W: 4, H: 3}, RefreshSeconds: 120}, false, buildSpaces},
	"my_devices": {oc.WidgetSpec{ID: "my_devices", Title: "My sessions and devices", Description: "Where you are signed in: web sessions and browser-extension devices, with when they were last seen",
		Kind: oc.KindList, Default: oc.Size{W: 4, H: 4}, Min: &oc.Size{W: 3, H: 2}, Max: &oc.Size{W: 6, H: 6}, RefreshSeconds: 120,
		Config: []oc.ConfigField{{Key: "show", Label: "Show", Type: "select", Default: "all", Options: []oc.Option{{Value: "all", Label: "Web and extensions"}, {Value: "ext", Label: "Extension devices only"}}}}}, false, buildDevices},
	"security_events": {oc.WidgetSpec{ID: "security_events", Title: "Security events", Description: "Failed unlocks, new devices, master-password changes and recovery use on your account",
		Kind: oc.KindList, Default: oc.Size{W: 8, H: 4}, Min: &oc.Size{W: 4, H: 3}, Max: &oc.Size{W: 12, H: 8}, RefreshSeconds: 120,
		Config: []oc.ConfigField{{Key: "days", Label: "Period", Type: "select", Default: "30", Options: []oc.Option{{Value: "7", Label: "7 days"}, {Value: "30", Label: "30 days"}, {Value: "90", Label: "90 days"}}}}}, false, buildEvents},
	"unlock_failures": {oc.WidgetSpec{ID: "unlock_failures", Title: "Failed unlocks per day", Description: "Wrong master passwords entered on your vault, per day",
		Kind: oc.KindSeries, Default: oc.Size{W: 6, H: 3}, Min: &oc.Size{W: 3, H: 2}, Max: &oc.Size{W: 12, H: 5}, RefreshSeconds: 300,
		Config: []oc.ConfigField{{Key: "days", Label: "Period", Type: "select", Default: "14", Options: daysOptions}}}, false, buildFailuresMine},
	"users": {oc.WidgetSpec{ID: "users", Title: "People", Description: "Active and locked accounts, vaults and lockouts (counts only)",
		Kind: oc.KindStat, Default: oc.Size{W: 3, H: 2}, Min: &oc.Size{W: 2, H: 2}, Max: &oc.Size{W: 4, H: 3}, RefreshSeconds: 120, Roles: []string{"admin"}}, true, buildUsers},
	"failed_unlocks": {oc.WidgetSpec{ID: "failed_unlocks", Title: "Failed unlocks per hour", Description: "Wrong master passwords across all accounts, per hour (no names or addresses)",
		Kind: oc.KindSeries, Default: oc.Size{W: 6, H: 3}, Min: &oc.Size{W: 3, H: 2}, Max: &oc.Size{W: 12, H: 5}, RefreshSeconds: 120, Roles: []string{"admin"},
		Config: []oc.ConfigField{{Key: "hours", Label: "Period", Type: "select", Default: "24", Options: []oc.Option{{Value: "24", Label: "24 hours"}, {Value: "72", Label: "3 days"}, {Value: "168", Label: "7 days"}}}}}, true, buildFailuresAll},
	"blocked_ips": {oc.WidgetSpec{ID: "blocked_ips", Title: "Blocked addresses", Description: "Addresses SkyNet currently has TheVault block",
		Kind: oc.KindList, Default: oc.Size{W: 4, H: 3}, Min: &oc.Size{W: 3, H: 2}, Max: &oc.Size{W: 6, H: 6}, RefreshSeconds: 60, Roles: []string{"admin"}}, true, buildBlocked},
	"sessions": {oc.WidgetSpec{ID: "sessions", Title: "Live sessions", Description: "Web sessions and extension devices that are signed in right now, all accounts (counts only)",
		Kind: oc.KindStat, Default: oc.Size{W: 3, H: 2}, Min: &oc.Size{W: 2, H: 2}, Max: &oc.Size{W: 4, H: 3}, RefreshSeconds: 60, Roles: []string{"admin"}}, true, buildSessions},
}

func buildManifest(cfg *config.Config, version string) oc.Manifest {
	m := oc.Manifest{
		App: oc.AppInfo{ID: alerts.Source, Name: "TheVault", Description: "Passwords and secrets", Version: version, Icon: "lock", Accent: "#1d4ed8", PublicURL: cfg.PublicURL, OpenURL: "/"},
		Overview: oc.Overview{Title: "TheVault", Widgets: []oc.OverviewItem{
			{Widget: "vault_status", W: 4, H: 3}, {Widget: "vault_size", W: 4, H: 3}, {Widget: "spaces", W: 4, H: 3},
			{Widget: "security_events", W: 8, H: 4}, {Widget: "my_devices", W: 4, H: 4},
			{Widget: "unlock_failures", W: 12, H: 3},
		}},
	}
	for _, id := range order {
		m.Widgets = append(m.Widgets, specs[id].WidgetSpec)
	}
	for _, c := range alerts.Categories {
		m.Notifications.Categories = append(m.Notifications.Categories, oc.Category{ID: c.ID, Title: c.Title, Description: c.Description, Level: string(c.Level), Mandatory: c.Mandatory})
	}
	return m
}

// ---- helpers ----

func pick(cfg map[string]string, key, def string, allowed ...string) string {
	v := cfg[key]
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return def
}

func atoiDef(s string, def int) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	if s == "" {
		return def
	}
	return n
}

func ago(now, t int64) string {
	d := now - t
	switch {
	case t <= 0:
		return "never"
	case d < 60:
		return "just now"
	case d < 3600:
		return itoa(int(d/60)) + " min ago"
	case d < 86400:
		return itoa(int(d/3600)) + " h ago"
	default:
		return itoa(int(d/86400)) + " days ago"
	}
}

func stamp(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02 15:04 UTC") }

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func noVault() oc.Widget {
	return oc.Widget{Kind: oc.KindNotice, Text: "Your vault has not been created yet. Open TheVault to set it up.", Action: &oc.Action{Label: "Open TheVault", Link: "/"}}
}

// ---- widgets for everybody (the person's own data) ----

func buildStatus(p *Provider, ctx context.Context, pr person, _ map[string]string) (oc.Widget, error) {
	now := p.now().Unix()
	w := oc.Widget{Kind: oc.KindStatus, Title: "Vault status", Link: "/#/settings/security"}
	vm, err := p.Store.VaultMeta(ctx, pr.sub)
	if errors.Is(err, store.ErrNotFound) {
		w.Checks = []oc.Check{{Label: "Vault", State: "warn", Detail: "Not created yet. Open TheVault to set it up.", Link: "/"}}
		w.Tone = oc.ToneWarn
		return w, nil
	}
	if err != nil {
		return w, err
	}
	live, err := p.Store.SessionMetas(ctx, pr.sub, 50)
	if err != nil {
		return w, err
	}
	ext := 0
	for _, s := range live {
		if s.Kind == "ext" {
			ext++
		}
	}
	checks := []oc.Check{{Label: "Vault", State: "ok", Detail: "Set up " + stamp(vm.CreatedAt)}}
	if vm.RecoveryConfigured {
		checks = append(checks, oc.Check{Label: "Recovery key", State: "ok", Detail: "Configured"})
	} else {
		checks = append(checks, oc.Check{Label: "Recovery key", State: "bad", Detail: "Not configured. Create one in Settings, Security.", Link: "/#/settings/security"})
	}
	if vm.LastUnlock > 0 {
		checks = append(checks, oc.Check{Label: "Last unlock", State: "ok", Detail: ago(now, vm.LastUnlock)})
	} else {
		checks = append(checks, oc.Check{Label: "Last unlock", State: "unknown", Detail: "Never unlocked"})
	}
	switch {
	case vm.LockedUntil > now:
		checks = append(checks, oc.Check{Label: "Unlock attempts", State: "bad", Detail: "Unlocking is paused for " + itoa(int((vm.LockedUntil-now+59)/60)) + " min after wrong passwords", Link: "/#/settings/activity"})
	case vm.FailedUnlocks > 0:
		checks = append(checks, oc.Check{Label: "Unlock attempts", State: "warn", Detail: plural(vm.FailedUnlocks, "wrong password", "wrong passwords") + " since the last successful unlock", Link: "/#/settings/activity"})
	default:
		checks = append(checks, oc.Check{Label: "Unlock attempts", State: "ok", Detail: "No wrong passwords"})
	}
	checks = append(checks, oc.Check{Label: "Extension devices", State: "ok", Detail: plural(ext, "device signed in", "devices signed in"), Link: "/#/settings/devices"})
	w.Checks = checks
	w.Tone = oc.ToneOK
	for _, c := range checks {
		if c.State == "bad" {
			w.Tone = oc.ToneBad
		} else if c.State == "warn" && w.Tone != oc.ToneBad {
			w.Tone = oc.ToneWarn
		}
	}
	return w, nil
}

func buildSize(p *Provider, ctx context.Context, pr person, _ map[string]string) (oc.Widget, error) {
	if _, err := p.Store.VaultMeta(ctx, pr.sub); errors.Is(err, store.ErrNotFound) {
		return noVault(), nil
	} else if err != nil {
		return oc.Widget{}, err
	}
	c, err := p.Store.PersonalItemCounts(ctx, pr.sub)
	if err != nil {
		return oc.Widget{}, err
	}
	w := oc.Widget{Kind: oc.KindStat, Title: "Items", Value: itoa(c.Active), Unit: "items", Link: "/#/all",
		Stats: []oc.Stat{{Label: "In trash", Value: itoa(c.Trashed), Tone: oc.ToneMuted}}}
	if c.Trashed > 0 {
		w.Subtitle = "Trash is emptied after 30 days"
	}
	return w, nil
}

func buildSpaces(p *Provider, ctx context.Context, pr person, _ map[string]string) (oc.Widget, error) {
	c, err := p.Store.SpaceCountsFor(ctx, pr.sub)
	if err != nil {
		return oc.Widget{}, err
	}
	w := oc.Widget{Kind: oc.KindStat, Title: "Shared spaces", Value: itoa(c.Member), Unit: "spaces", Link: "/#/spaces",
		Stats: []oc.Stat{{Label: "You own", Value: itoa(c.Owned)}}}
	rot := oc.Stat{Label: "Need key rotation", Value: itoa(c.NeedRotation), Tone: oc.ToneMuted}
	if c.NeedRotation > 0 {
		rot.Tone = oc.ToneBad
		w.Tone = oc.ToneBad
		w.Subtitle = "A member was removed: rotate the key"
	}
	w.Stats = append(w.Stats, rot)
	return w, nil
}

func buildDevices(p *Provider, ctx context.Context, pr person, cfg map[string]string) (oc.Widget, error) {
	show := pick(cfg, "show", "all", "all", "ext")
	rows, err := p.Store.SessionMetas(ctx, pr.sub, 50)
	if err != nil {
		return oc.Widget{}, err
	}
	now := p.now().Unix()
	w := oc.Widget{Kind: oc.KindList, Title: "My sessions and devices", Link: "/#/settings/devices", Empty: "No active sessions."}
	for _, s := range rows {
		if show == "ext" && s.Kind != "ext" {
			continue
		}
		it := oc.Item{Meta: "last seen " + ago(now, s.LastSeen), Subtitle: "signed in " + ago(now, s.CreatedAt)}
		if s.Kind == "ext" {
			it.Title, it.Badge, it.Icon = orDefault(s.Label, "Browser extension"), "extension", "key"
			if now-s.CreatedAt < 86400 {
				it.Tone = oc.ToneInfo
			}
		} else {
			it.Title, it.Badge, it.Icon = orDefault(s.Label, "Web browser"), "web", "globe"
		}
		w.Items = append(w.Items, it)
	}
	if show == "ext" {
		w.Empty = "No extension devices are signed in."
	}
	return w, nil
}

func orDefault(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

// The events a person may see about their own account (the same ones Settings, Activity shows), in words.
var eventNames = []string{"unlock_failed", "unlock_lockout", "recovery_failed", "recovery_used", "master_password_changed", "ext_device_added", "sessions_revoked_by_user", "session_revoked_by_user"}

func describe(a store.AuditBrief) (title string, tone oc.Tone) {
	f := strings.Fields(a.Details) // flatten() sorts keys: the last fields are the machine-written ones
	last := func(k string) string {
		for i := len(f) - 1; i >= 0 && i >= len(f)-3; i-- {
			if v, ok := strings.CutPrefix(f[i], k+"="); ok {
				return v
			}
		}
		return ""
	}
	switch a.Event {
	case "unlock_failed":
		t := "Wrong master password"
		if n := last("failed"); n != "" && len(n) < 6 {
			t += " (" + n + " in a row)"
		}
		return t, oc.ToneWarn
	case "unlock_lockout":
		return "Unlocking paused after repeated wrong passwords", oc.ToneBad
	case "recovery_failed":
		return "Wrong recovery key", oc.ToneWarn
	case "recovery_used":
		return "Recovery key used to reset the master password", oc.ToneBad
	case "master_password_changed":
		return "Master password changed", oc.ToneWarn
	case "ext_device_added":
		if last("replaced") == "true" || (last("replaced") == "" && last("renewed") == "true") {
			return "Extension device renewed", oc.ToneMuted
		}
		return "New extension device authorised", oc.ToneInfo
	case "sessions_revoked_by_user":
		return "Other sessions signed out", oc.ToneMuted
	case "session_revoked_by_user":
		return "A session was signed out", oc.ToneMuted
	}
	return a.Event, oc.ToneMuted
}

func buildEvents(p *Provider, ctx context.Context, pr person, cfg map[string]string) (oc.Widget, error) {
	days := atoiDef(pick(cfg, "days", "30", "7", "30", "90"), 30)
	now := p.now()
	rows, err := p.Store.RecentAuditByEvents(ctx, pr.sub, eventNames, now.AddDate(0, 0, -days).Unix(), 20)
	if err != nil {
		return oc.Widget{}, err
	}
	w := oc.Widget{Kind: oc.KindList, Title: "Security events", Subtitle: "Last " + itoa(days) + " days", Link: "/#/settings/activity", Empty: "Nothing to report in the last " + itoa(days) + " days."}
	for _, a := range rows {
		t, tone := describe(a)
		w.Items = append(w.Items, oc.Item{Title: t, Tone: tone, Meta: ago(now.Unix(), a.CreatedAt), Subtitle: stamp(a.CreatedAt)})
	}
	return w, nil
}

// dailySeries fills every bucket in [from, now] with a count, so quiet days are zeros and the chart has a stable x axis.
func series(counts map[int64]int, now time.Time, n int, bucket int64) []oc.Point {
	end := now.Unix() / bucket * bucket
	pts := make([]oc.Point, 0, n)
	for i := n - 1; i >= 0; i-- {
		t := end - int64(i)*bucket
		pts = append(pts, oc.Point{T: t, V: float64(counts[t])})
	}
	return pts
}

func total(counts map[int64]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}

func buildFailuresMine(p *Provider, ctx context.Context, pr person, cfg map[string]string) (oc.Widget, error) {
	days := atoiDef(pick(cfg, "days", "14", "7", "14", "30"), 14)
	now := p.now()
	since := now.Unix()/86400*86400 - int64(days-1)*86400
	counts, err := p.Store.CountAuditBuckets(ctx, "unlock_failed", pr.sub, since, 86400)
	if err != nil {
		return oc.Widget{}, err
	}
	w := oc.Widget{Kind: oc.KindSeries, Title: "Failed unlocks per day", Chart: "bar", X: "time", Link: "/#/settings/activity",
		Series: []oc.Series{{Name: "Failed unlocks", Points: series(counts, now, days, 86400)}}}
	if n := total(counts); n > 0 {
		w.Subtitle = plural(n, "wrong password", "wrong passwords") + " in " + itoa(days) + " days"
		w.Tone = oc.ToneWarn
	} else {
		w.Subtitle = "No wrong passwords in " + itoa(days) + " days"
		w.Tone = oc.ToneOK
	}
	return w, nil
}

// ---- administrator widgets: operational numbers only ----

func buildUsers(p *Provider, ctx context.Context, _ person, _ map[string]string) (oc.Widget, error) {
	c, err := p.Store.OperationalCounts(ctx)
	if err != nil {
		return oc.Widget{}, err
	}
	w := oc.Widget{Kind: oc.KindStat, Title: "People", Value: itoa(c.Active), Unit: "active", Link: "/#/admin/users",
		Stats: []oc.Stat{{Label: "Locked by an admin", Value: itoa(c.Locked), Tone: toneIf(c.Locked > 0, oc.ToneWarn)}, {Label: "Administrators", Value: itoa(c.Admins)},
			{Label: "With a vault", Value: itoa(c.Vaults)}, {Label: "In unlock lockout", Value: itoa(c.PasswordLockedOut), Tone: toneIf(c.PasswordLockedOut > 0, oc.ToneWarn)}}}
	return w, nil
}

func toneIf(c bool, t oc.Tone) oc.Tone {
	if c {
		return t
	}
	return oc.ToneMuted
}

func buildFailuresAll(p *Provider, ctx context.Context, _ person, cfg map[string]string) (oc.Widget, error) {
	hours := atoiDef(pick(cfg, "hours", "24", "24", "72", "168"), 24)
	now := p.now()
	since := now.Unix()/3600*3600 - int64(hours-1)*3600
	counts, err := p.Store.CountAuditBuckets(ctx, "unlock_failed", "", since, 3600)
	if err != nil {
		return oc.Widget{}, err
	}
	w := oc.Widget{Kind: oc.KindSeries, Title: "Failed unlocks per hour", Chart: "bar", X: "time", Link: "/#/admin/audit",
		Series: []oc.Series{{Name: "Failed unlocks", Points: series(counts, now, hours, 3600)}}}
	n := total(counts)
	w.Subtitle = plural(n, "wrong password", "wrong passwords") + " in " + itoa(hours) + " hours"
	if n > 0 {
		w.Tone = oc.ToneWarn
	}
	return w, nil
}

func buildBlocked(p *Provider, ctx context.Context, _ person, _ map[string]string) (oc.Widget, error) {
	w := oc.Widget{Kind: oc.KindList, Title: "Blocked addresses", Link: "/#/admin/skynet", Empty: "No addresses are blocked."}
	if !p.Cfg.SkyNetEnabled() {
		return oc.Widget{Kind: oc.KindNotice, Title: "Blocked addresses", Text: "SkyNet is not connected, so no addresses are blocked.", Link: "/#/admin/skynet"}, nil
	}
	deny, err := p.Store.DenyActive(ctx)
	if err != nil {
		return oc.Widget{}, err
	}
	now := p.now().Unix()
	w.Subtitle = plural(len(deny), "address blocked", "addresses blocked")
	for _, d := range deny {
		w.Items = append(w.Items, oc.Item{Title: d.IP, Subtitle: "until " + stamp(d.Until), Meta: "in " + itoa(int((d.Until-now+59)/60)) + " min", Tone: oc.ToneWarn, Icon: "shield"})
	}
	return w, nil
}

func buildSessions(p *Provider, ctx context.Context, _ person, _ map[string]string) (oc.Widget, error) {
	c, err := p.Store.OperationalCounts(ctx)
	if err != nil {
		return oc.Widget{}, err
	}
	return oc.Widget{Kind: oc.KindStat, Title: "Live sessions", Value: itoa(c.WebSessions + c.ExtSessions), Unit: "signed in", Link: "/#/admin/users",
		Stats: []oc.Stat{{Label: "Web sessions", Value: itoa(c.WebSessions)}, {Label: "Extension devices", Value: itoa(c.ExtSessions)}}}, nil
}

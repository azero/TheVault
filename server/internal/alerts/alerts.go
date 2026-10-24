package alerts

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/auth"
	"github.com/azero/thevault/server/internal/notify"
	"github.com/azero/thevault/server/internal/store"
)

// Options wires the alerts. A nil Notifier (Beacon not configured) makes every method a no-op.
type Options struct {
	Notifier   *notify.Notifier
	Store      *store.Store
	PublicURL  string // where "Open" leads; the vault itself, never an item or space
	AdminGroup string // Beacon group for admin_security
}

type Alerts struct {
	o      Options
	failed *auth.Limiter // unlock_failed: one message per person per 15 minutes, so an attacker cannot use us to spam someone

	// space_invitation can be caused by any colleague who owns a space (the add itself is allowed to everyone with a vault),
	// so what reaches one person is capped both per sender and in total. The addition still happens and shows in the app.
	invitedBy *auth.Limiter // per sender and recipient
	invitedTo *auth.Limiter // per recipient, whoever sent it
	wg        sync.WaitGroup
}

func New(o Options) *Alerts {
	return &Alerts{o: o, failed: auth.NewLimiter(1, 15*time.Minute), invitedBy: auth.NewLimiter(2, time.Hour), invitedTo: auth.NewLimiter(5, time.Hour)}
}

// Wait blocks until background lookups (space owners) are finished; the app calls it on shutdown before the store closes.
func (a *Alerts) Wait() { a.wg.Wait() }

// Sink is registered with the auditor. It must not block: the work is a map lookup and a non-blocking Notify, and the one
// database lookup (owners of a space) runs in its own goroutine.
func (a *Alerts) Sink(e audit.Event) {
	if a == nil || a.o.Notifier == nil {
		return
	}
	now := time.Now()
	switch e.Name {
	case "ext_device_added":
		// A renewal replaces the extension's previous token (same device, same person): not news. Only a new authorisation is.
		if e.Outcome == "success" && e.Actor != "" && e.Details["replaced"] != "true" {
			a.send(NewDevice, notify.Critical, e.Actor, "New extension device signed in",
				"A browser extension was authorised for your TheVault account"+from(e.IP)+". If this was not you, open TheVault, sign that device out under Settings, Devices, and change your master password.",
				"/#/settings/devices", key(NewDevice, e.Actor, now, e.IP))
		}
	case "master_password_changed":
		if e.Outcome == "success" && e.Actor != "" {
			a.send(PasswordChanged, notify.Critical, e.Actor, "Your master password was changed",
				"The master password of your vault was changed and your other sessions and extension devices were signed out"+from(e.IP)+". If this was not you, use your recovery key at once.",
				"/#/settings/security", key(PasswordChanged, e.Actor, now, ""))
		}
	case "recovery_used":
		if e.Outcome == "success" && e.Actor != "" {
			a.send(RecoveryUsed, notify.Critical, e.Actor, "Your recovery key was used",
				"Your recovery key was used to reset the master password of your vault"+from(e.IP)+". Other sessions and extension devices were signed out. If this was not you, contact an administrator now.",
				"/#/settings/security", key(RecoveryUsed, e.Actor, now, ""))
		}
	case "unlock_failed":
		n, _ := strconv.Atoi(e.Details["failed"])
		if e.Outcome == "failure" && e.Actor != "" && n >= 3 && a.failed.Allow(e.Actor) {
			a.send(UnlockFailed, notify.Important, e.Actor, "Wrong master password attempts",
				strconv.Itoa(n)+" wrong master passwords have been entered on your vault since it was last unlocked"+from(e.IP)+". After five, unlocking is slowed down. If this was not you, change your master password and sign out other sessions.",
				"/#/settings/security", key(UnlockFailed, e.Actor, now.Truncate(15*time.Minute), ""))
		}
	case "space_member_added":
		if e.Outcome == "success" && e.Details["member"] != "" && e.Details["member"] != e.Actor {
			role := e.Details["role"]
			if role != "owner" && role != "editor" && role != "viewer" {
				role = "member"
			}
			if !a.invitedBy.Allow(e.Actor+">"+e.Details["member"]) || !a.invitedTo.Allow(e.Details["member"]) {
				return
			}
			a.send(SpaceInvitation, notify.Notice, e.Details["member"], "You were added to a shared space",
				"A colleague added you to a shared space as "+role+". Unlock TheVault to see it.",
				"/#/spaces", key(SpaceInvitation, e.Details["member"]+":"+e.Target, now, ""))
		}
	case "space_member_removed", "space_left":
		if e.Outcome == "success" && e.Target != "" {
			a.afterRemoval(e, now)
		}
	case "admin_user_locked":
		if e.Outcome == "success" {
			a.sendGroup("An account was locked", "An administrator locked a TheVault account"+sessionsEnded(e.Details)+".", "/#/admin/users", key("admin_lock", e.Target, now, ""))
		}
	case "admin_vault_erased":
		if e.Outcome == "success" {
			a.sendGroup("A vault was erased", "An administrator erased a person's vault. The ciphertext is gone; the person can create a new vault.", "/#/admin/audit", key("admin_erase", e.Target, now, ""))
		}
	}
}

// OnResponse is called when SkyNet's signed block_ip command was applied. Only blocks matter; an unblock is not news.
func (a *Alerts) OnResponse(what, ip string, ttl int64) {
	if a == nil || a.o.Notifier == nil || what != "block" || ip == "" {
		return
	}
	mins := ttl / 60
	if mins < 1 {
		mins = 1
	}
	a.sendGroup("An address was blocked", "SkyNet blocked "+ip+" for "+strconv.FormatInt(mins, 10)+" minutes. Every request from it now gets HTTP 403.", "/#/admin/skynet", key("admin_block", ip, time.Now(), ""))
}

func (a *Alerts) afterRemoval(e audit.Event, now time.Time) {
	removed := e.Details["member"]
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		owners, err := a.o.Store.SpaceOwnersNeedingRotation(ctx, e.Target, removed)
		if err != nil {
			return
		}
		for _, sub := range owners {
			a.send(MemberRemoved, notify.Important, sub, "A space needs a new key",
				"A member was removed from a shared space you own. Until you rotate the space key, the removed person could still read new changes. Open TheVault, unlock it and rotate the key.",
				"/#/spaces", key(MemberRemoved, sub+":"+e.Target, now, ""))
		}
	}()
}

func (a *Alerts) send(cat string, lvl notify.Level, sub, title, body, path, idem string) {
	a.o.Notifier.Notify(notify.Event{Category: cat, Level: lvl, To: []notify.Recipient{{User: sub}}, Title: title, Body: body,
		URL: a.o.PublicURL + path, ActionLabel: "Open TheVault", IdempotencyKey: idem})
}

func (a *Alerts) sendGroup(title, body, path, idem string) {
	if a.o.AdminGroup == "" {
		return
	}
	a.o.Notifier.Notify(notify.Event{Category: AdminSecurity, Level: notify.Important, To: []notify.Recipient{{Group: a.o.AdminGroup}}, Title: title, Body: body,
		URL: a.o.PublicURL + path, ActionLabel: "Open TheVault", IdempotencyKey: idem})
}

// key is a stable id per real-world event: the same audit event retried or replayed never double-sends.
func key(kind, who string, at time.Time, extra string) string {
	k := kind + ":" + who + ":" + strconv.FormatInt(at.Unix(), 10)
	if extra != "" {
		k += ":" + extra
	}
	return k
}

func from(ip string) string {
	if ip == "" || len(ip) > 64 || strings.ContainsAny(ip, " \r\n\t") {
		return ""
	}
	return " from " + ip
}

func sessionsEnded(d map[string]string) string {
	if n := d["sessions_ended"]; n != "" && len(n) < 6 {
		return " (" + n + " sessions ended)"
	}
	return ""
}

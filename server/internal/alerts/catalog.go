// Package alerts turns TheVault's audit events into Beacon notifications (docs/omnicore.md).
//
// It is an audit sink: the audit trail is the one place every security-relevant action already passes through, so a
// notification can never be missed or double-counted by a handler, and a handler never waits for Beacon. Notifications
// are additional to the audit rows and SkyNet events, which are unchanged.
//
// Content rule (AGENTS.md hard constraint 1): titles and bodies say what happened to the recipient's own account and
// nothing else. Item, folder and space names are inside encrypted blobs and are unknown to the server; they, secrets,
// device labels chosen by a client, and other people's e-mail addresses are never put in a notification.
package alerts

import "github.com/azero/thevault/server/internal/notify"

// Source is TheVault's id at Beacon (and the app id in the OmniCore manifest).
const Source = "thevault"

// Category ids.
const (
	NewDevice         = "new_device"
	PasswordChanged   = "master_password_changed"
	RecoveryUsed      = "recovery_key_used"
	UnlockFailed      = "unlock_failed"
	SpaceInvitation   = "space_invitation"
	MemberRemoved     = "member_removed_rotate"
	AdminSecurity     = "admin_security"
	sourceTitle       = "TheVault"
	sourceDescription = "Passwords and secrets: security events about your account and your shared spaces"
)

// Categories is the catalog sent to Beacon and shown in OmniCore's settings. Mandatory ones are security events about the
// recipient's own account: people cannot switch them off.
var Categories = []notify.Category{
	{ID: NewDevice, Title: "New extension device", Description: "A browser extension was authorised for your account.", Level: notify.Critical, Mandatory: true},
	{ID: PasswordChanged, Title: "Master password changed", Description: "Your master password was changed and your other sessions were signed out.", Level: notify.Critical, Mandatory: true},
	{ID: RecoveryUsed, Title: "Recovery key used", Description: "Your recovery key was used to reset your master password.", Level: notify.Critical, Mandatory: true},
	{ID: UnlockFailed, Title: "Wrong master password attempts", Description: "Repeated wrong master passwords on your vault (at most one message every 15 minutes).", Level: notify.Important, Mandatory: true},
	{ID: SpaceInvitation, Title: "Added to a shared space", Description: "Someone added you to a shared space.", Level: notify.Notice},
	{ID: MemberRemoved, Title: "Space key rotation needed", Description: "A member was removed from a space you own; its key must be rotated.", Level: notify.Important},
	{ID: AdminSecurity, Title: "Administrator security events", Description: "Administrators: an address was blocked, an account was locked or a vault was erased.", Level: notify.Important},
}

// Config builds the notifier configuration. url and key empty means notifications are off (New returns nil).
func Config(url, key string, min notify.Level, logf func(string, ...any)) notify.Config {
	return notify.Config{URL: url, Key: key, Source: Source, Title: sourceTitle, Description: sourceDescription, Categories: Categories, MinLevel: min, Logf: logf}
}

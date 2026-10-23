package automation

import (
	"fmt"
	"strings"
)

// Scope is one permission an API key can hold for TheVault. The catalog below is the only place scopes are defined:
// `thevault api-scopes` prints it for pasting into ClosedDoor (Admin -> Applications -> TheVault -> API permissions),
// every route names exactly one of them, and tests keep the three in step.
type Scope struct {
	Name        string
	Description string // at most 190 characters (ClosedDoor's limit)

	// Sensitive scopes reveal personal data or act on accounts: every call is audited (api_call) and sent to SkyNet.
	// Mutating calls are always audited, whatever the scope.
	Sensitive bool
	// Category is the SkyNet category of the api_call event for this scope.
	Category string
}

// Catalog is ordered the way the docs and `api-scopes` present it. ClosedDoor accepts at most 100 scopes.
var Catalog = []Scope{
	{Name: "status:read", Category: "system",
		Description: "Read health, version, schema version, database size, SkyNet connection status and the list of backup snapshots (names, sizes, times). No vault data."},
	{Name: "users:read", Sensitive: true, Category: "iam",
		Description: "List and read accounts: id, name, email, role, locked state, whether a vault exists, sign-in times, number of sessions. Personal data."},
	{Name: "users:lock", Sensitive: true, Category: "iam",
		Description: "Lock an account like an administrator can: ends its sessions and refuses sign-in. Cannot lock yourself or the last administrator."},
	{Name: "users:unlock", Sensitive: true, Category: "iam",
		Description: "Unlock an account that was locked by an administrator."},
	{Name: "sessions:read", Sensitive: true, Category: "iam",
		Description: "List a person's browser and extension sessions: kind, label, address, times, whether unlocked. Metadata only, never tokens."},
	{Name: "sessions:revoke", Sensitive: true, Category: "iam",
		Description: "End one or all sessions of a person (web and extension devices). Signs them out; their vault is untouched."},
	{Name: "audit:read", Sensitive: true, Category: "system",
		Description: "Read the audit log (events, actors, addresses, details), the same data the administration screen shows. Sensitive."},
	{Name: "response:read", Sensitive: true, Category: "system",
		Description: "Read the addresses SkyNet has made TheVault block, with expiry and reason. Read-only."},
}

// CatalogText is the paste-ready block for ClosedDoor: one `name  description` per line.
func CatalogText() string {
	var b strings.Builder
	for _, s := range Catalog {
		fmt.Fprintf(&b, "%s  %s\n", s.Name, s.Description)
	}
	return b.String()
}

func scopeInfo(name string) (Scope, bool) {
	for _, s := range Catalog {
		if s.Name == name {
			return s, true
		}
	}
	return Scope{}, false
}

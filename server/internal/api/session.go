package api

import (
	"log"
	"net/http"
	"time"

	"github.com/azero/thevault/server/internal/httpx"
	"github.com/azero/thevault/server/internal/store"
)

func logErr(what string, err error) { log.Printf("%s: %v", what, err) }

type userJSON struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

func (s *Server) vaultState(c *rc) string {
	if _, err := s.Store.GetVaultKeys(c.R.Context(), c.Sess.Sub); err != nil {
		return "none"
	}
	if c.Sess.UnlockedUntil > time.Now().Unix() {
		return "unlocked"
	}
	return "locked"
}

func (s *Server) getSession(c *rc) {
	sess := c.Sess
	now := time.Now()
	idle := int(s.idleFor(sess) / time.Minute)
	c.ok(map[string]any{
		"user":              userJSON{Sub: sess.Sub, Email: sess.Email, Name: sess.Name, Role: sess.Role},
		"csrf":              sess.CSRF,
		"kind":              sess.Kind,
		"vault":             map[string]any{"state": s.vaultState(c), "unlocked_until": sess.UnlockedUntil},
		"sso":               map[string]any{"fresh": now.Before(time.Unix(sess.TokenExpiry, 0).Add(-tokenSkew)), "expires_at": sess.TokenExpiry},
		"idle_lock_minutes": idle,
		"version":           s.Version,
		"can_plain_export":  s.Cfg.AllowPlainExport,
		"extension_ids":     s.Cfg.ExtensionIDs,
		"server_time":       now.Unix(),
	})
}

func (s *Server) logout(c *rc) {
	s.Store.DeleteSessionByHash(c.R.Context(), c.Sess.IDHash)
	c.audit(s, "logout", "success", "", map[string]string{"kind": c.Sess.Kind})
	redirect := "/login"
	if c.Sess.Kind == "web" {
		if end := s.Auth.EndSessionURL(c.R.Context()); end != "" {
			sep := "?"
			if containsByte(end, '?') {
				sep = "&"
			}
			redirect = end + sep + "client_id=" + urlQuery(s.Cfg.OIDCClientID) + "&post_logout_redirect_uri=" + urlQuery(s.Cfg.PublicURL+"/login")
		}
	}
	c.ok(map[string]string{"redirect": redirect})
}

func (s *Server) putSettings(c *rc) {
	var in struct {
		IdleLockMinutes int `json:"idle_lock_minutes"`
	}
	if !c.decode(&in, 1<<10) {
		return
	}
	if in.IdleLockMinutes < 1 || in.IdleLockMinutes > 480 {
		c.fail(http.StatusBadRequest, "bad_request", "The auto-lock time must be between 1 minute and 8 hours.")
		return
	}
	if err := s.Store.SetUnlockIdle(c.R.Context(), c.Sess.Sub, in.IdleLockMinutes); err != nil {
		s.storeErr(c, err)
		return
	}
	// apply immediately to this session's grant
	if c.Sess.UnlockedUntil > time.Now().Unix() {
		c.Sess.UnlockIdleMinutes = in.IdleLockMinutes
		until := time.Now().Add(time.Duration(in.IdleLockMinutes) * time.Minute).Unix()
		if until < c.Sess.UnlockedUntil {
			s.Store.SetUnlockedUntil(c.R.Context(), c.Sess.IDHash, until)
		}
	}
	c.ok(map[string]any{"idle_lock_minutes": in.IdleLockMinutes})
}

func (s *Server) listSessions(c *rc) {
	list, err := s.Store.ListUserSessions(c.R.Context(), c.Sess.Sub)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	type row struct {
		ID        string `json:"id"`
		Kind      string `json:"kind"`
		Label     string `json:"label"`
		IP        string `json:"ip"`
		UserAgent string `json:"user_agent"`
		CreatedAt int64  `json:"created_at"`
		LastSeen  int64  `json:"last_seen"`
		Unlocked  bool   `json:"unlocked"`
		Current   bool   `json:"current"`
	}
	out := make([]row, 0, len(list))
	now := time.Now().Unix()
	for _, x := range list {
		out = append(out, row{ID: x.PublicID(), Kind: x.Kind, Label: x.Label, IP: x.IP, UserAgent: x.UserAgent, CreatedAt: x.CreatedAt, LastSeen: x.LastSeen, Unlocked: x.UnlockedUntil > now, Current: x.IDHash == c.Sess.IDHash})
	}
	c.ok(map[string]any{"sessions": out})
}

func (s *Server) revokeSession(c *rc) {
	id := c.R.PathValue("id")
	ok, err := s.Store.RevokeSessionByPublicID(c.R.Context(), c.Sess.Sub, id)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	if !ok {
		c.fail(http.StatusNotFound, "not_found", "That session no longer exists.")
		return
	}
	c.audit(s, "session_revoked_by_user", "success", id, nil)
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) revokeOthers(c *rc) {
	n, err := s.Store.DeleteUserSessions(c.R.Context(), c.Sess.Sub, c.Sess.IDHash)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "sessions_revoked_by_user", "success", "", map[string]string{"count": itoa(n)})
	c.ok(map[string]int{"revoked": n})
}

func (s *Server) activity(c *rc) {
	rows, err := s.Store.ListAudit(c.R.Context(), c.Sess.Sub, 100)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	// A user sees their own trail: what happened to their account, from where. Other people's addresses are not shown.
	for i := range rows {
		if rows[i].Actor != c.Sess.Sub {
			rows[i].IP, rows[i].UserAgent = "", ""
		}
	}
	c.ok(map[string]any{"events": rows})
}

// clientAudit lets the client report actions only it can see (an export happens in the browser). It is advisory:
// a compromised client can stay silent, but an honest one cannot do this unnoticed.
func (s *Server) clientAudit(c *rc) {
	var in struct {
		Event string `json:"event"`
		Count int    `json:"count"`
	}
	if !c.decode(&in, 1<<10) {
		return
	}
	switch in.Event {
	case "vault_export", "vault_export_encrypted", "vault_import_file":
	default:
		c.fail(http.StatusBadRequest, "bad_request", "Unknown event.")
		return
	}
	c.audit(s, in.Event, "success", "", map[string]string{"count": itoa(clampInt(in.Count, 0, 1000000))})
	c.ok(map[string]bool{"ok": true})
}

func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func containsByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}

var _ = store.RoleOwner

func writeJSON(c *rc, status int, v any) { httpx.JSON(c.W, status, v) }

// HasWebSession reports whether the request carries a live web session (used to redirect the shell to /login).
func (s *Server) HasWebSession(r *http.Request) bool {
	ck, err := r.Cookie(s.cookie)
	if err != nil {
		return false
	}
	sess, err := s.Store.GetSession(r.Context(), ck.Value, webIdle, extIdle)
	return err == nil && sess.Kind == "web" && !sess.Locked
}

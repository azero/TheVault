package automation

import (
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/store"
)

var (
	reSub     = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	reSession = regexp.MustCompile(`^[0-9a-f]{16}$`)
	reEvent   = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	// item events note which vault they happened in ("vault=space:<id>"); the id is shortened like a target is
	reSpaceInDetails = regexp.MustCompile(`(vault=space:[0-9a-f]{12})[0-9a-f]{20}`)
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// ---- parameters ----

func (c *call) badParam(name, why string) {
	c.fail(http.StatusBadRequest, "invalid_request", "Parameter "+name+" "+why+".")
}

// limit reads ?limit= (default 50, at most 200; larger values are treated as 200).
func (c *call) limit() (int, bool) {
	v := c.R.URL.Query().Get("limit")
	if v == "" {
		return defaultLimit, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		c.badParam("limit", "must be a whole number from 1 to 200")
		return 0, false
	}
	if n > maxLimit {
		n = maxLimit
	}
	return n, true
}

func (c *call) offset() (int, bool) {
	v := c.R.URL.Query().Get("offset")
	if v == "" {
		return 0, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 1000000 {
		c.badParam("offset", "must be a whole number from 0")
		return 0, false
	}
	return n, true
}

func (c *call) sub() (string, bool) {
	sub := c.R.PathValue("sub")
	if !reSub.MatchString(sub) {
		c.fail(http.StatusBadRequest, "invalid_request", "That is not a valid user id.")
		return "", false
	}
	return sub, true
}

// existingUser resolves {sub} to an account TheVault knows (404 otherwise).
func (c *call) existingUser() (*store.User, bool) {
	sub, ok := c.sub()
	if !ok {
		return nil, false
	}
	u, err := c.Server.Store.GetUser(c.R.Context(), sub)
	if err != nil {
		c.storeErr(err)
		return nil, false
	}
	return u, true
}

func (c *call) storeErr(err error) {
	if errors.Is(err, store.ErrNotFound) {
		c.fail(http.StatusNotFound, "not_found", "Not found.")
		return
	}
	log.Printf("automation api: %v", err)
	c.fail(http.StatusInternalServerError, "server_error", "Something went wrong on the server.")
}

// ---- whoami ----

func (s *Server) whoami(c *call) {
	p := c.P
	out := map[string]any{
		"sub": p.Subject, "principal": p.Type, "key_id": p.KeyID, "key_name": p.KeyName,
		"scopes": nonNil(strings.Fields(p.Scope)), "roles": nonNil(p.Roles),
	}
	if p.Name != "" {
		out["name"] = p.Name
	}
	if p.Email != "" {
		out["email"] = p.Email
	}
	c.json(http.StatusOK, out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---- status ----

// skynetStatus passes on the connection state only: not the agent id, the URL or the deny list.
func (s *Server) skynetStatus(c *call) map[string]any {
	if s.SkyNetStatus == nil {
		return map[string]any{"enabled": false}
	}
	m, _ := s.SkyNetStatus(c.R.Context()).(map[string]any)
	out := map[string]any{"enabled": m != nil}
	for _, k := range []string{"last_send", "last_error", "sent", "outbox", "dropped", "commands_enabled", "last_command", "command_error"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

func (s *Server) status(c *call) {
	ctx := c.R.Context()
	st, err := s.Store.Stats(ctx)
	if err != nil {
		c.storeErr(err)
		return
	}
	cur, latest, err := s.Store.SchemaVersions(ctx)
	if err != nil {
		c.storeErr(err)
		return
	}
	backups, err := s.Store.ListBackups()
	if err != nil {
		c.storeErr(err)
		return
	}
	type backup struct {
		Name     string `json:"name"`
		Bytes    int64  `json:"bytes"`
		Modified int64  `json:"modified"`
	}
	list := []backup{}
	for i, b := range backups {
		if i == 20 {
			break
		}
		list = append(list, backup{b.Name, b.Bytes, b.Modified})
	}
	sky := s.skynetStatus(c)
	problems := []string{}
	if e, _ := sky["last_error"].(string); e != "" {
		problems = append(problems, "skynet_events_failing")
	}
	if e, _ := sky["command_error"].(string); e != "" {
		problems = append(problems, "skynet_commands_failing")
	}
	state := "ok"
	if len(problems) > 0 {
		state = "degraded"
	}
	now := time.Now()
	// Counts are whole-server totals the administration overview already shows. Item and space counts are left out on
	// purpose: nothing about the size or shape of anyone's vault is needed for operations.
	c.json(http.StatusOK, map[string]any{
		"status": state, "problems": problems, "version": s.Version, "time": now.Unix(), "uptime_seconds": int64(now.Sub(s.start).Seconds()),
		"schema":   map[string]int{"current": cur, "latest": latest},
		"database": map[string]any{"bytes": st.DBBytes},
		"counts":   map[string]int{"users": st.Users, "vaults": st.Vaults, "sessions": st.Sessions, "audit_rows": st.AuditRows},
		"skynet":   sky,
		"backups":  map[string]any{"total": len(backups), "latest": list},
	})
}

// ---- users ----

type userJSON struct {
	Sub        string `json:"sub"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Role       string `json:"role"` // as of the person's last sign-in
	Locked     bool   `json:"locked"`
	LockedOut  bool   `json:"locked_out"` // temporary lockout after wrong master-password attempts
	HasVault   bool   `json:"has_vault"`
	Sessions   int    `json:"sessions"`
	FirstSeen  int64  `json:"first_seen"`
	LastLogin  int64  `json:"last_login"`
	LastUnlock int64  `json:"last_unlock"`
}

func toUser(u store.UserSummary, now int64) userJSON {
	return userJSON{u.Sub, u.Email, u.Name, u.Role, u.Locked, u.LockedUntil > now, u.HasVault, u.Sessions, u.FirstSeen, u.LastLogin, u.LastUnlock}
}

func (s *Server) listUsers(c *call) {
	limit, ok := c.limit()
	if !ok {
		return
	}
	q := c.R.URL.Query()
	cursor := q.Get("cursor")
	if cursor != "" && !reSub.MatchString(cursor) {
		c.badParam("cursor", "is not a cursor from a previous page")
		return
	}
	var locked *bool
	switch v := q.Get("locked"); v {
	case "":
	case "true", "false":
		b := v == "true"
		locked = &b
	default:
		c.badParam("locked", "must be true or false")
		return
	}
	rows, err := s.Store.UserSummaries(c.R.Context(), cursor, limit+1, locked)
	if err != nil {
		c.storeErr(err)
		return
	}
	var next any
	if len(rows) > limit {
		rows = rows[:limit]
		next = rows[limit-1].Sub
	}
	now := time.Now().Unix()
	out := make([]userJSON, 0, len(rows))
	for _, u := range rows {
		out = append(out, toUser(u, now))
	}
	c.json(http.StatusOK, map[string]any{"users": out, "next_cursor": next})
}

func (s *Server) getUser(c *call) {
	sub, ok := c.sub()
	if !ok {
		return
	}
	u, err := s.Store.UserSummaryBySub(c.R.Context(), sub)
	if err != nil {
		c.storeErr(err)
		return
	}
	c.json(http.StatusOK, toUser(*u, time.Now().Unix()))
}

// viaAPI marks the domain audit events (the ones the person sees in their own activity trail) as API-driven.
func (c *call) viaAPI(extra map[string]string) map[string]string {
	d := keyDetails(c.P)
	d["via"] = "api"
	for k, v := range extra {
		d[k] = v
	}
	return d
}

func (c *call) domainEvent(name, target string, details map[string]string) {
	actor, user := identity(c.P)
	c.Server.log(c.R, audit.Event{Name: name, Actor: actor, User: user, Target: target, IP: c.IP, UA: c.R.UserAgent(), Outcome: "success", Details: c.viaAPI(details)})
}

// lockUser is the administration screen's Lock: it refuses sign-in and ends every session. The screen forbids locking
// yourself; the API adds that a script (which has no "yourself") may not lock the last active administrator.
func (s *Server) lockUser(c *call) {
	if !c.noBody() {
		return
	}
	u, ok := c.existingUser()
	if !ok {
		return
	}
	ctx := c.R.Context()
	if c.P.IsUser() && u.Sub == c.P.Subject {
		c.fail(http.StatusConflict, "conflict", "You cannot lock your own account.")
		return
	}
	if u.Role == "admin" && !u.Locked {
		others, err := s.Store.OtherActiveAdmins(ctx, u.Sub)
		if err != nil {
			c.storeErr(err)
			return
		}
		if others == 0 {
			c.fail(http.StatusConflict, "conflict", "This is the last active administrator. Locking them would leave nobody to administer TheVault.")
			return
		}
	}
	if err := s.Store.SetUserLocked(ctx, u.Sub, true); err != nil {
		c.storeErr(err)
		return
	}
	n, _ := s.Store.DeleteUserSessions(ctx, u.Sub, "")
	c.domainEvent("admin_user_locked", u.Sub, map[string]string{"sessions_ended": itoa(n)})
	c.json(http.StatusOK, map[string]any{"ok": true, "locked": true, "sessions_ended": n})
}

func (s *Server) unlockUser(c *call) {
	if !c.noBody() {
		return
	}
	u, ok := c.existingUser()
	if !ok {
		return
	}
	if err := s.Store.SetUserLocked(c.R.Context(), u.Sub, false); err != nil {
		c.storeErr(err)
		return
	}
	c.domainEvent("admin_user_unlocked", u.Sub, nil)
	c.json(http.StatusOK, map[string]any{"ok": true, "locked": false})
}

// ---- sessions ----

func (s *Server) listSessions(c *call) {
	u, ok := c.existingUser()
	if !ok {
		return
	}
	limit, ok := c.limit()
	if !ok {
		return
	}
	offset, ok := c.offset()
	if !ok {
		return
	}
	list, err := s.Store.ListUserSessions(c.R.Context(), u.Sub)
	if err != nil {
		c.storeErr(err)
		return
	}
	type row struct {
		ID        string `json:"id"`
		Kind      string `json:"kind"` // web | ext
		Label     string `json:"label"`
		IP        string `json:"ip"`
		CreatedAt int64  `json:"created_at"`
		LastSeen  int64  `json:"last_seen"`
		ExpiresAt int64  `json:"expires_at"`
		Unlocked  bool   `json:"unlocked"`
	}
	now := time.Now().Unix()
	out := []row{}
	for i := offset; i < len(list) && len(out) < limit; i++ {
		x := list[i]
		out = append(out, row{x.PublicID(), x.Kind, x.Label, x.IP, x.CreatedAt, x.LastSeen, x.ExpiresAt, x.UnlockedUntil > now})
	}
	var next any
	if offset+len(out) < len(list) {
		next = offset + len(out)
	}
	c.json(http.StatusOK, map[string]any{"sessions": out, "total": len(list), "next_offset": next})
}

// revokeSessions is the administration screen's "End sessions": every web session and extension device of the person.
func (s *Server) revokeSessions(c *call) {
	if !c.noBody() {
		return
	}
	u, ok := c.existingUser()
	if !ok {
		return
	}
	n, err := s.Store.DeleteUserSessions(c.R.Context(), u.Sub, "")
	if err != nil {
		c.storeErr(err)
		return
	}
	c.domainEvent("admin_sessions_revoked", u.Sub, map[string]string{"count": itoa(n)})
	c.json(http.StatusOK, map[string]int{"revoked": n})
}

func (s *Server) revokeSession(c *call) {
	if !c.noBody() {
		return
	}
	u, ok := c.existingUser()
	if !ok {
		return
	}
	id := c.R.PathValue("id")
	if !reSession.MatchString(id) {
		c.fail(http.StatusBadRequest, "invalid_request", "That is not a session id.")
		return
	}
	found, err := s.Store.RevokeSessionByPublicID(c.R.Context(), u.Sub, id)
	if err != nil {
		c.storeErr(err)
		return
	}
	if !found {
		c.fail(http.StatusNotFound, "not_found", "That session no longer exists.")
		return
	}
	c.domainEvent("admin_sessions_revoked", u.Sub, map[string]string{"count": "1", "session": id})
	c.json(http.StatusOK, map[string]int{"revoked": 1})
}

// ---- audit ----

func (s *Server) listAudit(c *call) {
	limit, ok := c.limit()
	if !ok {
		return
	}
	q := c.R.URL.Query()
	f := store.AuditFilter{Limit: limit + 1}
	if v := q.Get("actor"); v != "" {
		if !reSub.MatchString(v) {
			c.badParam("actor", "is not a valid user id")
			return
		}
		f.Actor = v
	}
	if v := q.Get("event"); v != "" {
		if !reEvent.MatchString(v) {
			c.badParam("event", "is not an event name")
			return
		}
		f.Event = v
	}
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			c.badParam("since", "must be a unix time in seconds")
			return
		}
		f.Since = n
	}
	if v := q.Get("cursor"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			c.badParam("cursor", "is not a cursor from a previous page")
			return
		}
		f.BeforeID = n
	}
	rows, err := s.Store.AuditPage(c.R.Context(), f)
	if err != nil {
		c.storeErr(err)
		return
	}
	var next any
	if len(rows) > limit {
		rows = rows[:limit]
		next = strconv.FormatInt(rows[limit-1].ID, 10)
	}
	for i := range rows {
		rows[i].Target = shortTarget(rows[i].Event, rows[i].Target)
		rows[i].Details = reSpaceInDetails.ReplaceAllString(rows[i].Details, "${1}")
	}
	c.json(http.StatusOK, map[string]any{"events": rows, "next_cursor": next})
}

// shortTarget shortens the id of a vault object (an item or a space) to 12 characters, as the administration screen
// does: enough to recognise a repeat, not enough to address the object. Other targets (accounts, sessions) stay whole.
func shortTarget(event, target string) string {
	if (strings.HasPrefix(event, "item_") || strings.HasPrefix(event, "items_") || strings.HasPrefix(event, "space_")) && len(target) > 12 {
		return target[:12]
	}
	return target
}

// ---- SkyNet block list ----

func (s *Server) listBlocks(c *call) {
	limit, ok := c.limit()
	if !ok {
		return
	}
	offset, ok := c.offset()
	if !ok {
		return
	}
	deny, err := s.Store.DenyActive(c.R.Context())
	if err != nil {
		c.storeErr(err)
		return
	}
	type block struct {
		IP     string `json:"ip"`
		Until  int64  `json:"until"`
		Reason string `json:"reason"`
	}
	out := []block{}
	for i := offset; i < len(deny) && len(out) < limit; i++ {
		out = append(out, block{deny[i].IP, deny[i].Until, deny[i].Reason})
	}
	var next any
	if offset+len(out) < len(deny) {
		next = offset + len(out)
	}
	sky := s.skynetStatus(c)
	c.json(http.StatusOK, map[string]any{
		"enforced": sky["enabled"], "commands_enabled": sky["commands_enabled"] == true,
		"blocks": out, "total": len(deny), "next_offset": next,
	})
}

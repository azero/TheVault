package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/azero/thevault/server/internal/store"
)

// Administrators manage accounts and watch for abuse. Everything here is metadata (counts, times, addresses):
// there is no route that returns vault content, because the server does not have it in a readable form.

func (s *Server) adminOverview(c *rc) {
	ctx := c.R.Context()
	st, err := s.Store.Stats(ctx)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	users, err := s.Store.AdminUsers(ctx)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	type urow struct {
		Sub        string `json:"sub"`
		Email      string `json:"email"`
		Name       string `json:"name"`
		Role       string `json:"role"`
		Locked     bool   `json:"locked"`
		HasVault   bool   `json:"has_vault"`
		FirstSeen  int64  `json:"first_seen"`
		LastLogin  int64  `json:"last_login"`
		LastUnlock int64  `json:"last_unlock"`
		Items      int    `json:"items"`
		Spaces     int    `json:"spaces"`
		Sessions   int    `json:"sessions"`
		LockedOut  bool   `json:"locked_out"`
	}
	now := time.Now().Unix()
	rows := make([]urow, 0, len(users))
	for _, u := range users {
		rows = append(rows, urow{u.Sub, u.Email, u.Name, u.Role, u.Locked, u.HasVault, u.FirstSeen, u.LastLogin, u.LastUnlock, u.Items, u.Spaces, u.Sessions, u.LockedUntil > now})
	}
	var sky any
	if s.SkyNetStatus != nil {
		sky = s.SkyNetStatus(ctx)
	}
	c.ok(map[string]any{"stats": st, "users": rows, "skynet": sky, "version": s.Version})
}

func (s *Server) adminAudit(c *rc) {
	limit, _ := strconv.Atoi(c.R.URL.Query().Get("limit"))
	actor := c.R.URL.Query().Get("actor")
	if actor != "" && !reSub.MatchString(actor) {
		c.fail(http.StatusBadRequest, "bad_request", "Bad actor.")
		return
	}
	rows, err := s.Store.ListAudit(c.R.Context(), actor, limit)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	c.ok(map[string]any{"events": rows})
}

func (s *Server) adminTarget(c *rc) (string, bool) {
	sub := c.R.PathValue("sub")
	if !reSub.MatchString(sub) {
		c.fail(http.StatusBadRequest, "bad_request", "Bad user id.")
		return "", false
	}
	if _, err := s.Store.GetUser(c.R.Context(), sub); err != nil {
		s.storeErr(c, err)
		return "", false
	}
	return sub, true
}

func (s *Server) adminLockUser(c *rc) {
	sub, ok := s.adminTarget(c)
	if !ok {
		return
	}
	if sub == c.Sess.Sub {
		c.fail(http.StatusConflict, "self", "You cannot lock your own account.")
		return
	}
	ctx := c.R.Context()
	if err := s.Store.SetUserLocked(ctx, sub, true); err != nil {
		s.storeErr(c, err)
		return
	}
	n, _ := s.Store.DeleteUserSessions(ctx, sub, "")
	c.audit(s, "admin_user_locked", "success", sub, map[string]string{"sessions_ended": itoa(n)})
	c.ok(map[string]any{"ok": true, "sessions_ended": n})
}

func (s *Server) adminUnlockUser(c *rc) {
	sub, ok := s.adminTarget(c)
	if !ok {
		return
	}
	if err := s.Store.SetUserLocked(c.R.Context(), sub, false); err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "admin_user_unlocked", "success", sub, nil)
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) adminRevokeSessions(c *rc) {
	sub, ok := s.adminTarget(c)
	if !ok {
		return
	}
	keep := ""
	if sub == c.Sess.Sub {
		keep = c.Sess.IDHash
	}
	n, err := s.Store.DeleteUserSessions(c.R.Context(), sub, keep)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "admin_sessions_revoked", "success", sub, map[string]string{"count": itoa(n)})
	c.ok(map[string]int{"revoked": n})
}

// adminEraseVault destroys a user's ciphertext (for example after they lost both the master password and the recovery
// key). The admin must type the user's email or id to confirm. The user keeps their ClosedDoor access and can start over.
func (s *Server) adminEraseVault(c *rc) {
	sub, ok := s.adminTarget(c)
	if !ok {
		return
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if !c.decode(&in, 1<<10) {
		return
	}
	u, _ := s.Store.GetUser(c.R.Context(), sub)
	if in.Confirm == "" || (in.Confirm != u.Email && in.Confirm != sub) {
		c.fail(http.StatusBadRequest, "confirm", "Type the person's email address to confirm.")
		return
	}
	if err := s.Store.EraseVault(c.R.Context(), sub); err != nil {
		s.storeErr(c, err)
		return
	}
	n, _ := s.Store.DeleteUserSessions(c.R.Context(), sub, "")
	c.audit(s, "admin_vault_erased", "success", sub, map[string]string{"sessions_ended": itoa(n)})
	c.ok(map[string]bool{"ok": true})
}

var _ = store.RoleOwner

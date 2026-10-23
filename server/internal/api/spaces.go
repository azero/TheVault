package api

import (
	"net/http"
	"strings"

	"github.com/azero/thevault/server/internal/store"
)

type wrapIn struct {
	Eph string `json:"eph"`
	CT  string `json:"ct"`
	Sig string `json:"sig"`
}

func (w wrapIn) valid() bool {
	return rePub.MatchString(w.Eph) && isEnvelope(w.CT, maxSmallBlob) && reSig.MatchString(w.Sig)
}

func (w wrapIn) store(by string) store.Wrap {
	return store.Wrap{Eph: w.Eph, CT: w.CT, Sig: w.Sig, By: by}
}

func (s *Server) directory(c *rc) {
	if !s.dirRL.Allow(c.Sess.IDHash) {
		c.fail(http.StatusTooManyRequests, "rate_limited", "Too many searches.")
		return
	}
	q := strings.TrimSpace(c.R.URL.Query().Get("q"))
	if len(q) < 2 || len(q) > 100 {
		c.ok(map[string]any{"users": []any{}})
		return
	}
	us, err := s.Store.SearchUsers(c.R.Context(), q, 10)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	type row struct {
		Sub    string `json:"sub"`
		Name   string `json:"name"`
		Email  string `json:"email"`
		EncPub string `json:"enc_pub"`
		SigPub string `json:"sig_pub"`
	}
	out := make([]row, 0, len(us))
	for _, u := range us {
		if u.Sub != c.Sess.Sub {
			out = append(out, row{u.Sub, u.Name, u.Email, u.EncPub, u.SigPub})
		}
	}
	c.ok(map[string]any{"users": out})
}

func (s *Server) userKeys(c *rc) {
	sub := c.R.PathValue("sub")
	if !reSub.MatchString(sub) {
		c.fail(http.StatusBadRequest, "bad_request", "Bad user id.")
		return
	}
	u, err := s.Store.UserKeys(c.R.Context(), sub)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	c.ok(map[string]any{"sub": u.Sub, "name": u.Name, "email": u.Email, "enc_pub": u.EncPub, "sig_pub": u.SigPub})
}

func (s *Server) createSpace(c *rc) {
	var in struct {
		ID       string `json:"id"`
		NameBlob string `json:"name_blob"`
		Wrap     wrapIn `json:"wrap"`
	}
	if !c.decode(&in, 16<<10) {
		return
	}
	if !isID(in.ID) || !isEnvelope(in.NameBlob, maxSmallBlob) || !in.Wrap.valid() {
		c.fail(http.StatusBadRequest, "bad_request", "The space is malformed.")
		return
	}
	if err := s.Store.CreateSpace(c.R.Context(), store.NewSpace{ID: in.ID, NameBlob: in.NameBlob, Sub: c.Sess.Sub, Wrap: in.Wrap.store(c.Sess.Sub)}); err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "space_created", "success", in.ID, nil)
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) renameSpace(c *rc) {
	id := c.R.PathValue("id")
	var in struct {
		NameBlob string `json:"name_blob"`
	}
	if !c.decode(&in, 8<<10) {
		return
	}
	if !isID(id) || !isEnvelope(in.NameBlob, maxSmallBlob) {
		c.fail(http.StatusBadRequest, "bad_request", "The request is malformed.")
		return
	}
	if err := s.Store.RenameSpace(c.R.Context(), c.Sess.Sub, id, in.NameBlob); err != nil {
		s.storeErr(c, err)
		return
	}
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) deleteSpace(c *rc) {
	id := c.R.PathValue("id")
	if !isID(id) {
		c.fail(http.StatusBadRequest, "bad_request", "Bad space id.")
		return
	}
	n, err := s.Store.DeleteSpace(c.R.Context(), c.Sess.Sub, id)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "space_deleted", "success", id, map[string]string{"items": itoa(int(n))})
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) addMember(c *rc) {
	id := c.R.PathValue("id")
	var in struct {
		Sub        string `json:"sub"`
		Role       string `json:"role"`
		KeyVersion int    `json:"key_version"`
		Wrap       wrapIn `json:"wrap"`
	}
	if !c.decode(&in, 16<<10) {
		return
	}
	if !isID(id) || !reSub.MatchString(in.Sub) || !store.ValidRole(in.Role) || in.KeyVersion < 1 || !in.Wrap.valid() || in.Sub == c.Sess.Sub {
		c.fail(http.StatusBadRequest, "bad_request", "The request is malformed.")
		return
	}
	err := s.Store.AddSpaceMember(c.R.Context(), store.AddMember{SpaceID: id, ActorSub: c.Sess.Sub, Sub: in.Sub, Role: in.Role, KeyVersion: in.KeyVersion, Wrap: in.Wrap.store(c.Sess.Sub)})
	if err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "space_member_added", "success", id, map[string]string{"member": in.Sub, "role": in.Role})
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) setMemberRole(c *rc) {
	id, sub := c.R.PathValue("id"), c.R.PathValue("sub")
	var in struct {
		Role string `json:"role"`
	}
	if !c.decode(&in, 1<<10) {
		return
	}
	if !isID(id) || !reSub.MatchString(sub) || !store.ValidRole(in.Role) {
		c.fail(http.StatusBadRequest, "bad_request", "The request is malformed.")
		return
	}
	if err := s.Store.SetMemberRole(c.R.Context(), c.Sess.Sub, id, sub, in.Role); err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "space_member_role_changed", "success", id, map[string]string{"member": sub, "role": in.Role})
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) removeMember(c *rc) {
	id, sub := c.R.PathValue("id"), c.R.PathValue("sub")
	if !isID(id) || !reSub.MatchString(sub) {
		c.fail(http.StatusBadRequest, "bad_request", "The request is malformed.")
		return
	}
	if err := s.Store.RemoveMember(c.R.Context(), c.Sess.Sub, id, sub); err != nil {
		s.storeErr(c, err)
		return
	}
	name := "space_member_removed"
	if sub == c.Sess.Sub {
		name = "space_left"
	}
	c.audit(s, name, "success", id, map[string]string{"member": sub})
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) rotateSpace(c *rc) {
	id := c.R.PathValue("id")
	var in struct {
		KeyVersion int    `json:"key_version"`
		NameBlob   string `json:"name_blob"`
		Items      []struct {
			ID      string `json:"id"`
			BaseSeq int64  `json:"base_seq"`
			Blob    string `json:"blob"`
		} `json:"items"`
		Members []struct {
			Sub  string `json:"sub"`
			Wrap wrapIn `json:"wrap"`
		} `json:"members"`
	}
	if !c.decode(&in, 40<<20) {
		return
	}
	if !isID(id) || in.KeyVersion < 2 || !isEnvelope(in.NameBlob, maxSmallBlob) || len(in.Items) > 20000 || len(in.Members) == 0 || len(in.Members) > 200 {
		c.fail(http.StatusBadRequest, "bad_request", "The request is malformed.")
		return
	}
	r := store.Rotate{SpaceID: id, ActorSub: c.Sess.Sub, NameBlob: in.NameBlob, NewVersion: in.KeyVersion}
	for _, it := range in.Items {
		if !isID(it.ID) || it.BaseSeq < 1 || !isEnvelope(it.Blob, maxItemBlob) {
			c.fail(http.StatusBadRequest, "bad_request", "An item in the rotation is malformed.")
			return
		}
		r.Items = append(r.Items, store.RotateItem{ID: it.ID, BaseSeq: it.BaseSeq, Blob: it.Blob})
	}
	for _, m := range in.Members {
		if !reSub.MatchString(m.Sub) || !m.Wrap.valid() {
			c.fail(http.StatusBadRequest, "bad_request", "A member wrap is malformed.")
			return
		}
		r.Members = append(r.Members, store.RotateMember{Sub: m.Sub, Wrap: m.Wrap.store(c.Sess.Sub)})
	}
	if err := s.Store.RotateSpace(c.R.Context(), r); err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "space_key_rotated", "success", id, map[string]string{"items": itoa(len(in.Items)), "members": itoa(len(in.Members)), "version": itoa(in.KeyVersion)})
	c.ok(map[string]bool{"ok": true})
}

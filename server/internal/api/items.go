package api

import (
	"net/http"
	"strconv"
)

func (s *Server) sync(c *rc) {
	since, _ := strconv.ParseInt(c.R.URL.Query().Get("since"), 10, 64)
	if since < 0 {
		since = 0
	}
	res, err := s.Store.Sync(c.R.Context(), c.Sess.Sub, since)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	if since == 0 {
		// A full download is the thing an attacker with a stolen unlocked session does: make it visible.
		c.audit(s, "sync_full", "success", "", map[string]string{"items": itoa(len(res.Items)), "kind": c.Sess.Kind})
	}
	c.ok(res)
}

type putItemIn struct {
	VaultID    string `json:"vault_id"`
	BaseSeq    int64  `json:"base_seq"`
	KeyVersion int    `json:"key_version"`
	Blob       string `json:"blob"`
}

func (s *Server) putItem(c *rc) {
	id := c.R.PathValue("id")
	var in putItemIn
	if !c.decode(&in, maxItemBlob+4096) {
		return
	}
	if !isID(id) || !isVaultID(in.VaultID) || in.BaseSeq < 0 || in.KeyVersion < 1 || !isEnvelope(in.Blob, maxItemBlob) {
		c.fail(http.StatusBadRequest, "bad_request", "The item is malformed.")
		return
	}
	it, err := s.Store.PutItem(c.R.Context(), putItemParams(c, id, in, s.Cfg.MaxItemsPerUser))
	if err != nil {
		s.storeErr(c, err)
		return
	}
	name := "item_updated"
	if in.BaseSeq == 0 {
		name = "item_created"
	}
	c.audit(s, name, "success", id, map[string]string{"vault": auditVault(in.VaultID)})
	it.Blob = ""
	c.ok(it)
}

func auditVault(v string) string {
	if v == "personal" {
		return v
	}
	return "space:" + v
}

func (s *Server) deleteItem(c *rc) {
	id := c.R.PathValue("id")
	if !isID(id) {
		c.fail(http.StatusBadRequest, "bad_request", "Bad item id.")
		return
	}
	purge := c.R.URL.Query().Get("purge") == "1"
	it, err := s.Store.DeleteItem(c.R.Context(), c.Sess.Sub, id, purge)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	name := "item_deleted"
	if purge {
		name = "item_purged"
	}
	c.audit(s, name, "success", id, map[string]string{"vault": auditVault(it.VaultID)})
	c.ok(it)
}

func (s *Server) restoreItem(c *rc) {
	id := c.R.PathValue("id")
	if !isID(id) {
		c.fail(http.StatusBadRequest, "bad_request", "Bad item id.")
		return
	}
	it, err := s.Store.RestoreItem(c.R.Context(), c.Sess.Sub, id)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "item_restored", "success", id, nil)
	it.Blob = ""
	c.ok(it)
}

func (s *Server) itemVersions(c *rc) {
	id := c.R.PathValue("id")
	if !isID(id) {
		c.fail(http.StatusBadRequest, "bad_request", "Bad item id.")
		return
	}
	v, err := s.Store.ItemVersions(c.R.Context(), c.Sess.Sub, id)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	c.ok(map[string]any{"versions": v})
}

// importItems stores many new personal items at once. All or nothing.
func (s *Server) importItems(c *rc) {
	var in struct {
		KeyVersion int `json:"key_version"`
		Items      []struct {
			ID   string `json:"id"`
			Blob string `json:"blob"`
		} `json:"items"`
	}
	if !c.decode(&in, 40<<20) {
		return
	}
	if len(in.Items) == 0 || len(in.Items) > 500 || in.KeyVersion < 1 {
		c.fail(http.StatusBadRequest, "bad_request", "Import between 1 and 500 items per request.")
		return
	}
	seen := map[string]bool{}
	ps := make([]putItemT, 0, len(in.Items))
	for _, it := range in.Items {
		if !isID(it.ID) || seen[it.ID] || !isEnvelope(it.Blob, maxItemBlob) {
			c.fail(http.StatusBadRequest, "bad_request", "An item in the import is malformed.")
			return
		}
		seen[it.ID] = true
		ps = append(ps, putItemT{Sub: c.Sess.Sub, ID: it.ID, VaultID: "personal", Blob: it.Blob, KeyVersion: in.KeyVersion, MaxItems: s.Cfg.MaxItemsPerUser})
	}
	out, err := s.Store.ImportItems(c.R.Context(), ps)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "items_imported", "success", "", map[string]string{"count": itoa(len(out))})
	c.ok(map[string]any{"items": out})
}

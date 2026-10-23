package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const PersonalVault = "personal"

// Item is one encrypted record. The server never learns its type, name, URL or folder: all of that is inside Blob.
type Item struct {
	ID         string `json:"id"`
	VaultID    string `json:"vault_id"`
	Seq        int64  `json:"seq"`
	Blob       string `json:"blob,omitempty"`
	KeyVersion int    `json:"key_version"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
	DeletedAt  int64  `json:"deleted_at,omitempty"`
	Purged     bool   `json:"purged,omitempty"`
	UpdatedBy  string `json:"updated_by,omitempty"`
}

// ConflictError carries the current server copy so the client can merge or retry.
type ConflictError struct{ Current *Item }

func (e ConflictError) Error() string { return "the item changed on the server" }

const maxVersionsPerItem = 10

type PutItem struct {
	Sub, ID, VaultID string
	BaseSeq          int64
	Blob             string
	KeyVersion       int
	MaxItems         int // per-user cap on personal items (0 = unlimited)
}

// writableVault checks that sub may write to vaultID and returns the key version blobs must carry.
func writableVault(ctx context.Context, tx *sql.Tx, sub, vaultID string) (int, error) {
	if vaultID == PersonalVault {
		var v int
		err := tx.QueryRowContext(ctx, `SELECT key_version FROM vault_keys WHERE sub = ?`, sub).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrForbidden
		}
		return v, err
	}
	var role string
	var v int
	err := tx.QueryRowContext(ctx, `SELECT m.role, s.key_version FROM space_members m JOIN spaces s ON s.id = m.space_id WHERE m.space_id = ? AND m.sub = ?`, vaultID, sub).Scan(&role, &v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if role != RoleOwner && role != RoleEditor {
		return 0, ErrForbidden
	}
	return v, nil
}

func putItemTx(ctx context.Context, tx *sql.Tx, p PutItem) (*Item, error) {
	kv, err := writableVault(ctx, tx, p.Sub, p.VaultID)
	if err != nil {
		return nil, err
	}
	if p.KeyVersion != kv {
		return nil, ErrBadRequest
	}
	now := time.Now().Unix()
	var cur Item
	var purged int
	var owner string
	err = tx.QueryRowContext(ctx, `SELECT id,vault_id,seq,blob,key_version,created_at,updated_at,deleted_at,purged,owner_sub FROM items WHERE id = ?`, p.ID).
		Scan(&cur.ID, &cur.VaultID, &cur.Seq, &cur.Blob, &cur.KeyVersion, &cur.CreatedAt, &cur.UpdatedAt, &cur.DeletedAt, &purged, &owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if p.BaseSeq != 0 {
			return nil, ErrNotFound
		}
		if p.VaultID == PersonalVault && p.MaxItems > 0 {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM items WHERE owner_sub = ? AND vault_id = 'personal' AND purged = 0`, p.Sub).Scan(&n); err != nil {
				return nil, err
			}
			if n >= p.MaxItems {
				return nil, ErrLimit
			}
		}
		seq, err := nextSeq(ctx, tx)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO items(id,owner_sub,vault_id,seq,blob,key_version,created_at,updated_at,updated_by) VALUES (?,?,?,?,?,?,?,?,?)`,
			p.ID, p.Sub, p.VaultID, seq, p.Blob, p.KeyVersion, now, now, p.Sub); err != nil {
			return nil, err
		}
		return &Item{ID: p.ID, VaultID: p.VaultID, Seq: seq, Blob: p.Blob, KeyVersion: p.KeyVersion, CreatedAt: now, UpdatedAt: now}, nil
	case err != nil:
		return nil, err
	}
	// An id exists. It must live in the same vault and be reachable by this user, otherwise pretend it does not exist.
	if cur.VaultID != p.VaultID || (p.VaultID == PersonalVault && owner != p.Sub) {
		return nil, ErrNotFound
	}
	if purged != 0 || cur.DeletedAt != 0 {
		return nil, ErrBadRequest // restore from the trash first
	}
	if p.BaseSeq != cur.Seq {
		return nil, ConflictError{Current: &cur}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO item_versions(item_id,blob,key_version,saved_at,saved_by) VALUES (?,?,?,?,?)`, p.ID, cur.Blob, cur.KeyVersion, cur.UpdatedAt, p.Sub); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM item_versions WHERE item_id = ? AND id NOT IN (SELECT id FROM item_versions WHERE item_id = ? ORDER BY id DESC LIMIT `+itoa(maxVersionsPerItem)+`)`, p.ID, p.ID); err != nil {
		return nil, err
	}
	seq, err := nextSeq(ctx, tx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE items SET blob=?, seq=?, updated_at=?, updated_by=?, key_version=? WHERE id = ?`, p.Blob, seq, now, p.Sub, p.KeyVersion, p.ID); err != nil {
		return nil, err
	}
	return &Item{ID: p.ID, VaultID: p.VaultID, Seq: seq, Blob: p.Blob, KeyVersion: p.KeyVersion, CreatedAt: cur.CreatedAt, UpdatedAt: now}, nil
}

func (s *Store) PutItem(ctx context.Context, p PutItem) (*Item, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	it, err := putItemTx(ctx, tx, p)
	if err != nil {
		return nil, err
	}
	return it, tx.Commit()
}

// ImportItems creates many new personal items atomically (import). Every id must be new.
func (s *Store) ImportItems(ctx context.Context, ps []PutItem) ([]Item, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out := make([]Item, 0, len(ps))
	for _, p := range ps {
		p.BaseSeq = 0
		it, err := putItemTx(ctx, tx, p)
		if err != nil {
			return nil, err
		}
		it.Blob = ""
		out = append(out, *it)
	}
	return out, tx.Commit()
}

// itemAccess loads an item and checks sub may act on it. needWrite requires owner/editor in a space.
func itemAccess(ctx context.Context, tx *sql.Tx, sub, id string, needWrite bool) (*Item, error) {
	var it Item
	var purged int
	var owner string
	err := tx.QueryRowContext(ctx, `SELECT id,vault_id,seq,blob,key_version,created_at,updated_at,deleted_at,purged,owner_sub FROM items WHERE id = ?`, id).
		Scan(&it.ID, &it.VaultID, &it.Seq, &it.Blob, &it.KeyVersion, &it.CreatedAt, &it.UpdatedAt, &it.DeletedAt, &purged, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	it.Purged = purged != 0
	if it.VaultID == PersonalVault {
		if owner != sub {
			return nil, ErrNotFound
		}
		return &it, nil
	}
	var role string
	err = tx.QueryRowContext(ctx, `SELECT role FROM space_members WHERE space_id = ? AND sub = ?`, it.VaultID, sub).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if needWrite && role != RoleOwner && role != RoleEditor {
		return nil, ErrForbidden
	}
	return &it, nil
}

// DeleteItem moves an item to the trash, or (purge) removes its ciphertext for good while keeping a tombstone so other
// devices learn about it.
func (s *Store) DeleteItem(ctx context.Context, sub, id string, purge bool) (*Item, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	it, err := itemAccess(ctx, tx, sub, id, true)
	if err != nil {
		return nil, err
	}
	if it.Purged {
		return nil, ErrNotFound
	}
	seq, err := nextSeq(ctx, tx)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if purge {
		if _, err := tx.ExecContext(ctx, `UPDATE items SET blob='', purged=1, deleted_at=?, seq=?, updated_at=?, updated_by=? WHERE id = ?`, now, seq, now, sub, id); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM item_versions WHERE item_id = ?`, id); err != nil {
			return nil, err
		}
		it.Blob, it.Purged = "", true
	} else {
		if it.DeletedAt != 0 {
			return it, tx.Commit() // already in the trash
		}
		if _, err := tx.ExecContext(ctx, `UPDATE items SET deleted_at=?, seq=?, updated_at=?, updated_by=? WHERE id = ?`, now, seq, now, sub, id); err != nil {
			return nil, err
		}
		it.DeletedAt = now
	}
	it.Seq, it.UpdatedAt, it.Blob = seq, now, ""
	return it, tx.Commit()
}

func (s *Store) RestoreItem(ctx context.Context, sub, id string) (*Item, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	it, err := itemAccess(ctx, tx, sub, id, true)
	if err != nil {
		return nil, err
	}
	if it.Purged || it.DeletedAt == 0 {
		return nil, ErrNotFound
	}
	seq, err := nextSeq(ctx, tx)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `UPDATE items SET deleted_at=0, seq=?, updated_at=?, updated_by=? WHERE id = ?`, seq, now, sub, id); err != nil {
		return nil, err
	}
	it.DeletedAt, it.Seq, it.UpdatedAt = 0, seq, now
	return it, tx.Commit()
}

type Version struct {
	ID         int64  `json:"id"`
	Blob       string `json:"blob"`
	KeyVersion int    `json:"key_version"`
	SavedAt    int64  `json:"saved_at"`
}

func (s *Store) ItemVersions(ctx context.Context, sub, id string) ([]Version, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := itemAccess(ctx, tx, sub, id, false); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,blob,key_version,saved_at FROM item_versions WHERE item_id = ? ORDER BY id DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		var v Version
		if err := rows.Scan(&v.ID, &v.Blob, &v.KeyVersion, &v.SavedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

const syncPage = 2000

// SyncResult is what a client needs to bring its local copy up to date.
type SyncResult struct {
	Seq        int64   `json:"seq"`
	More       bool    `json:"more"`
	Items      []Item  `json:"items"`
	Spaces     []Space `json:"spaces"`
	KeyVersion int     `json:"key_version"`
}

// Sync returns the items visible to sub that changed after `since`, and always the full list of spaces.
func (s *Store) Sync(ctx context.Context, sub string, since int64) (*SyncResult, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var global int64
	if err := tx.QueryRowContext(ctx, `SELECT n FROM seq WHERE id = 1`).Scan(&global); err != nil {
		return nil, err
	}
	res := &SyncResult{Items: []Item{}}
	if err := tx.QueryRowContext(ctx, `SELECT key_version FROM vault_keys WHERE sub = ?`, sub).Scan(&res.KeyVersion); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,vault_id,seq,blob,key_version,created_at,updated_at,deleted_at,purged FROM items
		WHERE seq > ? AND seq <= ? AND ((vault_id = 'personal' AND owner_sub = ?) OR vault_id IN (SELECT space_id FROM space_members WHERE sub = ?))
		ORDER BY seq LIMIT `+itoa(syncPage+1), since, global, sub, sub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var it Item
		var purged int
		if err := rows.Scan(&it.ID, &it.VaultID, &it.Seq, &it.Blob, &it.KeyVersion, &it.CreatedAt, &it.UpdatedAt, &it.DeletedAt, &purged); err != nil {
			return nil, err
		}
		it.Purged = purged != 0
		res.Items = append(res.Items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(res.Items) > syncPage {
		res.Items, res.More = res.Items[:syncPage], true
		res.Seq = res.Items[syncPage-1].Seq
	} else {
		res.Seq = global
	}
	rows.Close()
	res.Spaces, err = spacesFor(ctx, tx, sub)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// PruneTombstones removes purged-item rows that every device has had ample time to see.
func (s *Store) PruneTombstones(ctx context.Context, olderThan time.Duration) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM items WHERE purged = 1 AND updated_at < ?`, time.Now().Add(-olderThan).Unix())
	return err
}

// PruneTrash permanently removes items that sat in the trash for longer than d (ciphertext only; tombstone stays).
func (s *Store) PruneTrash(ctx context.Context, d time.Duration) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	seq, err := nextSeq(ctx, tx)
	if err != nil {
		return 0, err
	}
	cut := time.Now().Add(-d).Unix()
	if _, err := tx.ExecContext(ctx, `DELETE FROM item_versions WHERE item_id IN (SELECT id FROM items WHERE deleted_at > 0 AND deleted_at < ? AND purged = 0)`, cut); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE items SET blob='', purged=1, seq=?, updated_at=? WHERE deleted_at > 0 AND deleted_at < ? AND purged = 0`, seq, time.Now().Unix(), cut)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, tx.Commit()
}

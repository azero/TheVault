package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	RoleOwner  = "owner"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

func ValidRole(r string) bool { return r == RoleOwner || r == RoleEditor || r == RoleViewer }

// Wrap is a space key sealed for one member (ephemeral ECDH + AES-GCM, signed by the sharer; see docs/crypto.md).
type Wrap struct {
	Eph string `json:"eph"`
	CT  string `json:"ct"`
	Sig string `json:"sig"`
	By  string `json:"by"`
}

type Member struct {
	Sub    string `json:"sub"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	EncPub string `json:"enc_pub"`
	SigPub string `json:"sig_pub"`
}

type Space struct {
	ID            string   `json:"id"`
	NameBlob      string   `json:"name_blob"`
	KeyVersion    int      `json:"key_version"`
	NeedsRotation bool     `json:"needs_rotation"`
	CreatedBy     string   `json:"created_by"`
	CreatedAt     int64    `json:"created_at"`
	Role          string   `json:"role"`
	Wrap          Wrap     `json:"wrap"`
	WrapVersion   int      `json:"wrap_key_version"`
	WrapByEncPub  string   `json:"wrap_by_enc_pub"`
	WrapBySigPub  string   `json:"wrap_by_sig_pub"`
	Members       []Member `json:"members"`
}

func spacesFor(ctx context.Context, tx *sql.Tx, sub string) ([]Space, error) {
	rows, err := tx.QueryContext(ctx, `SELECT s.id,s.name_blob,s.key_version,s.needs_rotation,s.created_by,s.created_at,m.role,m.wrap_eph,m.wrap_ct,m.wrap_sig,m.wrapped_by,m.key_version,COALESCE(vk.enc_pub,rk.enc_pub,''),COALESCE(vk.sig_pub,rk.sig_pub,'')
		FROM space_members m JOIN spaces s ON s.id = m.space_id LEFT JOIN vault_keys vk ON vk.sub = m.wrapped_by LEFT JOIN retired_keys rk ON rk.id = m.wrapped_by WHERE m.sub = ? ORDER BY s.created_at`, sub)
	if err != nil {
		return nil, err
	}
	out := []Space{}
	for rows.Next() {
		var sp Space
		var nr int
		if err := rows.Scan(&sp.ID, &sp.NameBlob, &sp.KeyVersion, &nr, &sp.CreatedBy, &sp.CreatedAt, &sp.Role, &sp.Wrap.Eph, &sp.Wrap.CT, &sp.Wrap.Sig, &sp.Wrap.By, &sp.WrapVersion, &sp.WrapByEncPub, &sp.WrapBySigPub); err != nil {
			rows.Close()
			return nil, err
		}
		sp.NeedsRotation = nr != 0
		out = append(out, sp)
	}
	rows.Close()
	for i := range out {
		mr, err := tx.QueryContext(ctx, `SELECT m.sub,COALESCE(u.name,''),COALESCE(u.email,''),m.role,COALESCE(vk.enc_pub,''),COALESCE(vk.sig_pub,'') FROM space_members m
			LEFT JOIN users u ON u.sub = m.sub LEFT JOIN vault_keys vk ON vk.sub = m.sub WHERE m.space_id = ? ORDER BY m.added_at`, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Members = []Member{}
		for mr.Next() {
			var m Member
			if err := mr.Scan(&m.Sub, &m.Name, &m.Email, &m.Role, &m.EncPub, &m.SigPub); err != nil {
				mr.Close()
				return nil, err
			}
			out[i].Members = append(out[i].Members, m)
		}
		mr.Close()
	}
	return out, nil
}

type NewSpace struct {
	ID, NameBlob, Sub string
	Wrap              Wrap
}

const maxSpacesPerUser = 100

func (s *Store) CreateSpace(ctx context.Context, n NewSpace) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var has int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM vault_keys WHERE sub = ?`, n.Sub).Scan(&has); err != nil || has == 0 {
		return ErrForbidden
	}
	var mine int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM spaces WHERE created_by = ?`, n.Sub).Scan(&mine); err != nil {
		return err
	}
	if mine >= maxSpacesPerUser {
		return ErrLimit
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `INSERT INTO spaces(id,name_blob,key_version,created_by,created_at) VALUES (?,?,1,?,?)`, n.ID, n.NameBlob, n.Sub, now); err != nil {
		if isUniqueViolation(err) {
			return ErrExists
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO space_members(space_id,sub,role,key_version,wrap_eph,wrap_ct,wrap_sig,wrapped_by,added_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		n.ID, n.Sub, RoleOwner, 1, n.Wrap.Eph, n.Wrap.CT, n.Wrap.Sig, n.Sub, now); err != nil {
		return err
	}
	return tx.Commit()
}

// roleIn returns sub's role in a space, ErrNotFound if not a member.
func roleIn(ctx context.Context, tx *sql.Tx, spaceID, sub string) (string, int, error) {
	var role string
	var kv int
	err := tx.QueryRowContext(ctx, `SELECT m.role, s.key_version FROM space_members m JOIN spaces s ON s.id = m.space_id WHERE m.space_id = ? AND m.sub = ?`, spaceID, sub).Scan(&role, &kv)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	return role, kv, err
}

func (s *Store) RenameSpace(ctx context.Context, sub, spaceID, nameBlob string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	role, _, err := roleIn(ctx, tx, spaceID, sub)
	if err != nil {
		return err
	}
	if role != RoleOwner {
		return ErrForbidden
	}
	if _, err := tx.ExecContext(ctx, `UPDATE spaces SET name_blob = ? WHERE id = ?`, nameBlob, spaceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteSpace(ctx context.Context, sub, spaceID string) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	role, _, err := roleIn(ctx, tx, spaceID, sub)
	if err != nil {
		return 0, err
	}
	if role != RoleOwner {
		return 0, ErrForbidden
	}
	var n int64
	tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM items WHERE vault_id = ? AND purged = 0`, spaceID).Scan(&n)
	// tombstones so other devices of members drop the items
	seq, err := nextSeq(ctx, tx)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `DELETE FROM item_versions WHERE item_id IN (SELECT id FROM items WHERE vault_id = ?)`, spaceID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE items SET blob='', purged=1, deleted_at=?, seq=?, updated_at=? WHERE vault_id = ?`, now, seq, now, spaceID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM spaces WHERE id = ?`, spaceID); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

type AddMember struct {
	SpaceID, ActorSub, Sub, Role string
	KeyVersion                   int
	Wrap                         Wrap
}

const maxMembers = 200

func (s *Store) AddSpaceMember(ctx context.Context, a AddMember) error {
	if !ValidRole(a.Role) {
		return ErrBadRequest
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	role, kv, err := roleIn(ctx, tx, a.SpaceID, a.ActorSub)
	if err != nil {
		return err
	}
	if role != RoleOwner {
		return ErrForbidden
	}
	var nr int
	tx.QueryRowContext(ctx, `SELECT needs_rotation FROM spaces WHERE id = ?`, a.SpaceID).Scan(&nr)
	if nr != 0 || a.KeyVersion != kv {
		return ErrBadRequest // rotate first: never hand the old key to a new member
	}
	var n int
	tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM space_members WHERE space_id = ?`, a.SpaceID).Scan(&n)
	if n >= maxMembers {
		return ErrLimit
	}
	var has int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM vault_keys vk JOIN users u ON u.sub = vk.sub WHERE vk.sub = ? AND u.locked = 0`, a.Sub).Scan(&has); err != nil || has == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO space_members(space_id,sub,role,key_version,wrap_eph,wrap_ct,wrap_sig,wrapped_by,added_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		a.SpaceID, a.Sub, a.Role, kv, a.Wrap.Eph, a.Wrap.CT, a.Wrap.Sig, a.ActorSub, time.Now().Unix()); err != nil {
		if isUniqueViolation(err) {
			return ErrExists
		}
		return err
	}
	return tx.Commit()
}

func ownerCount(ctx context.Context, tx *sql.Tx, spaceID string) int {
	var n int
	tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM space_members WHERE space_id = ? AND role = 'owner'`, spaceID).Scan(&n)
	return n
}

var ErrLastOwner = errors.New("a space needs at least one owner")

func (s *Store) SetMemberRole(ctx context.Context, actor, spaceID, sub, newRole string) error {
	if !ValidRole(newRole) {
		return ErrBadRequest
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	role, _, err := roleIn(ctx, tx, spaceID, actor)
	if err != nil {
		return err
	}
	if role != RoleOwner {
		return ErrForbidden
	}
	target, _, err := roleIn(ctx, tx, spaceID, sub)
	if err != nil {
		return err
	}
	if target == RoleOwner && newRole != RoleOwner && ownerCount(ctx, tx, spaceID) <= 1 {
		return ErrLastOwner
	}
	if _, err := tx.ExecContext(ctx, `UPDATE space_members SET role = ? WHERE space_id = ? AND sub = ?`, newRole, spaceID, sub); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveMember removes a member (an owner removing someone, or anyone leaving). The space is flagged so that the key must
// be rotated: the removed person still knows the old key.
func (s *Store) RemoveMember(ctx context.Context, actor, spaceID, sub string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	role, _, err := roleIn(ctx, tx, spaceID, actor)
	if err != nil {
		return err
	}
	if actor != sub && role != RoleOwner {
		return ErrForbidden
	}
	target, _, err := roleIn(ctx, tx, spaceID, sub)
	if err != nil {
		return err
	}
	if target == RoleOwner && ownerCount(ctx, tx, spaceID) <= 1 {
		return ErrLastOwner
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM space_members WHERE space_id = ? AND sub = ?`, spaceID, sub); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE spaces SET needs_rotation = 1 WHERE id = ?`, spaceID); err != nil {
		return err
	}
	return tx.Commit()
}

type RotateItem struct {
	ID      string
	BaseSeq int64
	Blob    string
}

type RotateMember struct {
	Sub  string
	Wrap Wrap
}

type Rotate struct {
	SpaceID, ActorSub, NameBlob string
	NewVersion                  int
	Items                       []RotateItem
	Members                     []RotateMember
}

// RotateSpace swaps the space key: every (non-purged) item is re-encrypted under the new key and every remaining member
// receives a new wrap, all in one transaction. The server cannot check the ciphertext, but it does check completeness
// so a half-finished rotation can never leave items undecryptable.
func (s *Store) RotateSpace(ctx context.Context, r Rotate) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	role, kv, err := roleIn(ctx, tx, r.SpaceID, r.ActorSub)
	if err != nil {
		return err
	}
	if role != RoleOwner {
		return ErrForbidden
	}
	if r.NewVersion != kv+1 {
		return ErrBadRequest
	}
	// members: exactly the current set
	cur := map[string]bool{}
	mr, err := tx.QueryContext(ctx, `SELECT sub FROM space_members WHERE space_id = ?`, r.SpaceID)
	if err != nil {
		return err
	}
	for mr.Next() {
		var sub string
		mr.Scan(&sub)
		cur[sub] = true
	}
	mr.Close()
	if len(r.Members) != len(cur) {
		return ErrBadRequest
	}
	for _, m := range r.Members {
		if !cur[m.Sub] {
			return ErrBadRequest
		}
		delete(cur, m.Sub)
	}
	// items: exactly the live set, at the sequence the client saw
	type row struct {
		seq int64
	}
	have := map[string]row{}
	ir, err := tx.QueryContext(ctx, `SELECT id, seq FROM items WHERE vault_id = ? AND purged = 0`, r.SpaceID)
	if err != nil {
		return err
	}
	for ir.Next() {
		var id string
		var seq int64
		ir.Scan(&id, &seq)
		have[id] = row{seq}
	}
	ir.Close()
	if len(r.Items) != len(have) {
		return ErrBadRequest
	}
	for _, it := range r.Items {
		h, ok := have[it.ID]
		if !ok {
			return ErrBadRequest
		}
		if h.seq != it.BaseSeq {
			return ConflictError{}
		}
		delete(have, it.ID)
	}
	now := time.Now().Unix()
	for _, it := range r.Items {
		seq, err := nextSeq(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE items SET blob=?, key_version=?, seq=?, updated_at=?, updated_by=? WHERE id = ?`, it.Blob, r.NewVersion, seq, now, r.ActorSub, it.ID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM item_versions WHERE item_id IN (SELECT id FROM items WHERE vault_id = ?)`, r.SpaceID); err != nil {
		return err
	}
	for _, m := range r.Members {
		if _, err := tx.ExecContext(ctx, `UPDATE space_members SET key_version=?, wrap_eph=?, wrap_ct=?, wrap_sig=?, wrapped_by=? WHERE space_id = ? AND sub = ?`,
			r.NewVersion, m.Wrap.Eph, m.Wrap.CT, m.Wrap.Sig, r.ActorSub, r.SpaceID, m.Sub); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE spaces SET key_version=?, needs_rotation=0, name_blob=? WHERE id = ?`, r.NewVersion, r.NameBlob, r.SpaceID); err != nil {
		return err
	}
	return tx.Commit()
}

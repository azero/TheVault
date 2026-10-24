package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Read models for the automation API. They carry the same metadata the administration screens already show and
// nothing else: no item, folder or space content, and no per-person item or space counts.

// UserSummary is one account as an administrator sees it.
type UserSummary struct {
	User
	HasVault    bool
	LastUnlock  int64
	LockedUntil int64 // password lockout (unlock attempts), not the admin lock
	Sessions    int
}

const userSummarySQL = `
SELECT u.sub,u.email,u.name,u.role,u.first_seen,u.last_login,u.locked,
       (vk.sub IS NOT NULL), COALESCE(vk.last_unlock,0), COALESCE(vk.locked_until,0),
       (SELECT COUNT(*) FROM sessions se WHERE se.sub = u.sub AND se.expires_at > ?)
FROM users u LEFT JOIN vault_keys vk ON vk.sub = u.sub `

func scanUserSummary(row interface{ Scan(...any) error }) (*UserSummary, error) {
	var r UserSummary
	var locked, has int
	if err := row.Scan(&r.Sub, &r.Email, &r.Name, &r.Role, &r.FirstSeen, &r.LastLogin, &locked, &has, &r.LastUnlock, &r.LockedUntil, &r.Sessions); err != nil {
		return nil, err
	}
	r.Locked, r.HasVault = locked != 0, has != 0
	return &r, nil
}

// UserSummaries pages through accounts in sub order (keyset pagination: pass the last sub of the previous page).
// locked, when not nil, keeps only locked or only unlocked accounts. limit is inlined, so it must be validated by the caller.
func (s *Store) UserSummaries(ctx context.Context, afterSub string, limit int, locked *bool) ([]UserSummary, error) {
	if limit < 1 || limit > 1000 {
		limit = 50
	}
	q := userSummarySQL + `WHERE u.sub > ? `
	args := []any{time.Now().Unix(), afterSub}
	if locked != nil {
		q += `AND u.locked = ? `
		args = append(args, boolInt(*locked))
	}
	rows, err := s.DB.QueryContext(ctx, q+`ORDER BY u.sub LIMIT `+itoa(limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserSummary{}
	for rows.Next() {
		r, err := scanUserSummary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// UserSummaryBySub returns one account, or ErrNotFound.
func (s *Store) UserSummaryBySub(ctx context.Context, sub string) (*UserSummary, error) {
	r, err := scanUserSummary(s.DB.QueryRowContext(ctx, userSummarySQL+`WHERE u.sub = ?`, time.Now().Unix(), sub))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// OtherActiveAdmins counts accounts with the admin role that are not locked, other than `exceptSub`.
func (s *Store) OtherActiveAdmins(ctx context.Context, exceptSub string) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND locked = 0 AND sub <> ?`, exceptSub).Scan(&n)
	return n, err
}

// AuditFilter narrows AuditPage. Zero values mean "no filter".
type AuditFilter struct {
	Actor    string // matches actor or target, like the administration screen
	Event    string
	Since    int64 // unix seconds, inclusive
	BeforeID int64 // keyset cursor: only rows with a smaller id
	Limit    int
}

// AuditPage returns audit rows newest first. Limit is inlined, so it is clamped here.
func (s *Store) AuditPage(ctx context.Context, f AuditFilter) ([]AuditRow, error) {
	limit := f.Limit
	if limit < 1 || limit > 1000 {
		limit = 50
	}
	var where []string
	var args []any
	if f.Actor != "" {
		where = append(where, `(actor = ? OR target = ?)`)
		args = append(args, f.Actor, f.Actor)
	}
	if f.Event != "" {
		where = append(where, `event = ?`)
		args = append(args, f.Event)
	}
	if f.Since > 0 {
		where = append(where, `created_at >= ?`)
		args = append(args, f.Since)
	}
	if f.BeforeID > 0 {
		where = append(where, `id < ?`)
		args = append(args, f.BeforeID)
	}
	q := `SELECT id,created_at,event,actor,target,ip,user_agent,outcome,details FROM audit_log `
	if len(where) > 0 {
		q += `WHERE ` + strings.Join(where, ` AND `) + ` `
	}
	rows, err := s.DB.QueryContext(ctx, q+`ORDER BY id DESC LIMIT `+itoa(limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditRow{}
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.ID, &r.CreatedAt, &r.Event, &r.Actor, &r.Target, &r.IP, &r.UserAgent, &r.Outcome, &r.Details); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SchemaVersions reports the schema the database is at and the newest one this build knows.
func (s *Store) SchemaVersions(ctx context.Context) (current, latest int, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&current)
	return current, len(migrations), err
}

// BackupInfo is the metadata of one snapshot written by `thevault backup`. Never its path or contents.
type BackupInfo struct {
	Name     string
	Bytes    int64
	Modified int64
}

// ListBackups returns the snapshots in the data directory's backups folder, newest first.
func (s *Store) ListBackups() ([]BackupInfo, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "backups"))
	if err != nil {
		if os.IsNotExist(err) {
			return []BackupInfo{}, nil
		}
		return nil, err
	}
	out := []BackupInfo{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "vault-") || !strings.HasSuffix(name, ".db") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupInfo{Name: name, Bytes: fi.Size(), Modified: fi.ModTime().Unix()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

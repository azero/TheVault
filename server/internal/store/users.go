package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type User struct {
	Sub, Email, Name, Role string
	FirstSeen, LastLogin   int64
	Locked                 bool
	UnlockIdleMinutes      int
}

// UpsertUser records a sign-in. The admin lock is never touched here.
func (s *Store) UpsertUser(ctx context.Context, u User) error {
	now := time.Now().Unix()
	_, err := s.DB.ExecContext(ctx, `INSERT INTO users(sub,email,name,role,first_seen,last_login) VALUES (?,?,?,?,?,?)
		ON CONFLICT(sub) DO UPDATE SET email=excluded.email, name=excluded.name, role=excluded.role, last_login=excluded.last_login`,
		u.Sub, clip(u.Email, 320), clip(u.Name, 200), u.Role, now, now)
	return err
}

func (s *Store) GetUser(ctx context.Context, sub string) (*User, error) {
	var u User
	var locked int
	err := s.DB.QueryRowContext(ctx, `SELECT sub,email,name,role,first_seen,last_login,locked,unlock_idle_minutes FROM users WHERE sub = ?`, sub).
		Scan(&u.Sub, &u.Email, &u.Name, &u.Role, &u.FirstSeen, &u.LastLogin, &locked, &u.UnlockIdleMinutes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	u.Locked = locked != 0
	return &u, err
}

func (s *Store) SetUserLocked(ctx context.Context, sub string, locked bool) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE users SET locked = ? WHERE sub = ?`, boolInt(locked), sub)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetUnlockIdle(ctx context.Context, sub string, minutes int) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET unlock_idle_minutes = ? WHERE sub = ?`, minutes, sub)
	return err
}

// AdminUserRow is what the admin overview shows. It contains no vault content, only counts.
type AdminUserRow struct {
	User
	HasVault    bool
	LastUnlock  int64
	Items       int
	Sessions    int
	Spaces      int
	LockedUntil int64
}

func (s *Store) AdminUsers(ctx context.Context) ([]AdminUserRow, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT u.sub,u.email,u.name,u.role,u.first_seen,u.last_login,u.locked,
       (vk.sub IS NOT NULL), COALESCE(vk.last_unlock,0), COALESCE(vk.locked_until,0),
       (SELECT COUNT(*) FROM items i WHERE i.owner_sub = u.sub AND i.vault_id = 'personal' AND i.purged = 0 AND i.deleted_at = 0),
       (SELECT COUNT(*) FROM sessions se WHERE se.sub = u.sub AND se.expires_at > ?),
       (SELECT COUNT(*) FROM space_members sm WHERE sm.sub = u.sub)
FROM users u LEFT JOIN vault_keys vk ON vk.sub = u.sub ORDER BY u.last_login DESC`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminUserRow
	for rows.Next() {
		var r AdminUserRow
		var locked, has int
		if err := rows.Scan(&r.Sub, &r.Email, &r.Name, &r.Role, &r.FirstSeen, &r.LastLogin, &locked, &has, &r.LastUnlock, &r.LockedUntil, &r.Items, &r.Sessions, &r.Spaces); err != nil {
			return nil, err
		}
		r.Locked, r.HasVault = locked != 0, has != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

type Stats struct {
	Users, Vaults, Items, Spaces, Sessions, AuditRows, Outbox int
	DBBytes                                                   int64
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	err := s.DB.QueryRowContext(ctx, `SELECT
 (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM vault_keys),
 (SELECT COUNT(*) FROM items WHERE purged = 0 AND deleted_at = 0), (SELECT COUNT(*) FROM spaces),
 (SELECT COUNT(*) FROM sessions WHERE expires_at > ?), (SELECT COUNT(*) FROM audit_log), (SELECT COUNT(*) FROM outbox)`, time.Now().Unix()).
		Scan(&st.Users, &st.Vaults, &st.Items, &st.Spaces, &st.Sessions, &st.AuditRows, &st.Outbox)
	st.DBBytes = s.Size()
	return st, err
}

// SearchUsers is the directory used when sharing a space: people who already have a vault (and so a public key).
func (s *Store) SearchUsers(ctx context.Context, q string, limit int) ([]DirectoryUser, error) {
	like := "%" + escapeLike(q) + "%"
	rows, err := s.DB.QueryContext(ctx, `SELECT u.sub,u.name,u.email,vk.enc_pub,vk.sig_pub FROM users u JOIN vault_keys vk ON vk.sub = u.sub
		WHERE u.locked = 0 AND (u.email LIKE ? ESCAPE '\' OR u.name LIKE ? ESCAPE '\') ORDER BY u.name, u.email LIMIT `+itoa(limit), like, like)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryUser
	for rows.Next() {
		var d DirectoryUser
		if err := rows.Scan(&d.Sub, &d.Name, &d.Email, &d.EncPub, &d.SigPub); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type DirectoryUser struct{ Sub, Name, Email, EncPub, SigPub string }

func (s *Store) UserKeys(ctx context.Context, sub string) (*DirectoryUser, error) {
	var d DirectoryUser
	err := s.DB.QueryRowContext(ctx, `SELECT u.sub,u.name,u.email,vk.enc_pub,vk.sig_pub FROM users u JOIN vault_keys vk ON vk.sub = u.sub WHERE u.sub = ? AND u.locked = 0`, sub).
		Scan(&d.Sub, &d.Name, &d.Email, &d.EncPub, &d.SigPub)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &d, err
}

func escapeLike(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' || s[i] == '_' || s[i] == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(out)
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

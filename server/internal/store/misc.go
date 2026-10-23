package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ---- audit ----

type AuditRow struct {
	ID        int64  `json:"id"`
	CreatedAt int64  `json:"created_at"`
	Event     string `json:"event"`
	Actor     string `json:"actor"`
	Target    string `json:"target"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Outcome   string `json:"outcome"`
	Details   string `json:"details"`
}

// InsertAudit records a security-relevant action. Failures are swallowed on purpose: auditing must never break the action.
func (s *Store) InsertAudit(ctx context.Context, r AuditRow) {
	s.DB.ExecContext(ctx, `INSERT INTO audit_log(created_at,event,actor,target,ip,user_agent,outcome,details) VALUES (?,?,?,?,?,?,?,?)`,
		time.Now().Unix(), clip(r.Event, 64), clip(r.Actor, 200), clip(r.Target, 200), clip(r.IP, 64), clip(r.UserAgent, 300), clip(r.Outcome, 16), clip(r.Details, 2000))
}

// ListAudit returns the newest rows, optionally only those where actor == sub (a user's own security activity).
func (s *Store) ListAudit(ctx context.Context, actor string, limit int) ([]AuditRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id,created_at,event,actor,target,ip,user_agent,outcome,details FROM audit_log `
	var args []any
	if actor != "" {
		q += `WHERE actor = ? OR target = ? `
		args = append(args, actor, actor)
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

func (s *Store) PruneAudit(ctx context.Context, older time.Duration) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM audit_log WHERE created_at < ?`, time.Now().Add(-older).Unix())
	return err
}

// ---- settings ----

func (s *Store) Setting(ctx context.Context, key, def string) string {
	var v string
	if err := s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

func (s *Store) SetSetting(ctx context.Context, key, value, actor string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at,updated_by) VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		key, value, time.Now().Unix(), actor)
	return err
}

// ---- extension sign-in codes ----

type ExtCode struct {
	Sub, Email, Name, Role, Challenge, Redirect, AccessToken string
	TokenExpiry                                              int64
}

// CreateExtCode stores a one-time code (valid 60 s) minted after an SSO sign-in that was started by the extension.
func (s *Store) CreateExtCode(ctx context.Context, c ExtCode) (string, error) {
	code := "vxc_" + RandomToken(24)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO ext_codes(code_hash,sub,email,name,role,challenge,redirect,access_token,token_expiry,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		Hash(code), c.Sub, c.Email, c.Name, c.Role, c.Challenge, c.Redirect, c.AccessToken, c.TokenExpiry, time.Now().Add(60*time.Second).Unix())
	return code, err
}

// ConsumeExtCode atomically burns the code and returns it. A used or expired code is ErrNotFound.
func (s *Store) ConsumeExtCode(ctx context.Context, code string) (*ExtCode, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var c ExtCode
	var exp int64
	err = tx.QueryRowContext(ctx, `SELECT sub,email,name,role,challenge,redirect,access_token,token_expiry,expires_at FROM ext_codes WHERE code_hash = ?`, Hash(code)).
		Scan(&c.Sub, &c.Email, &c.Name, &c.Role, &c.Challenge, &c.Redirect, &c.AccessToken, &c.TokenExpiry, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ext_codes WHERE code_hash = ?`, Hash(code)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if time.Now().Unix() > exp {
		return nil, ErrNotFound
	}
	return &c, nil
}

// ---- SkyNet outbox ----

type OutboxRow struct {
	ID      int64
	Payload string
}

func (s *Store) OutboxPush(ctx context.Context, payload string, max int) error {
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO outbox(created_at,payload) VALUES (?,?)`, time.Now().Unix(), payload); err != nil {
		return err
	}
	// bounded: when SkyNet is unreachable for a long time the oldest events are dropped first
	_, err := s.DB.ExecContext(ctx, `DELETE FROM outbox WHERE id <= (SELECT COALESCE(MAX(id),0) FROM outbox) - ?`, max)
	return err
}

func (s *Store) OutboxPeek(ctx context.Context, n int) ([]OutboxRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,payload FROM outbox ORDER BY id LIMIT `+itoa(n))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxRow
	for rows.Next() {
		var r OutboxRow
		if err := rows.Scan(&r.ID, &r.Payload); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) OutboxAck(ctx context.Context, upToID int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM outbox WHERE id <= ?`, upToID)
	return err
}

func (s *Store) OutboxCount(ctx context.Context) int {
	var n int
	s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&n)
	return n
}

// ---- deny list (SkyNet block_ip) ----

type Deny struct {
	IP        string
	Until     int64
	Reason    string
	CommandID int64
}

func (s *Store) DenyAdd(ctx context.Context, d Deny) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO deny_list(ip,until,reason,command_id) VALUES (?,?,?,?) ON CONFLICT(ip) DO UPDATE SET until=excluded.until, reason=excluded.reason, command_id=excluded.command_id`,
		d.IP, d.Until, clip(d.Reason, 300), d.CommandID)
	return err
}

func (s *Store) DenyRemove(ctx context.Context, ip string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM deny_list WHERE ip = ?`, ip)
	return err
}

func (s *Store) DenyActive(ctx context.Context) ([]Deny, error) {
	now := time.Now().Unix()
	s.DB.ExecContext(ctx, `DELETE FROM deny_list WHERE until <= ?`, now)
	rows, err := s.DB.QueryContext(ctx, `SELECT ip,until,reason,command_id FROM deny_list ORDER BY until DESC LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Deny
	for rows.Next() {
		var d Deny
		if err := rows.Scan(&d.IP, &d.Until, &d.Reason, &d.CommandID); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// CommandSeen records a SkyNet command id before it is acted on and reports whether it was already recorded (replay).
func (s *Store) CommandSeen(ctx context.Context, id int64) (already bool, err error) {
	res, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO command_seen(id,seen_at) VALUES (?,?)`, id, time.Now().Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	s.DB.ExecContext(ctx, `DELETE FROM command_seen WHERE id NOT IN (SELECT id FROM command_seen ORDER BY id DESC LIMIT 2000)`)
	return n == 0, nil
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"
)

// Read models for the OmniCore widgets (docs/omnicore.md). Like the administration screens they carry counts, times and
// names a person chose themselves, and nothing else: no query here selects a blob, a key, a proof, a hash, a token or an
// address. Every method is read-only.

// VaultMeta is the state of a person's vault as the server knows it.
type VaultMeta struct {
	CreatedAt, UpdatedAt, LastUnlock, LockedUntil int64
	FailedUnlocks                                 int
	RecoveryConfigured                            bool
}

// VaultMeta returns ErrNotFound when the person has not created a vault yet.
func (s *Store) VaultMeta(ctx context.Context, sub string) (*VaultMeta, error) {
	var m VaultMeta
	var rec int
	err := s.DB.QueryRowContext(ctx, `SELECT created_at,updated_at,last_unlock,locked_until,failed_unlocks,(recovery_hash <> '') FROM vault_keys WHERE sub = ?`, sub).
		Scan(&m.CreatedAt, &m.UpdatedAt, &m.LastUnlock, &m.LockedUntil, &m.FailedUnlocks, &rec)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	m.RecoveryConfigured = rec != 0
	return &m, err
}

// SessionMeta is one live session as the person's own device list shows it, without the address, agent or any token.
type SessionMeta struct {
	Kind, Label, Role              string
	CreatedAt, LastSeen, ExpiresAt int64
}

func (s *Store) SessionMetas(ctx context.Context, sub string, limit int) ([]SessionMeta, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT kind,label,role,created_at,last_seen,expires_at FROM sessions WHERE sub = ? AND expires_at > ? ORDER BY last_seen DESC LIMIT `+itoa(limit),
		sub, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionMeta
	for rows.Next() {
		var x SessionMeta
		if err := rows.Scan(&x.Kind, &x.Label, &x.Role, &x.CreatedAt, &x.LastSeen, &x.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// SpaceCounts says how many shared spaces a person belongs to, how many of them they own, and how many of those are
// waiting for a key rotation. Space names are encrypted and never read here.
type SpaceCounts struct{ Member, Owned, NeedRotation int }

func (s *Store) SpaceCountsFor(ctx context.Context, sub string) (SpaceCounts, error) {
	var c SpaceCounts
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN m.role = 'owner' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN m.role = 'owner' AND s.needs_rotation <> 0 THEN 1 ELSE 0 END),0)
		FROM space_members m JOIN spaces s ON s.id = m.space_id WHERE m.sub = ?`, sub).Scan(&c.Member, &c.Owned, &c.NeedRotation)
	return c, err
}

// SpaceOwnersNeedingRotation returns the owners of a space that is flagged for rotation, minus `except` (the person who
// just left or was removed). Used to tell them; empty when the space was already rotated or no longer exists.
func (s *Store) SpaceOwnersNeedingRotation(ctx context.Context, spaceID, except string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT m.sub FROM space_members m JOIN spaces s ON s.id = m.space_id
		WHERE m.space_id = ? AND m.role = 'owner' AND s.needs_rotation <> 0 AND m.sub <> ? ORDER BY m.sub LIMIT 200`, spaceID, except)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// ItemCounts are the numbers of live and trashed items in a person's personal vault.
type ItemCounts struct{ Active, Trashed int }

func (s *Store) PersonalItemCounts(ctx context.Context, sub string) (ItemCounts, error) {
	var c ItemCounts
	err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN deleted_at = 0 THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN deleted_at <> 0 THEN 1 ELSE 0 END),0)
		FROM items WHERE owner_sub = ? AND vault_id = 'personal' AND purged = 0`, sub).Scan(&c.Active, &c.Trashed)
	return c, err
}

// AuditBrief is one audit row without address, agent or target: what a widget may show a person about their own account.
type AuditBrief struct {
	CreatedAt      int64
	Event, Outcome string
	Details        string
}

// RecentAuditByEvents returns the person's own newest rows for the given event names since `since`, newest first. It
// matches the actor only (the person's own actions), and each name is one indexed lookup.
func (s *Store) RecentAuditByEvents(ctx context.Context, actor string, events []string, since int64, limit int) ([]AuditBrief, error) {
	var out []AuditBrief
	for _, ev := range events {
		rows, err := s.DB.QueryContext(ctx, `SELECT created_at,event,outcome,details FROM audit_log WHERE event = ? AND created_at >= ? AND actor = ? ORDER BY created_at DESC LIMIT `+itoa(limit), ev, since, actor)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var a AuditBrief
			if err := rows.Scan(&a.CreatedAt, &a.Event, &a.Outcome, &a.Details); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, a)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// CountAuditBuckets counts audit rows of one event name since `since`, grouped into buckets of `bucket` seconds (bucket
// start => count). actor "" counts everyone (the administrators' operational series); otherwise only that person.
func (s *Store) CountAuditBuckets(ctx context.Context, event, actor string, since, bucket int64) (map[int64]int, error) {
	q := `SELECT (created_at / ?) * ?, COUNT(*) FROM audit_log WHERE event = ? AND created_at >= ? `
	args := []any{bucket, bucket, event, since}
	if actor != "" {
		q += `AND actor = ? `
		args = append(args, actor)
	}
	rows, err := s.DB.QueryContext(ctx, q+`GROUP BY 1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var t int64
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, rows.Err()
}

// OperationalCounts are the numbers on the administrators' overview.
type OperationalCounts struct {
	Active, Locked, Admins, Vaults int
	WebSessions, ExtSessions       int
	PasswordLockedOut              int // accounts currently in an unlock lockout
}

func (s *Store) OperationalCounts(ctx context.Context) (OperationalCounts, error) {
	var c OperationalCounts
	now := time.Now().Unix()
	err := s.DB.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM users WHERE locked = 0), (SELECT COUNT(*) FROM users WHERE locked <> 0),
		(SELECT COUNT(*) FROM users WHERE locked = 0 AND role = 'admin'), (SELECT COUNT(*) FROM vault_keys),
		(SELECT COUNT(*) FROM sessions WHERE expires_at > ? AND kind = 'web'), (SELECT COUNT(*) FROM sessions WHERE expires_at > ? AND kind = 'ext'),
		(SELECT COUNT(*) FROM vault_keys WHERE locked_until > ?)`, now, now, now).
		Scan(&c.Active, &c.Locked, &c.Admins, &c.Vaults, &c.WebSessions, &c.ExtSessions, &c.PasswordLockedOut)
	return c, err
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"github.com/azero/thevault/server/internal/appnav"
	"time"
)

type Session struct {
	Apps                                                             []appnav.App
	IDHash, Sub, Kind, Label, Role, CSRF, IP, UserAgent, AccessToken string
	CreatedAt, LastSeen, ExpiresAt, CheckedAt, TokenExpiry           int64
	UnlockedUntil                                                    int64
	Email, Name                                                      string
	Locked                                                           bool // the user is locked by an admin
	UnlockIdleMinutes                                                int
}

// PublicID is a stable, non-secret handle for listing/revoking sessions in the UI.
func (s *Session) PublicID() string { return s.IDHash[:16] }

var ErrNoSession = errors.New("no session")

type NewSession struct {
	Apps                                               []appnav.App
	Sub, Kind, Label, Role, IP, UserAgent, AccessToken string
	TokenExpiry                                        time.Time
	Idle, Absolute                                     time.Duration
	UnlockedUntil                                      int64 // carried over when an extension session is renewed
	Prefix                                             string
}

// CreateSession stores a new session and returns the opaque bearer/cookie value (only its hash is kept).
func (s *Store) CreateSession(ctx context.Context, n NewSession) (token, csrf string, err error) {
	token = n.Prefix + RandomToken(32)
	csrf = RandomToken(24)
	now := time.Now()
	_, err = s.DB.ExecContext(ctx, `INSERT INTO sessions(id_hash,sub,kind,label,role,csrf,created_at,last_seen,expires_at,checked_at,access_token,token_expiry,ip,user_agent,unlocked_until,apps)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		Hash(token), n.Sub, n.Kind, clip(n.Label, 120), n.Role, csrf, now.Unix(), now.Unix(), now.Add(n.Absolute).Unix(), now.Unix(), n.AccessToken, n.TokenExpiry.Unix(),
		clip(n.IP, 64), clip(n.UserAgent, 300), n.UnlockedUntil, appnav.Encode(n.Apps))
	return token, csrf, err
}

const sessCols = `s.id_hash,s.sub,s.kind,s.label,s.role,s.csrf,s.created_at,s.last_seen,s.expires_at,s.checked_at,s.access_token,s.token_expiry,s.ip,s.user_agent,s.unlocked_until,COALESCE(u.email,''),COALESCE(u.name,''),COALESCE(u.locked,0),COALESCE(u.unlock_idle_minutes,0),s.apps`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var x Session
	var locked int
	var rawApps string
	err := row.Scan(&x.IDHash, &x.Sub, &x.Kind, &x.Label, &x.Role, &x.CSRF, &x.CreatedAt, &x.LastSeen, &x.ExpiresAt, &x.CheckedAt, &x.AccessToken, &x.TokenExpiry,
		&x.IP, &x.UserAgent, &x.UnlockedUntil, &x.Email, &x.Name, &locked, &x.UnlockIdleMinutes, &rawApps)
	x.Apps = appnav.Decode(rawApps)
	x.Locked = locked != 0
	return &x, err
}

// GetSession returns the live session for a token, enforcing the idle and absolute timeouts and sliding the idle window.
func (s *Store) GetSession(ctx context.Context, token string, idleWeb, idleExt time.Duration) (*Session, error) {
	if token == "" || len(token) > 200 {
		return nil, ErrNoSession
	}
	x, err := scanSession(s.DB.QueryRowContext(ctx, `SELECT `+sessCols+` FROM sessions s LEFT JOIN users u ON u.sub = s.sub WHERE s.id_hash = ?`, Hash(token)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	idle := idleWeb
	if x.Kind == "ext" {
		idle = idleExt
	}
	now := time.Now().Unix()
	if now > x.ExpiresAt || now-x.LastSeen > int64(idle.Seconds()) {
		s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, x.IDHash)
		return nil, ErrNoSession
	}
	if now-x.LastSeen > 30 {
		s.DB.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE id_hash = ?`, now, x.IDHash)
		x.LastSeen = now
	}
	return x, nil
}

func (s *Store) MarkSessionChecked(ctx context.Context, idHash string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET checked_at = ? WHERE id_hash = ?`, time.Now().Unix(), idHash)
	return err
}

func (s *Store) UpdateSessionRole(ctx context.Context, idHash, role string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET role = ? WHERE id_hash = ?`, role, idHash)
	return err
}

func (s *Store) SetSessionIP(ctx context.Context, idHash, ip string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET ip = ? WHERE id_hash = ?`, clip(ip, 64), idHash)
	return err
}

// SetSessionToken records a fresh SSO access token on an existing session.
func (s *Store) SetSessionToken(ctx context.Context, idHash, accessToken string, expiry time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET access_token = ?, token_expiry = ?, checked_at = ? WHERE id_hash = ?`, accessToken, expiry.Unix(), time.Now().Unix(), idHash)
	return err
}

func (s *Store) SetUnlockedUntil(ctx context.Context, idHash string, until int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET unlocked_until = ? WHERE id_hash = ?`, until, idHash)
	return err
}

func (s *Store) DeleteSessionByHash(ctx context.Context, idHash string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteUserSessions ends every session of a user except `keep` (a session id hash; "" keeps none). It returns how many.
func (s *Store) DeleteUserSessions(ctx context.Context, sub, keep string) (int, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE sub = ? AND id_hash <> ?`, sub, keep)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *Store) ListUserSessions(ctx context.Context, sub string) ([]Session, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+sessCols+` FROM sessions s LEFT JOIN users u ON u.sub = s.sub WHERE s.sub = ? AND s.expires_at > ? ORDER BY s.last_seen DESC`, sub, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		x, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		x.AccessToken, x.CSRF = "", ""
		out = append(out, *x)
	}
	return out, rows.Err()
}

// RevokeSessionByPublicID ends one of the user's own sessions.
func (s *Store) RevokeSessionByPublicID(ctx context.Context, sub, publicID string) (bool, error) {
	if len(publicID) != 16 {
		return false, nil
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE sub = ? AND substr(id_hash,1,16) = ?`, sub, publicID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) PurgeSessions(ctx context.Context, webIdle time.Duration) error {
	now := time.Now()
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ? OR (kind = 'web' AND last_seen < ?)`, now.Unix(), now.Add(-webIdle).Unix())
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `DELETE FROM ext_codes WHERE expires_at < ?`, now.Unix())
	return err
}

func (s *Store) UpdateSessionApps(ctx context.Context, idHash string, apps []appnav.App) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET apps=? WHERE id_hash=?`, appnav.Encode(apps), idHash)
	return err
}

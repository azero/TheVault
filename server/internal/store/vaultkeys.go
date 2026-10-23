package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// VaultKeys is everything the server keeps about a user's cryptography. Every value is either public, an
// envelope only the user's keys can open, or an HMAC of a proof (see docs/crypto.md).
type VaultKeys struct {
	Sub                              string
	KDF                              string
	KDFIter                          int
	KDFSalt                          string
	AuthHash                         string
	WrappedUK                        string
	KeyVersion                       int
	EncPub, SigPub, EncPriv, SigPriv string
	RecoveryHash, RecoveryWrappedUK  string
	CreatedAt, UpdatedAt             int64
	FailedUnlocks                    int
	LockedUntil, LastUnlock          int64
	FailedRecoveries                 int
	RecoveryLockedUntil              int64
}

const vkCols = `sub,kdf,kdf_iter,kdf_salt,auth_hash,wrapped_uk,key_version,enc_pub,sig_pub,enc_priv,sig_priv,recovery_hash,recovery_wrapped_uk,created_at,updated_at,failed_unlocks,locked_until,last_unlock,failed_recoveries,recovery_locked_until`

func (s *Store) GetVaultKeys(ctx context.Context, sub string) (*VaultKeys, error) {
	var v VaultKeys
	err := s.DB.QueryRowContext(ctx, `SELECT `+vkCols+` FROM vault_keys WHERE sub = ?`, sub).Scan(
		&v.Sub, &v.KDF, &v.KDFIter, &v.KDFSalt, &v.AuthHash, &v.WrappedUK, &v.KeyVersion, &v.EncPub, &v.SigPub, &v.EncPriv, &v.SigPriv,
		&v.RecoveryHash, &v.RecoveryWrappedUK, &v.CreatedAt, &v.UpdatedAt, &v.FailedUnlocks, &v.LockedUntil, &v.LastUnlock, &v.FailedRecoveries, &v.RecoveryLockedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &v, err
}

func (s *Store) CreateVaultKeys(ctx context.Context, v VaultKeys) error {
	now := time.Now().Unix()
	_, err := s.DB.ExecContext(ctx, `INSERT INTO vault_keys(sub,kdf,kdf_iter,kdf_salt,auth_hash,wrapped_uk,key_version,enc_pub,sig_pub,enc_priv,sig_priv,recovery_hash,recovery_wrapped_uk,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.Sub, v.KDF, v.KDFIter, v.KDFSalt, v.AuthHash, v.WrappedUK, 1, v.EncPub, v.SigPub, v.EncPriv, v.SigPriv, v.RecoveryHash, v.RecoveryWrappedUK, now, now)
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

// Lockout schedule: the first 4 wrong proofs are free (typos), then 30 s, doubling, capped at 15 minutes.
func lockoutFor(failed int) time.Duration {
	if failed < 5 {
		return 0
	}
	d := 30 * time.Second << uint(min(failed-5, 5))
	return min(d, 15*time.Minute)
}

// RecordUnlockFailure increments the counter and sets the lockout. It returns the new count and lock expiry.
func (s *Store) RecordUnlockFailure(ctx context.Context, sub string, now time.Time) (failed int, lockedUntil int64, err error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `UPDATE vault_keys SET failed_unlocks = failed_unlocks + 1 WHERE sub = ? RETURNING failed_unlocks`, sub).Scan(&failed); err != nil {
		return 0, 0, err
	}
	if d := lockoutFor(failed); d > 0 {
		lockedUntil = now.Add(d).Unix()
		if _, err := tx.ExecContext(ctx, `UPDATE vault_keys SET locked_until = ? WHERE sub = ?`, lockedUntil, sub); err != nil {
			return 0, 0, err
		}
	}
	return failed, lockedUntil, tx.Commit()
}

func (s *Store) RecordUnlockSuccess(ctx context.Context, sub string, now time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE vault_keys SET failed_unlocks = 0, locked_until = 0, last_unlock = ? WHERE sub = ?`, now.Unix(), sub)
	return err
}

// Recovery attempts are stricter: 5 free guesses, then a 1 hour lockout per further failure (a 256-bit key cannot be guessed;
// this only limits abuse and noise).
func (s *Store) RecordRecoveryFailure(ctx context.Context, sub string, now time.Time) (failed int, lockedUntil int64, err error) {
	if err := s.DB.QueryRowContext(ctx, `UPDATE vault_keys SET failed_recoveries = failed_recoveries + 1 WHERE sub = ? RETURNING failed_recoveries`, sub).Scan(&failed); err != nil {
		return 0, 0, err
	}
	if failed >= 5 {
		lockedUntil = now.Add(time.Hour).Unix()
		_, err = s.DB.ExecContext(ctx, `UPDATE vault_keys SET recovery_locked_until = ? WHERE sub = ?`, lockedUntil, sub)
	}
	return failed, lockedUntil, err
}

type PasswordChange struct {
	KDF, Salt, AuthHash, WrappedUK string
	Iter                           int
}

// SetPassword replaces the master-password material (the user key itself is unchanged) and resets the counters.
func (s *Store) SetPassword(ctx context.Context, sub string, p PasswordChange) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE vault_keys SET kdf=?, kdf_iter=?, kdf_salt=?, auth_hash=?, wrapped_uk=?, updated_at=?, failed_unlocks=0, locked_until=0 WHERE sub = ?`,
		p.KDF, p.Iter, p.Salt, p.AuthHash, p.WrappedUK, time.Now().Unix(), sub)
	return oneRow(res, err)
}

func (s *Store) SetRecovery(ctx context.Context, sub, hash, wrapped string) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE vault_keys SET recovery_hash=?, recovery_wrapped_uk=?, updated_at=?, failed_recoveries=0, recovery_locked_until=0 WHERE sub = ?`,
		hash, wrapped, time.Now().Unix(), sub)
	return oneRow(res, err)
}

// RecoverPassword applies a recovery: new master-password material and a new recovery key in one statement.
func (s *Store) RecoverPassword(ctx context.Context, sub string, p PasswordChange, recoveryHash, recoveryWrapped string) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE vault_keys SET kdf=?, kdf_iter=?, kdf_salt=?, auth_hash=?, wrapped_uk=?, recovery_hash=?, recovery_wrapped_uk=?, updated_at=?,
		failed_unlocks=0, locked_until=0, failed_recoveries=0, recovery_locked_until=0 WHERE sub = ?`,
		p.KDF, p.Iter, p.Salt, p.AuthHash, p.WrappedUK, recoveryHash, recoveryWrapped, time.Now().Unix(), sub)
	return oneRow(res, err)
}

func oneRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// EraseVault destroys a user's ciphertext and keys (admin action, or the user's own "delete my vault"). The ClosedDoor
// identity stays; they can create a new vault. Spaces they created that still have other members are kept.
func (s *Store) EraseVault(ctx context.Context, sub string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmts := []string{
		`DELETE FROM items WHERE vault_id = 'personal' AND owner_sub = ?`,
		`DELETE FROM space_members WHERE sub = ?`,
		`DELETE FROM items WHERE vault_id IN (SELECT id FROM spaces WHERE id NOT IN (SELECT space_id FROM space_members))`,
		`DELETE FROM spaces WHERE id NOT IN (SELECT space_id FROM space_members)`,
		`DELETE FROM vault_keys WHERE sub = ?`,
		`DELETE FROM sessions WHERE sub = ? AND kind = 'ext'`,
		`UPDATE sessions SET unlocked_until = 0 WHERE sub = ?`,
	}
	for _, q := range stmts {
		var err error
		if containsQ(q) {
			_, err = tx.ExecContext(ctx, q, sub)
		} else {
			_, err = tx.ExecContext(ctx, q)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func containsQ(q string) bool {
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			return true
		}
	}
	return false
}

// Package store persists everything under one data directory:
//
//	vault.db   users, ciphertext items, spaces, sessions, audit, SkyNet outbox, ...
//	keys/      session.key, pepper.key, skynet.json (secrets; created on first start)
//	backups/   `thevault backup` snapshots
//
// The database holds ciphertext only. Schema changes are append-only migrations that run at start-up.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	dir string
	DB  *sql.DB
}

var (
	ErrNotFound   = errors.New("not found")
	ErrForbidden  = errors.New("forbidden")
	ErrExists     = errors.New("already exists")
	ErrLimit      = errors.New("limit reached")
	ErrBadRequest = errors.New("bad request")
)

// busy_timeout MUST come first (see SkyNet): switching a new file to WAL needs a lock. _txlock=immediate makes
// write transactions take the write lock at BEGIN, where the busy timeout applies.
const dsnPragmas = "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"

// Open creates the data directory layout and migrates vault.db.
func Open(dataDir string) (*Store, error) {
	for _, d := range []string{dataDir, filepath.Join(dataDir, "keys"), filepath.Join(dataDir, "backups")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("data dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "vault.db")+dsnPragmas)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open vault.db: %w", err)
	}
	s := &Store{dir: dataDir, DB: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) Dir() string  { return s.dir }

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	var cur int
	if err := s.DB.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&cur); err != nil {
		return err
	}
	if cur > len(migrations) {
		return fmt.Errorf("database is at schema v%d but this build only knows v%d: refusing to run an older TheVault against newer data", cur, len(migrations))
	}
	for v := cur + 1; v <= len(migrations); v++ {
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v-1]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, v, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Backup writes a consistent snapshot (VACUUM INTO is safe while the server runs). It contains ciphertext only,
// but it still includes session hashes and the audit log: store it like any other backup of a security system.
func (s *Store) Backup(ctx context.Context) (string, error) {
	name := filepath.Join(s.dir, "backups", "vault-"+time.Now().UTC().Format("20060102-150405")+".db")
	if _, err := s.DB.ExecContext(ctx, `VACUUM INTO ?`, name); err != nil {
		return "", err
	}
	return name, os.Chmod(name, 0o600)
}

// Size returns the on-disk size of the main database file (for the admin overview).
func (s *Store) Size() int64 {
	var n int64
	for _, suf := range []string{"", "-wal"} {
		if fi, err := os.Stat(filepath.Join(s.dir, "vault.db"+suf)); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// RandomToken returns n random bytes, base64url-encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash is the at-rest form of every high-entropy token (SHA-256, hex).
func Hash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func clip(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nextSeq increments and returns the global change counter. Callers hold a write transaction.
func nextSeq(ctx context.Context, tx *sql.Tx) (int64, error) {
	var n int64
	err := tx.QueryRowContext(ctx, `UPDATE seq SET n = n + 1 WHERE id = 1 RETURNING n`).Scan(&n)
	return n, err
}

func isUniqueViolation(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "PRIMARY KEY"))
}

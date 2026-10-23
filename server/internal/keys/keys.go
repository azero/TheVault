// Package keys holds the server's own secrets under <data>/keys: the pepper that turns client proofs into stored
// hashes, and the HMAC key that signs the pre-login cookie. Both are generated on first start (mode 0600).
package keys

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

func load(dataDir, name string) ([]byte, error) {
	p := filepath.Join(dataDir, "keys", name)
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		return b, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", p, err)
	}
	return b, nil
}

// Pepper turns an auth proof (a 256-bit HKDF output of the master key) into the value stored in the database, so a
// stolen database alone cannot even be used to test master-password guesses; the pepper file is needed as well.
type Pepper struct{ key []byte }

func LoadPepper(dataDir string) (*Pepper, error) {
	k, err := load(dataDir, "pepper.key")
	return &Pepper{key: k}, err
}

func NewPepper(key []byte) *Pepper { return &Pepper{key: key} }

func (p *Pepper) Hash(proof string) string {
	m := hmac.New(sha256.New, p.key)
	m.Write([]byte("thevault/proof/v1\x00"))
	m.Write([]byte(proof))
	return hex.EncodeToString(m.Sum(nil))
}

func (p *Pepper) Equal(stored, proof string) bool {
	return subtle.ConstantTimeCompare([]byte(stored), []byte(p.Hash(proof))) == 1
}

func LoadSessionKey(dataDir string) ([]byte, error) { return load(dataDir, "session.key") }

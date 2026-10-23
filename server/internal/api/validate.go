package api

import (
	"regexp"
	"strings"

	"github.com/azero/thevault/server/internal/store"
)

var (
	reID        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reB64u      = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	reProof     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)    // 32 bytes
	rePub       = regexp.MustCompile(`^[A-Za-z0-9_-]{87}$`)    // uncompressed P-256 point, 65 bytes
	reSig       = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)    // r||s, 64 bytes
	reSalt      = regexp.MustCompile(`^[A-Za-z0-9_-]{22,86}$`) // 16..64 bytes
	reEnvelope  = regexp.MustCompile(`^1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$`)
	reSub       = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	reChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	reVerifier  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

const (
	maxItemBlob  = 262144 // 256 KB of base64url text
	maxSmallBlob = 4096   // wrapped keys, space names
	minIter      = 600000
	maxIter      = 20000000
)

func isID(s string) bool                { return reID.MatchString(s) }
func isProof(s string) bool             { return reProof.MatchString(s) }
func isEnvelope(s string, max int) bool { return len(s) <= max && reEnvelope.MatchString(s) }
func isVaultID(s string) bool           { return s == "personal" || isID(s) }

// kdfOK validates the key-derivation parameters a client wants to store. The client refuses weak ones too; this stops a
// buggy or hostile client from storing parameters that other clients would then refuse to use.
func kdfOK(kdf string, iter int, salt string) bool {
	return kdf == "pbkdf2-sha256" && iter >= minIter && iter <= maxIter && reSalt.MatchString(salt)
}

func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return strings.ToValidUTF8(s, "")
}

type putItemT = store.PutItem

func putItemParams(c *rc, id string, in putItemIn, max int) store.PutItem {
	return store.PutItem{Sub: c.Sess.Sub, ID: id, VaultID: in.VaultID, BaseSeq: in.BaseSeq, Blob: in.Blob, KeyVersion: in.KeyVersion, MaxItems: max}
}

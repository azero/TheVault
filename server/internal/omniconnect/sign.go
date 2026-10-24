// Vendored from OmniCore reference/go/omniconnect; change upstream, not here.

package omniconnect

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Header names of a signed OmniCore -> app request.
const (
	HeaderKey       = "X-OmniCore-Key"
	HeaderTimestamp = "X-OmniCore-Timestamp"
	HeaderNonce     = "X-OmniCore-Nonce"
	HeaderUser      = "X-OmniCore-User"
	HeaderSignature = "X-OmniCore-Signature"
)

const (
	sigPrefix = "v1="
	// MaxSkew is how far a request's timestamp may be from the receiver's clock.
	MaxSkew = 2 * time.Minute
	// nonceTTL must exceed 2*MaxSkew so a captured request cannot be replayed inside its validity window.
	nonceTTL = 6 * time.Minute
)

// Key is a shared secret between OmniCore and one app. ID names it (so keys can be rotated: an app may
// accept two at once); Secret is the raw bytes used as the HMAC key.
type Key struct {
	ID     string
	Secret []byte
}

// Canonical builds the string that is signed. method is upper-case; target is the request target exactly as it
// goes on the wire (path plus "?query" when there is one, no scheme or host); user is the ClosedDoor sub, or ""
// for calls that are not on behalf of a person; bodySHA256 is the lower-case hex SHA-256 of the body (v1
// requests have no body: use EmptyBodySHA256).
func Canonical(method, target string, ts int64, nonce, user, bodySHA256 string) string {
	return "OMNICORE-V1\n" + method + "\n" + target + "\n" + strconv.FormatInt(ts, 10) + "\n" + nonce + "\n" + user + "\n" + bodySHA256
}

// EmptyBodySHA256 is sha256("").
const EmptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Signature returns "v1=<hex hmac-sha256(secret, canonical)>".
func Signature(secret []byte, canonical string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(canonical))
	return sigPrefix + hex.EncodeToString(m.Sum(nil))
}

// NewNonce returns 18 random bytes, base64url without padding.
func NewNonce() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic("omniconnect: no randomness: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// SignRequest sets the OmniCore headers on a GET request. user may be "".
func SignRequest(k Key, req *http.Request, user string, now time.Time) {
	nonce := NewNonce()
	ts := now.Unix()
	target := req.URL.EscapedPath()
	if target == "" {
		target = "/"
	}
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}
	req.Header.Set(HeaderKey, k.ID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderNonce, nonce)
	if user != "" {
		req.Header.Set(HeaderUser, user)
	} else {
		req.Header.Del(HeaderUser)
	}
	req.Header.Set(HeaderSignature, Signature(k.Secret, Canonical(req.Method, target, ts, nonce, user, EmptyBodySHA256)))
}

var (
	ErrUnauthorized = errors.New("omniconnect: unauthorized")
)

// Verifier checks signed requests. Safe for concurrent use.
type Verifier struct {
	keys  map[string][]byte
	now   func() time.Time
	mu    sync.Mutex
	nonce map[string]time.Time // key id + nonce -> expiry
}

// NewVerifier accepts any of keys. Pass the current key and, during rotation, the previous one.
func NewVerifier(keys ...Key) *Verifier {
	v := &Verifier{keys: map[string][]byte{}, now: time.Now, nonce: map[string]time.Time{}}
	for _, k := range keys {
		if k.ID != "" && len(k.Secret) >= 16 {
			v.keys[k.ID] = k.Secret
		}
	}
	return v
}

// SetClock replaces the clock (tests).
func (v *Verifier) SetClock(f func() time.Time) { v.now = f }

// Verify authenticates r. It returns the user the call is on behalf of ("" when the call carries none).
// Every failure is ErrUnauthorized: callers answer 401 without saying which check failed (they may log the
// reason through the Reason in the wrapped error text for their own audit, never to the client).
func (v *Verifier) Verify(r *http.Request) (string, error) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return "", wrap("method")
	}
	if r.ContentLength > 0 {
		return "", wrap("body")
	}
	secret, ok := v.keys[r.Header.Get(HeaderKey)]
	if !ok || len(secret) == 0 {
		return "", wrap("unknown key")
	}
	ts, err := strconv.ParseInt(r.Header.Get(HeaderTimestamp), 10, 64)
	if err != nil {
		return "", wrap("timestamp")
	}
	now := v.now()
	if d := now.Sub(time.Unix(ts, 0)); d > MaxSkew || d < -MaxSkew {
		return "", wrap("clock skew")
	}
	nonce := r.Header.Get(HeaderNonce)
	if len(nonce) < 16 || len(nonce) > 64 || !tokenChars(nonce) {
		return "", wrap("nonce")
	}
	user := r.Header.Get(HeaderUser)
	if user != "" && !validUser(user) {
		return "", wrap("user")
	}
	target := r.URL.EscapedPath()
	if target == "" {
		target = "/"
	}
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	want := Signature(secret, Canonical(r.Method, target, ts, nonce, user, EmptyBodySHA256))
	if !hmac.Equal([]byte(want), []byte(r.Header.Get(HeaderSignature))) {
		return "", wrap("signature")
	}
	// Only a correctly signed request may use up a nonce, so strangers cannot fill the table.
	if !v.fresh(r.Header.Get(HeaderKey)+"\x00"+nonce, now) {
		return "", wrap("replay")
	}
	return user, nil
}

type reasonErr struct{ reason string }

func (e reasonErr) Error() string { return "omniconnect: unauthorized (" + e.reason + ")" }
func (e reasonErr) Unwrap() error { return ErrUnauthorized }
func wrap(reason string) error    { return reasonErr{reason} }

func (v *Verifier) fresh(id string, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.nonce) > 4096 {
		for k, exp := range v.nonce {
			if now.After(exp) {
				delete(v.nonce, k)
			}
		}
		if len(v.nonce) > 20000 { // sustained flood of valid signatures: fail closed rather than grow
			return false
		}
	}
	if exp, seen := v.nonce[id]; seen && now.Before(exp) {
		return false
	}
	v.nonce[id] = now.Add(nonceTTL)
	return true
}

func tokenChars(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// validUser accepts a ClosedDoor subject: letters, digits and . _ @ : - up to 128 characters.
func validUser(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._@:-", r)) {
			return false
		}
	}
	return true
}

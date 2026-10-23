package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/azero/thevault/server/internal/store"
)

type recoveryIn struct {
	Proof     string `json:"proof"`
	WrappedUK string `json:"wrapped_uk"`
}

func (r recoveryIn) valid() bool { return isProof(r.Proof) && isEnvelope(r.WrappedUK, maxSmallBlob) }

func (s *Server) prelogin(c *rc) {
	vk, err := s.Store.GetVaultKeys(c.R.Context(), c.Sess.Sub)
	if err != nil {
		c.fail(http.StatusNotFound, "no_vault", "No vault has been created yet.")
		return
	}
	c.ok(map[string]any{"kdf": vk.KDF, "iterations": vk.KDFIter, "salt": vk.KDFSalt, "key_version": vk.KeyVersion})
}

type setupIn struct {
	KDF        string     `json:"kdf"`
	Iterations int        `json:"iterations"`
	Salt       string     `json:"salt"`
	Auth       string     `json:"auth"`
	KeyVersion int        `json:"key_version"`
	WrappedUK  string     `json:"wrapped_uk"`
	EncPub     string     `json:"enc_pub"`
	SigPub     string     `json:"sig_pub"`
	EncPriv    string     `json:"enc_priv"`
	SigPriv    string     `json:"sig_priv"`
	Recovery   recoveryIn `json:"recovery"`
}

func (s *Server) setup(c *rc) {
	var in setupIn
	if !c.decode(&in, 16<<10) {
		return
	}
	if !kdfOK(in.KDF, in.Iterations, in.Salt) || !isProof(in.Auth) || in.KeyVersion != 1 || !isEnvelope(in.WrappedUK, maxSmallBlob) ||
		!rePub.MatchString(in.EncPub) || !rePub.MatchString(in.SigPub) || !isEnvelope(in.EncPriv, maxSmallBlob) || !isEnvelope(in.SigPriv, maxSmallBlob) || !in.Recovery.valid() {
		c.fail(http.StatusBadRequest, "bad_request", "The vault data is malformed.")
		return
	}
	if in.Auth == in.Recovery.Proof {
		c.fail(http.StatusBadRequest, "bad_request", "The vault data is malformed.")
		return
	}
	err := s.Store.CreateVaultKeys(c.R.Context(), store.VaultKeys{
		Sub: c.Sess.Sub, KDF: in.KDF, KDFIter: in.Iterations, KDFSalt: in.Salt, AuthHash: s.Pepper.Hash(in.Auth), WrappedUK: in.WrappedUK,
		EncPub: in.EncPub, SigPub: in.SigPub, EncPriv: in.EncPriv, SigPriv: in.SigPriv,
		RecoveryHash: s.Pepper.Hash(in.Recovery.Proof), RecoveryWrappedUK: in.Recovery.WrappedUK,
	})
	if err != nil {
		s.storeErr(c, err)
		return
	}
	s.markUnlocked(c)
	c.audit(s, "vault_created", "success", "", map[string]string{"iterations": itoa(in.Iterations)})
	c.ok(map[string]any{"ok": true})
}

func (s *Server) markUnlocked(c *rc) {
	until := time.Now().Add(s.idleFor(c.Sess)).Unix()
	if limit := time.Unix(c.Sess.TokenExpiry, 0).Add(ssoGrace).Unix(); until > limit {
		until = limit
	}
	s.Store.SetUnlockedUntil(c.R.Context(), c.Sess.IDHash, until)
	c.Sess.UnlockedUntil = until
}

// checkProof verifies the master-password proof with throttling. It writes the response and returns false on failure.
// Checks are serialised per account: the lock state is re-read under the lock, so a burst of parallel guesses cannot all
// be evaluated against the same "not locked yet" snapshot. Callers other than unlock (which has its own per-address
// limit) pass limit=true to share a second per-address budget.
func (s *Server) checkProof(c *rc, vk *store.VaultKeys, proof, event string, limit bool) bool {
	ctx := c.R.Context()
	if limit && !s.verifyRL.Allow(c.IP) {
		c.W.Header().Set("Retry-After", "30")
		c.fail(http.StatusTooManyRequests, "rate_limited", "Too many attempts from this address.")
		return false
	}
	mu := s.proofLock(c.Sess.Sub)
	mu.Lock()
	defer mu.Unlock()
	if fresh, err := s.Store.GetVaultKeys(ctx, c.Sess.Sub); err == nil {
		vk = fresh
	}
	now := time.Now()
	if vk.LockedUntil > now.Unix() {
		c.W.Header().Set("Retry-After", itoa(int(vk.LockedUntil-now.Unix())))
		c.fail(http.StatusTooManyRequests, "locked_out", "Too many wrong passwords. Try again in a few minutes.")
		return false
	}
	if !isProof(proof) || !s.Pepper.Equal(vk.AuthHash, proof) {
		failed, until, err := s.Store.RecordUnlockFailure(ctx, c.Sess.Sub, now)
		if err != nil {
			logErr("record unlock failure", err)
		}
		c.audit(s, event, "failure", "", map[string]string{"failed": itoa(failed)})
		if until > 0 {
			c.audit(s, "unlock_lockout", "failure", "", map[string]string{"failed": itoa(failed), "seconds": itoa(int(until - now.Unix()))})
			c.W.Header().Set("Retry-After", itoa(int(until-now.Unix())))
		}
		body := map[string]any{"error": "bad_password", "message": "That master password is not correct.", "failed": failed}
		if until > 0 {
			body["retry_after"] = until - now.Unix()
		}
		writeJSON(c, http.StatusUnauthorized, body)
		return false
	}
	return true
}

func (s *Server) unlock(c *rc) {
	var in struct {
		Auth string `json:"auth"`
	}
	if !c.decode(&in, 2<<10) {
		return
	}
	ctx := c.R.Context()
	if !s.unlockRL.Allow(c.IP) {
		c.W.Header().Set("Retry-After", "30")
		c.fail(http.StatusTooManyRequests, "rate_limited", "Too many attempts from this address.")
		return
	}
	vk, err := s.Store.GetVaultKeys(ctx, c.Sess.Sub)
	if err != nil {
		c.fail(http.StatusNotFound, "no_vault", "No vault has been created yet.")
		return
	}
	// Unlocking needs a fresh SSO token, re-checked right now: this is where a revoked ClosedDoor account is cut off.
	if time.Now().After(time.Unix(c.Sess.TokenExpiry, 0).Add(-tokenSkew)) {
		c.fail(http.StatusUnauthorized, "sso_expired", "Sign in with ClosedDoor again to unlock.")
		return
	}
	if time.Since(time.Unix(c.Sess.CheckedAt, 0)) > time.Minute && !s.revalidate(c, c.Sess) {
		return
	}
	if !s.checkProof(c, vk, in.Auth, "unlock_failed", false) {
		return
	}
	now := time.Now()
	s.Store.RecordUnlockSuccess(ctx, c.Sess.Sub, now)
	s.markUnlocked(c)
	c.audit(s, "unlock", "success", "", map[string]string{"kind": c.Sess.Kind})
	c.ok(map[string]any{
		"wrapped_uk": vk.WrappedUK, "key_version": vk.KeyVersion, "enc_pub": vk.EncPub, "sig_pub": vk.SigPub, "enc_priv": vk.EncPriv, "sig_priv": vk.SigPriv,
		"kdf": vk.KDF, "iterations": vk.KDFIter, "salt": vk.KDFSalt, "unlocked_until": c.Sess.UnlockedUntil,
	})
}

func (s *Server) lock(c *rc) {
	s.Store.SetUnlockedUntil(c.R.Context(), c.Sess.IDHash, 0)
	c.audit(s, "lock", "success", "", map[string]string{"kind": c.Sess.Kind})
	c.ok(map[string]bool{"ok": true})
}

// verifyPassword re-checks the master password before something dangerous (export, erase, new recovery key), with the
// same throttling and audit as unlocking, so a hijacked unlocked session cannot guess its way into destructive actions.
func (s *Server) verifyPassword(c *rc) {
	var in struct {
		Auth string `json:"auth"`
	}
	if !c.decode(&in, 2<<10) {
		return
	}
	vk, err := s.Store.GetVaultKeys(c.R.Context(), c.Sess.Sub)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	if !s.checkProof(c, vk, in.Auth, "unlock_failed", true) {
		return
	}
	c.ok(map[string]bool{"ok": true})
}

func (s *Server) changePassword(c *rc) {
	var in struct {
		AuthOld    string `json:"auth_old"`
		AuthNew    string `json:"auth_new"`
		KDF        string `json:"kdf"`
		Iterations int    `json:"iterations"`
		Salt       string `json:"salt"`
		WrappedUK  string `json:"wrapped_uk"`
	}
	if !c.decode(&in, 8<<10) {
		return
	}
	ctx := c.R.Context()
	vk, err := s.Store.GetVaultKeys(ctx, c.Sess.Sub)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	if !kdfOK(in.KDF, in.Iterations, in.Salt) || !isProof(in.AuthNew) || !isEnvelope(in.WrappedUK, maxSmallBlob) {
		c.fail(http.StatusBadRequest, "bad_request", "The request is malformed.")
		return
	}
	if !s.checkProof(c, vk, in.AuthOld, "unlock_failed", true) {
		return
	}
	if err := s.Store.SetPassword(ctx, c.Sess.Sub, store.PasswordChange{KDF: in.KDF, Iter: in.Iterations, Salt: in.Salt, AuthHash: s.Pepper.Hash(in.AuthNew), WrappedUK: in.WrappedUK}); err != nil {
		s.storeErr(c, err)
		return
	}
	n, _ := s.Store.DeleteUserSessions(ctx, c.Sess.Sub, c.Sess.IDHash)
	c.audit(s, "master_password_changed", "success", "", map[string]string{"sessions_ended": itoa(n)})
	c.ok(map[string]any{"ok": true, "sessions_ended": n})
}

// ---- recovery ----

func (s *Server) recoveryGate(c *rc, vk *store.VaultKeys, proof string) bool {
	ctx := c.R.Context()
	now := time.Now()
	if vk.RecoveryLockedUntil > now.Unix() {
		c.W.Header().Set("Retry-After", itoa(int(vk.RecoveryLockedUntil-now.Unix())))
		c.fail(http.StatusTooManyRequests, "locked_out", "Too many wrong recovery keys. Try again later.")
		return false
	}
	if !s.unlockRL.Allow(c.IP) {
		c.fail(http.StatusTooManyRequests, "rate_limited", "Too many attempts from this address.")
		return false
	}
	if time.Now().After(time.Unix(c.Sess.TokenExpiry, 0).Add(-tokenSkew)) {
		c.fail(http.StatusUnauthorized, "sso_expired", "Sign in with ClosedDoor again first.")
		return false
	}
	if !isProof(proof) || !s.Pepper.Equal(vk.RecoveryHash, proof) {
		failed, until, _ := s.Store.RecordRecoveryFailure(ctx, c.Sess.Sub, now)
		c.audit(s, "recovery_failed", "failure", "", map[string]string{"failed": itoa(failed)})
		body := map[string]any{"error": "bad_recovery_key", "message": "That recovery key is not correct.", "failed": failed}
		if until > 0 {
			body["retry_after"] = until - now.Unix()
		}
		writeJSON(c, http.StatusUnauthorized, body)
		return false
	}
	return true
}

func (s *Server) recoveryStart(c *rc) {
	var in struct {
		Proof string `json:"proof"`
	}
	if !c.decode(&in, 2<<10) {
		return
	}
	vk, err := s.Store.GetVaultKeys(c.R.Context(), c.Sess.Sub)
	if err != nil {
		c.fail(http.StatusNotFound, "no_vault", "No vault has been created yet.")
		return
	}
	if !s.recoveryGate(c, vk, in.Proof) {
		return
	}
	c.audit(s, "recovery_started", "success", "", nil)
	c.ok(map[string]any{
		"wrapped_uk": vk.RecoveryWrappedUK, "enc_pub": vk.EncPub, "sig_pub": vk.SigPub, "enc_priv": vk.EncPriv, "sig_priv": vk.SigPriv,
	})
}

func (s *Server) recoveryFinish(c *rc) {
	var in struct {
		Proof      string     `json:"proof"`
		AuthNew    string     `json:"auth_new"`
		KDF        string     `json:"kdf"`
		Iterations int        `json:"iterations"`
		Salt       string     `json:"salt"`
		WrappedUK  string     `json:"wrapped_uk"`
		Recovery   recoveryIn `json:"recovery"`
	}
	if !c.decode(&in, 16<<10) {
		return
	}
	ctx := c.R.Context()
	vk, err := s.Store.GetVaultKeys(ctx, c.Sess.Sub)
	if err != nil {
		c.fail(http.StatusNotFound, "no_vault", "No vault has been created yet.")
		return
	}
	if !kdfOK(in.KDF, in.Iterations, in.Salt) || !isProof(in.AuthNew) || !isEnvelope(in.WrappedUK, maxSmallBlob) || !in.Recovery.valid() || in.AuthNew == in.Recovery.Proof {
		c.fail(http.StatusBadRequest, "bad_request", "The request is malformed.")
		return
	}
	if !s.recoveryGate(c, vk, in.Proof) {
		return
	}
	err = s.Store.RecoverPassword(ctx, c.Sess.Sub, store.PasswordChange{KDF: in.KDF, Iter: in.Iterations, Salt: in.Salt, AuthHash: s.Pepper.Hash(in.AuthNew), WrappedUK: in.WrappedUK},
		s.Pepper.Hash(in.Recovery.Proof), in.Recovery.WrappedUK)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	n, _ := s.Store.DeleteUserSessions(ctx, c.Sess.Sub, c.Sess.IDHash)
	s.markUnlocked(c)
	c.audit(s, "recovery_used", "success", "", map[string]string{"sessions_ended": itoa(n)})
	c.ok(map[string]any{"ok": true, "sessions_ended": n})
}

func (s *Server) recoveryRotate(c *rc) {
	var in struct {
		Auth     string     `json:"auth"`
		Recovery recoveryIn `json:"recovery"`
	}
	if !c.decode(&in, 8<<10) {
		return
	}
	ctx := c.R.Context()
	vk, err := s.Store.GetVaultKeys(ctx, c.Sess.Sub)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	if !in.Recovery.valid() || in.Recovery.Proof == in.Auth {
		c.fail(http.StatusBadRequest, "bad_request", "The request is malformed.")
		return
	}
	if !s.checkProof(c, vk, in.Auth, "unlock_failed", true) {
		return
	}
	if err := s.Store.SetRecovery(ctx, c.Sess.Sub, s.Pepper.Hash(in.Recovery.Proof), in.Recovery.WrappedUK); err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "recovery_rotated", "success", "", nil)
	c.ok(map[string]bool{"ok": true})
}

// eraseOwnVault deletes the caller's vault after a fresh master-password proof (the last resort when both the master
// password and the recovery key are gone).
func (s *Server) eraseOwnVault(c *rc) {
	var in struct {
		Auth string `json:"auth"`
	}
	if !c.decode(&in, 2<<10) {
		return
	}
	ctx := c.R.Context()
	vk, err := s.Store.GetVaultKeys(ctx, c.Sess.Sub)
	if err != nil {
		s.storeErr(c, err)
		return
	}
	// Without the master password, erasing is only possible through an administrator.
	if !s.checkProof(c, vk, in.Auth, "unlock_failed", true) {
		return
	}
	if err := s.Store.EraseVault(ctx, c.Sess.Sub); err != nil {
		s.storeErr(c, err)
		return
	}
	c.audit(s, "vault_erased_self", "success", "", nil)
	c.ok(map[string]bool{"ok": true})
}

// proofLock returns the mutex that serialises master-password checks for one account.
func (s *Server) proofLock(sub string) *sync.Mutex {
	m, _ := s.proofMu.LoadOrStore(sub, new(sync.Mutex))
	return m.(*sync.Mutex)
}

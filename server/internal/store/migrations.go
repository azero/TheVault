package store

// Append-only. Never edit an applied migration; add a new one.
var migrations = []string{
	// 1: everything
	`
CREATE TABLE users (
    sub        TEXT PRIMARY KEY,
    email      TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    role       TEXT NOT NULL DEFAULT 'member',
    first_seen INTEGER NOT NULL,
    last_login INTEGER NOT NULL DEFAULT 0,
    locked     INTEGER NOT NULL DEFAULT 0,
    unlock_idle_minutes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE vault_keys (
    sub                   TEXT PRIMARY KEY REFERENCES users(sub) ON DELETE CASCADE,
    kdf                   TEXT NOT NULL,
    kdf_iter              INTEGER NOT NULL,
    kdf_salt              TEXT NOT NULL,
    auth_hash             TEXT NOT NULL,
    wrapped_uk            TEXT NOT NULL,
    key_version           INTEGER NOT NULL DEFAULT 1,
    enc_pub               TEXT NOT NULL,
    sig_pub               TEXT NOT NULL,
    enc_priv              TEXT NOT NULL,
    sig_priv              TEXT NOT NULL,
    recovery_hash         TEXT NOT NULL,
    recovery_wrapped_uk   TEXT NOT NULL,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    failed_unlocks        INTEGER NOT NULL DEFAULT 0,
    locked_until          INTEGER NOT NULL DEFAULT 0,
    last_unlock           INTEGER NOT NULL DEFAULT 0,
    failed_recoveries     INTEGER NOT NULL DEFAULT 0,
    recovery_locked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE sessions (
    id_hash        TEXT PRIMARY KEY,
    sub            TEXT NOT NULL,
    kind           TEXT NOT NULL DEFAULT 'web',
    label          TEXT NOT NULL DEFAULT '',
    role           TEXT NOT NULL,
    csrf           TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    checked_at     INTEGER NOT NULL,
    access_token   TEXT NOT NULL DEFAULT '',
    token_expiry   INTEGER NOT NULL DEFAULT 0,
    ip             TEXT NOT NULL DEFAULT '',
    user_agent     TEXT NOT NULL DEFAULT '',
    unlocked_until INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX sessions_sub ON sessions(sub);
CREATE TABLE seq (id INTEGER PRIMARY KEY CHECK (id = 1), n INTEGER NOT NULL);
INSERT INTO seq(id, n) VALUES (1, 0);
CREATE TABLE spaces (
    id             TEXT PRIMARY KEY,
    name_blob      TEXT NOT NULL,
    key_version    INTEGER NOT NULL DEFAULT 1,
    needs_rotation INTEGER NOT NULL DEFAULT 0,
    created_by     TEXT NOT NULL,
    created_at     INTEGER NOT NULL
);
CREATE TABLE space_members (
    space_id    TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    sub         TEXT NOT NULL,
    role        TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    wrap_eph    TEXT NOT NULL,
    wrap_ct     TEXT NOT NULL,
    wrap_sig    TEXT NOT NULL,
    wrapped_by  TEXT NOT NULL,
    added_at    INTEGER NOT NULL,
    PRIMARY KEY (space_id, sub)
);
CREATE INDEX space_members_sub ON space_members(sub);
CREATE TABLE items (
    id          TEXT PRIMARY KEY,
    owner_sub   TEXT NOT NULL,
    vault_id    TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    blob        TEXT NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    deleted_at  INTEGER NOT NULL DEFAULT 0,
    purged      INTEGER NOT NULL DEFAULT 0,
    updated_by  TEXT NOT NULL
);
CREATE INDEX items_owner ON items(owner_sub, seq);
CREATE INDEX items_vault ON items(vault_id, seq);
CREATE INDEX items_seq ON items(seq);
CREATE TABLE item_versions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id     TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    blob        TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    saved_at    INTEGER NOT NULL,
    saved_by    TEXT NOT NULL
);
CREATE INDEX item_versions_item ON item_versions(item_id, id);
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    event      TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    target     TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    outcome    TEXT NOT NULL DEFAULT '',
    details    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_created ON audit_log(created_at);
CREATE INDEX audit_actor ON audit_log(actor, id);
CREATE TABLE ext_codes (
    code_hash    TEXT PRIMARY KEY,
    sub          TEXT NOT NULL,
    email        TEXT NOT NULL DEFAULT '',
    name         TEXT NOT NULL DEFAULT '',
    role         TEXT NOT NULL,
    challenge    TEXT NOT NULL,
    redirect     TEXT NOT NULL,
    access_token TEXT NOT NULL DEFAULT '',
    token_expiry INTEGER NOT NULL DEFAULT 0,
    expires_at   INTEGER NOT NULL
);
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    payload    TEXT NOT NULL
);
CREATE TABLE deny_list (
    ip         TEXT PRIMARY KEY,
    until      INTEGER NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    command_id INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE command_seen (
    id      INTEGER PRIMARY KEY,
    seen_at INTEGER NOT NULL
);
`,
	// v2: public keys of erased accounts, so wraps they made for other members stay verifiable until the space is rotated.
	`
CREATE TABLE retired_keys (
    id         TEXT PRIMARY KEY,
    enc_pub    TEXT NOT NULL,
    sig_pub    TEXT NOT NULL,
    retired_at INTEGER NOT NULL
);
`,
	// Grant-filtered navigation, empty for older sessions until verified again.
	`ALTER TABLE sessions ADD COLUMN apps TEXT NOT NULL DEFAULT '[]';`,
	// Index for the OmniCore widgets (failed unlocks per day/hour, a person's recent security events): lookups by event
	// name and time instead of walking a person's whole trail, which also holds every item write.
	`CREATE INDEX audit_event_created ON audit_log(event, created_at);`,
}

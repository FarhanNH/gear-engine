-- migrations/001_init.sql
-- Initial schema for Gear Secret Management

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Admin user (single admin in Phase 1)
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,   -- bcrypt atau argon2 hash
    created_at    INTEGER NOT NULL -- Unix timestamp
);

-- Secrets table with envelope encryption
CREATE TABLE IF NOT EXISTS secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    path            TEXT NOT NULL UNIQUE,   -- e.g. "app/db/password"
    encrypted_value BLOB NOT NULL,          -- AES-256-GCM ciphertext dari DEK
    value_nonce     BLOB NOT NULL,          -- 12-byte nonce untuk enkripsi value
    encrypted_dek   BLOB NOT NULL,          -- DEK dienkripsi oleh Master Key
    dek_nonce       BLOB NOT NULL,          -- 12-byte nonce untuk enkripsi DEK
    version         INTEGER NOT NULL DEFAULT 1, -- untuk versioning di masa depan
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_secrets_path ON secrets(path);

-- Access tokens
CREATE TABLE IF NOT EXISTS tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,              -- deskriptif, untuk display saja
    token_hash  TEXT NOT NULL UNIQUE,       -- SHA-256(plaintext_token), hex encoded
    expires_at  INTEGER,                    -- Unix timestamp; NULL = no expiry
    revoked     INTEGER NOT NULL DEFAULT 0, -- 0=active, 1=revoked
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);

-- Access policies (many-per-token)
CREATE TABLE IF NOT EXISTS policies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id     INTEGER NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    path_pattern TEXT NOT NULL,             -- e.g. "app/*" atau "app/db/password"
    can_read     INTEGER NOT NULL DEFAULT 0,
    can_write    INTEGER NOT NULL DEFAULT 0,
    can_delete   INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policies_token ON policies(token_id);

-- Audit log (append-only)
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id   INTEGER,                    -- NULL jika unauthenticated attempt
    token_name TEXT,                       -- snapshot nama token saat kejadian
    path       TEXT,                       -- path yang diakses (bisa NULL untuk /auth)
    action     TEXT NOT NULL,              -- "read", "write", "delete", "list", "login", "token_create", dll.
    result     TEXT NOT NULL,              -- "success", "denied", "error"
    error_code INTEGER,                    -- HTTP status code
    ip_address TEXT,
    timestamp  INTEGER NOT NULL            -- Unix timestamp (nanosecond precision)
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_token     ON audit_log(token_id);
CREATE INDEX IF NOT EXISTS idx_audit_path      ON audit_log(path);

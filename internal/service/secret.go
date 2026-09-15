package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/gear/engine/internal/crypto"
)

// ErrSecretNotFound is returned when a secret path does not exist in the database.
var ErrSecretNotFound = errors.New("secret not found")

// SecretService defines the operations for managing encrypted secrets.
type SecretService interface {
	Put(ctx context.Context, path, value string) error
	Get(ctx context.Context, path string) (string, error)
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// SecretServiceImpl is the concrete implementation of SecretService.
// It uses envelope encryption: each secret is encrypted with a per-secret DEK,
// and the DEK is itself encrypted with the Master Key before being stored in SQLite.
type SecretServiceImpl struct {
	db        *sql.DB
	masterKey []byte
}

// NewSecretService creates a new SecretServiceImpl with the given database handle
// and Master Key. The Master Key must be exactly 32 bytes (AES-256).
func NewSecretService(db *sql.DB, masterKey []byte) *SecretServiceImpl {
	return &SecretServiceImpl{
		db:        db,
		masterKey: masterKey,
	}
}

// Put encrypts the value using a freshly generated DEK, encrypts the DEK with the
// Master Key, and upserts the record into the secrets table.
//
// Envelope encryption flow:
//  1. Generate a random 32-byte DEK via crypto.GenerateKey()
//  2. Encrypt([]byte(value), dek)  → encryptedValue, valueNonce
//  3. Encrypt(dek, masterKey)      → encryptedDEK,   dekNonce
//  4. Zero-out DEK from memory     via defer crypto.ZeroBytes(dek)
//  5. INSERT OR REPLACE INTO secrets …
func (s *SecretServiceImpl) Put(ctx context.Context, path, value string) error {
	// 1. Generate a unique DEK for this secret.
	dek, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("put secret %q: generate DEK: %w", path, err)
	}
	// Zero-out DEK plaintext from memory after this function returns.
	defer crypto.ZeroBytes(dek)

	// 2. Encrypt the secret value with the DEK.
	encryptedValue, valueNonce, err := crypto.Encrypt([]byte(value), dek)
	if err != nil {
		return fmt.Errorf("put secret %q: encrypt value: %w", path, err)
	}

	// 3. Encrypt the DEK with the Master Key.
	encryptedDEK, dekNonce, err := crypto.Encrypt(dek, s.masterKey)
	if err != nil {
		return fmt.Errorf("put secret %q: encrypt DEK: %w", path, err)
	}

	// 4. Upsert into the secrets table.
	now := time.Now().Unix()
	const q = `
		INSERT INTO secrets
			(path, encrypted_value, value_nonce, encrypted_dek, dek_nonce, version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 1, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			encrypted_value = excluded.encrypted_value,
			value_nonce     = excluded.value_nonce,
			encrypted_dek   = excluded.encrypted_dek,
			dek_nonce       = excluded.dek_nonce,
			version         = version + 1,
			updated_at      = excluded.updated_at
	`
	_, err = s.db.ExecContext(ctx, q,
		path,
		encryptedValue,
		valueNonce,
		encryptedDEK,
		dekNonce,
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("put secret %q: db upsert: %w", path, err)
	}
	return nil
}

// Get retrieves the secret at the given path, decrypts the DEK with the Master Key,
// then decrypts the value with the DEK. The DEK is zeroed from memory before returning.
func (s *SecretServiceImpl) Get(ctx context.Context, path string) (string, error) {
	const q = `
		SELECT encrypted_value, value_nonce, encrypted_dek, dek_nonce
		FROM secrets
		WHERE path = ?
	`
	var (
		encryptedValue []byte
		valueNonce     []byte
		encryptedDEK   []byte
		dekNonce       []byte
	)
	err := s.db.QueryRowContext(ctx, q, path).Scan(
		&encryptedValue,
		&valueNonce,
		&encryptedDEK,
		&dekNonce,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrSecretNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get secret %q: db query: %w", path, err)
	}

	// Decrypt the DEK using the Master Key.
	dek, err := crypto.Decrypt(encryptedDEK, dekNonce, s.masterKey)
	if err != nil {
		return "", fmt.Errorf("get secret %q: decrypt DEK: %w", path, err)
	}
	// Zero-out DEK plaintext from memory after this function returns.
	defer crypto.ZeroBytes(dek)

	// Decrypt the secret value using the DEK.
	plaintext, err := crypto.Decrypt(encryptedValue, valueNonce, dek)
	if err != nil {
		return "", fmt.Errorf("get secret %q: decrypt value: %w", path, err)
	}

	return string(plaintext), nil
}

// Delete removes the secret row (and its encrypted DEK) from the database.
// Returns ErrSecretNotFound if no row was affected.
func (s *SecretServiceImpl) Delete(ctx context.Context, path string) error {
	const q = `DELETE FROM secrets WHERE path = ?`
	res, err := s.db.ExecContext(ctx, q, path)
	if err != nil {
		return fmt.Errorf("delete secret %q: db exec: %w", path, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete secret %q: rows affected: %w", path, err)
	}
	if affected == 0 {
		return ErrSecretNotFound
	}
	return nil
}

// List returns all secret paths whose path column starts with prefix.
// The LIKE query pattern used is "prefix%" so it matches any path with that prefix.
// Returns an empty (non-nil) slice when no paths are found.
func (s *SecretServiceImpl) List(ctx context.Context, prefix string) ([]string, error) {
	const q = `SELECT path FROM secrets WHERE path LIKE ? ORDER BY path`
	// Escape any LIKE special characters in the prefix itself, then append '%'.
	pattern := escapeLike(prefix) + "%"

	rows, err := s.db.QueryContext(ctx, q, pattern)
	if err != nil {
		return nil, fmt.Errorf("list secrets prefix %q: db query: %w", prefix, err)
	}
	defer rows.Close()

	paths := []string{} // non-nil empty slice by default
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("list secrets prefix %q: scan: %w", prefix, err)
		}
		paths = append(paths, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list secrets prefix %q: rows iteration: %w", prefix, err)
	}
	return paths, nil
}

// escapeLike escapes special LIKE metacharacters (%, _, \) in s using backslash
// so that a raw prefix string can be safely used in a LIKE pattern.
func escapeLike(s string) string {
	out := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' || c == '_' || c == '\\' {
			out = append(out, '\\')
		}
		out = append(out, c)
	}
	return string(out)
}

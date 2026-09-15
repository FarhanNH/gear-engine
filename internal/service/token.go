package service

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gear/engine/internal/crypto"
	"github.com/gear/engine/internal/model"
)

// Sentinel errors untuk TokenService.
var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenRevoked  = errors.New("token has been revoked")
	ErrTokenExpired  = errors.New("token has expired")
)

// TokenService mendefinisikan operasi manajemen access token.
type TokenService interface {
	Create(ctx context.Context, name string, ttl time.Duration) (plaintext string, id int64, err error)
	Revoke(ctx context.Context, id int64) error
	Validate(ctx context.Context, plaintext string) (*model.Token, error)
	List(ctx context.Context) ([]model.Token, error)
}

// TokenServiceImpl adalah implementasi TokenService menggunakan SQLite.
type TokenServiceImpl struct {
	db *sql.DB
}

// NewTokenService membuat instance baru TokenServiceImpl.
func NewTokenService(db *sql.DB) *TokenServiceImpl {
	return &TokenServiceImpl{db: db}
}

// Create membuat token baru, menyimpan hash-nya ke DB, dan mengembalikan plaintext token sekali saja.
// Jika ttl > 0, token akan kedaluwarsa setelah durasi tersebut. Jika ttl == 0, token tidak kedaluwarsa.
func (s *TokenServiceImpl) Create(ctx context.Context, name string, ttl time.Duration) (plaintext string, id int64, err error) {
	plaintext, err = crypto.GenerateToken()
	if err != nil {
		return "", 0, err
	}

	tokenHash := crypto.HashToken(plaintext)
	createdAt := time.Now().Unix()

	var expiresAt *int64
	if ttl > 0 {
		exp := time.Now().Add(ttl).Unix()
		expiresAt = &exp
	}

	var result sql.Result
	if expiresAt != nil {
		result, err = s.db.ExecContext(ctx,
			`INSERT INTO tokens (name, token_hash, expires_at, revoked, created_at) VALUES (?, ?, ?, 0, ?)`,
			name, tokenHash, *expiresAt, createdAt,
		)
	} else {
		result, err = s.db.ExecContext(ctx,
			`INSERT INTO tokens (name, token_hash, expires_at, revoked, created_at) VALUES (?, ?, NULL, 0, ?)`,
			name, tokenHash, createdAt,
		)
	}
	if err != nil {
		return "", 0, err
	}

	id, err = result.LastInsertId()
	if err != nil {
		return "", 0, err
	}

	return plaintext, id, nil
}

// Validate memeriksa apakah token plaintext valid (ada, tidak di-revoke, belum kedaluwarsa).
// Mengembalikan *model.Token jika valid, atau sentinel error yang sesuai.
func (s *TokenServiceImpl) Validate(ctx context.Context, plaintext string) (*model.Token, error) {
	tokenHash := crypto.HashToken(plaintext)

	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, token_hash, expires_at, revoked, created_at FROM tokens WHERE token_hash = ?`,
		tokenHash,
	)

	var t model.Token
	var expiresAtUnix sql.NullInt64
	var revokedInt int
	var createdAtUnix int64

	err := row.Scan(&t.ID, &t.Name, &t.TokenHash, &expiresAtUnix, &revokedInt, &createdAtUnix)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	t.Revoked = revokedInt == 1
	t.CreatedAt = time.Unix(createdAtUnix, 0)

	if expiresAtUnix.Valid {
		exp := time.Unix(expiresAtUnix.Int64, 0)
		t.ExpiresAt = &exp
	}

	if t.Revoked {
		return nil, ErrTokenRevoked
	}

	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	return &t, nil
}

// Revoke menandai token sebagai di-revoke berdasarkan ID-nya.
// Mengembalikan ErrTokenNotFound jika tidak ada token dengan ID tersebut.
func (s *TokenServiceImpl) Revoke(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE tokens SET revoked = 1 WHERE id = ?`,
		id,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrTokenNotFound
	}

	return nil
}

// List mengembalikan semua token diurutkan dari yang terbaru.
func (s *TokenServiceImpl) List(ctx context.Context) ([]model.Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, token_hash, expires_at, revoked, created_at FROM tokens ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []model.Token
	for rows.Next() {
		var t model.Token
		var expiresAtUnix sql.NullInt64
		var revokedInt int
		var createdAtUnix int64

		if err := rows.Scan(&t.ID, &t.Name, &t.TokenHash, &expiresAtUnix, &revokedInt, &createdAtUnix); err != nil {
			return nil, err
		}

		t.Revoked = revokedInt == 1
		t.CreatedAt = time.Unix(createdAtUnix, 0)

		if expiresAtUnix.Valid {
			exp := time.Unix(expiresAtUnix.Int64, 0)
			t.ExpiresAt = &exp
		}

		tokens = append(tokens, t)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tokens, nil
}

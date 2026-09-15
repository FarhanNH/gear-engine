package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gear/engine/internal/model"
)

// ErrPolicyNotFound dikembalikan ketika policy dengan ID yang diminta tidak ditemukan.
var ErrPolicyNotFound = errors.New("policy not found")

// PolicyService mendefinisikan operasi manajemen access policy per token.
type PolicyService interface {
	Create(ctx context.Context, tokenID int64, pathPattern string, perms []string) error
	Delete(ctx context.Context, id int64) error
	Evaluate(ctx context.Context, tokenID int64, path, action string) (bool, error)
}

// PolicyServiceImpl adalah implementasi PolicyService menggunakan SQLite.
type PolicyServiceImpl struct {
	db *sql.DB
}

// NewPolicyService membuat instance baru PolicyServiceImpl.
func NewPolicyService(db *sql.DB) *PolicyServiceImpl {
	return &PolicyServiceImpl{db: db}
}

// Create membuat policy baru untuk tokenID dengan path pattern dan permissions yang diberikan.
// perms adalah slice string yang dapat berisi "read", "write", dan/atau "delete".
func (s *PolicyServiceImpl) Create(ctx context.Context, tokenID int64, pathPattern string, perms []string) error {
	var canRead, canWrite, canDelete bool
	for _, p := range perms {
		switch strings.ToLower(p) {
		case "read":
			canRead = true
		case "write":
			canWrite = true
		case "delete":
			canDelete = true
		}
	}

	createdAt := time.Now().Unix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO policies (token_id, path_pattern, can_read, can_write, can_delete, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		tokenID,
		pathPattern,
		boolToInt(canRead),
		boolToInt(canWrite),
		boolToInt(canDelete),
		createdAt,
	)
	if err != nil {
		return fmt.Errorf("create policy for token %d: %w", tokenID, err)
	}
	return nil
}

// Delete menghapus policy berdasarkan ID-nya.
// Mengembalikan ErrPolicyNotFound jika tidak ada policy dengan ID tersebut.
func (s *PolicyServiceImpl) Delete(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM policies WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("delete policy %d: %w", id, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete policy %d: rows affected: %w", id, err)
	}
	if rows == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

// Evaluate memeriksa apakah tokenID memiliki izin untuk melakukan action pada path.
// Action yang valid: "read", "write", "delete".
//
// Logika pencocokan path:
//   - Exact match: path == pathPattern
//   - Wildcard suffix: jika pathPattern berakhir dengan "/*",
//     path harus memiliki prefix yang sama (sebelum "*").
//     Contoh: pattern "app/*" cocok dengan "app/db", "app/db/password", tapi tidak "app".
//
// Mengembalikan true hanya jika ditemukan policy yang cocok DAN memiliki permission yang diminta.
// Mengembalikan false (bukan error) jika tidak ada policy yang cocok.
func (s *PolicyServiceImpl) Evaluate(ctx context.Context, tokenID int64, path, action string) (bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT path_pattern, can_read, can_write, can_delete
		 FROM policies
		 WHERE token_id = ?`,
		tokenID,
	)
	if err != nil {
		return false, fmt.Errorf("evaluate policy for token %d: %w", tokenID, err)
	}
	defer rows.Close()

	for rows.Next() {
		var pathPattern string
		var canReadInt, canWriteInt, canDeleteInt int

		if err := rows.Scan(&pathPattern, &canReadInt, &canWriteInt, &canDeleteInt); err != nil {
			return false, fmt.Errorf("evaluate policy for token %d: scan: %w", tokenID, err)
		}

		if !matchPath(path, pathPattern) {
			continue
		}

		// Path cocok; periksa permission untuk action yang diminta.
		switch strings.ToLower(action) {
		case "read":
			if canReadInt == 1 {
				return true, nil
			}
		case "write":
			if canWriteInt == 1 {
				return true, nil
			}
		case "delete":
			if canDeleteInt == 1 {
				return true, nil
			}
		}
	}

	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("evaluate policy for token %d: rows iteration: %w", tokenID, err)
	}

	// Tidak ada policy yang cocok dengan permission yang diminta.
	return false, nil
}

// ListByToken mengembalikan semua policy yang dimiliki oleh tokenID.
// Digunakan oleh admin handler untuk menampilkan policy per token.
func (s *PolicyServiceImpl) ListByToken(ctx context.Context, tokenID int64) ([]model.Policy, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, token_id, path_pattern, can_read, can_write, can_delete, created_at
		 FROM policies
		 WHERE token_id = ?
		 ORDER BY created_at DESC`,
		tokenID,
	)
	if err != nil {
		return nil, fmt.Errorf("list policies for token %d: %w", tokenID, err)
	}
	defer rows.Close()

	return scanPolicies(rows)
}

// ListAll mengembalikan semua policy yang tersimpan di database.
// Digunakan oleh admin handler untuk menampilkan seluruh daftar policy.
func (s *PolicyServiceImpl) ListAll(ctx context.Context) ([]model.Policy, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, token_id, path_pattern, can_read, can_write, can_delete, created_at
		 FROM policies
		 ORDER BY token_id, created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list all policies: %w", err)
	}
	defer rows.Close()

	return scanPolicies(rows)
}

// matchPath memeriksa apakah path cocok dengan pathPattern.
//
// Aturan pencocokan:
//  1. Exact match: path == pathPattern
//  2. Wildcard suffix: jika pathPattern berakhir dengan "/*",
//     prefix diambil dari pathPattern dengan memotong karakter "*" di akhir.
//     path harus memiliki HasPrefix(path, prefix) di mana prefix = pathPattern tanpa "*".
//     Ini memungkinkan "app/*" mencocokkan "app/db", "app/db/password", dst.
//     Namun "app/" sendiri (prefix tanpa komponen setelahnya) juga dicocokkan
//     dengan memeriksa apakah path == strings.TrimSuffix(prefix, "/").
func matchPath(path, pathPattern string) bool {
	// Exact match.
	if path == pathPattern {
		return true
	}

	// Wildcard suffix: pattern harus berakhir dengan "/*".
	if !strings.HasSuffix(pathPattern, "/*") {
		return false
	}

	// Prefix adalah pathPattern tanpa "*" di akhir, misalnya "app/*" → prefix = "app/".
	prefix := pathPattern[:len(pathPattern)-1] // buang "*", sisakan "app/"

	// path harus dimulai dengan prefix tersebut, contoh: "app/db" starts with "app/".
	return strings.HasPrefix(path, prefix)
}

// scanPolicies membaca rows hasil query dan mengembalikan slice model.Policy.
func scanPolicies(rows *sql.Rows) ([]model.Policy, error) {
	var policies []model.Policy
	for rows.Next() {
		var p model.Policy
		var canReadInt, canWriteInt, canDeleteInt int
		var createdAtUnix int64

		if err := rows.Scan(
			&p.ID,
			&p.TokenID,
			&p.PathPattern,
			&canReadInt,
			&canWriteInt,
			&canDeleteInt,
			&createdAtUnix,
		); err != nil {
			return nil, err
		}

		p.CanRead = canReadInt == 1
		p.CanWrite = canWriteInt == 1
		p.CanDelete = canDeleteInt == 1
		p.CreatedAt = time.Unix(createdAtUnix, 0)

		policies = append(policies, p)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return policies, nil
}

// boolToInt mengkonversi bool ke int (0 atau 1) untuk penyimpanan di SQLite.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

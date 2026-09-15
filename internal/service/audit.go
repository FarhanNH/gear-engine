package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gear/engine/internal/model"
)

const (
	auditDefaultLimit = 100
	auditMaxLimit     = 1000
)

// AuditService mendefinisikan operasi pencatatan dan pembacaan audit log.
// Log TIDAK pernah mencatat nilai secret, password, atau credential plaintext —
// hanya metadata akses (token ID, path, action, result, IP, timestamp).
type AuditService interface {
	Log(ctx context.Context, entry model.AuditEntry) error
	Query(ctx context.Context, filter model.AuditFilter) ([]model.AuditEntry, error)
}

// AuditServiceImpl adalah implementasi AuditService menggunakan SQLite.
type AuditServiceImpl struct {
	db *sql.DB
}

// NewAuditService membuat instance baru AuditServiceImpl.
func NewAuditService(db *sql.DB) *AuditServiceImpl {
	return &AuditServiceImpl{db: db}
}

// Log mencatat satu audit entry ke tabel audit_log.
// Jika entry.Timestamp adalah zero value, diisi dengan time.Now().
// Nilai secret, password, dan credential plaintext TIDAK BOLEH ada dalam entry yang dikirim;
// fungsi ini hanya menyimpan metadata yang diterima tanpa transformasi.
func (s *AuditServiceImpl) Log(ctx context.Context, entry model.AuditEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Konversi pointer fields ke sql.Null* untuk penanganan NULL yang benar.
	var tokenID sql.NullInt64
	if entry.TokenID != nil {
		tokenID = sql.NullInt64{Int64: *entry.TokenID, Valid: true}
	}

	var tokenName sql.NullString
	if entry.TokenName != nil {
		tokenName = sql.NullString{String: *entry.TokenName, Valid: true}
	}

	var path sql.NullString
	if entry.Path != nil {
		path = sql.NullString{String: *entry.Path, Valid: true}
	}

	var errorCode sql.NullInt64
	if entry.ErrorCode != nil {
		errorCode = sql.NullInt64{Int64: int64(*entry.ErrorCode), Valid: true}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log
			(token_id, token_name, path, action, result, error_code, ip_address, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tokenID,
		tokenName,
		path,
		entry.Action,
		entry.Result,
		errorCode,
		entry.IPAddress,
		entry.Timestamp.UnixNano(),
	)
	return err
}

// Query mengambil audit entries berdasarkan filter yang diberikan.
// Filter nil berarti tidak difilter. Limit default 100, maksimum 1000.
// Hasil diurutkan dari yang terbaru (timestamp DESC).
func (s *AuditServiceImpl) Query(ctx context.Context, filter model.AuditFilter) ([]model.AuditEntry, error) {
	// Terapkan default dan cap pada Limit.
	limit := filter.Limit
	if limit <= 0 {
		limit = auditDefaultLimit
	}
	if limit > auditMaxLimit {
		limit = auditMaxLimit
	}

	// Bangun WHERE clauses secara dinamis.
	var conditions []string
	var args []interface{}

	if filter.TokenID != nil {
		conditions = append(conditions, "token_id = ?")
		args = append(args, *filter.TokenID)
	}

	if filter.Path != nil {
		conditions = append(conditions, "path LIKE ?")
		args = append(args, *filter.Path+"%")
	}

	if filter.Since != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.Since.UnixNano())
	}

	if filter.Until != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.Until.UnixNano())
	}

	if filter.Result != nil {
		conditions = append(conditions, "result = ?")
		args = append(args, *filter.Result)
	}

	query := `SELECT id, token_id, token_name, path, action, result, error_code, ip_address, timestamp
	          FROM audit_log`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT %d OFFSET %d", limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		var tokenID sql.NullInt64
		var tokenName sql.NullString
		var path sql.NullString
		var errorCode sql.NullInt64
		var timestampNano int64

		if err := rows.Scan(
			&e.ID,
			&tokenID,
			&tokenName,
			&path,
			&e.Action,
			&e.Result,
			&errorCode,
			&e.IPAddress,
			&timestampNano,
		); err != nil {
			return nil, err
		}

		if tokenID.Valid {
			e.TokenID = &tokenID.Int64
		}
		if tokenName.Valid {
			e.TokenName = &tokenName.String
		}
		if path.Valid {
			e.Path = &path.String
		}
		if errorCode.Valid {
			code := int(errorCode.Int64)
			e.ErrorCode = &code
		}
		e.Timestamp = time.Unix(0, timestampNano)

		entries = append(entries, e)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

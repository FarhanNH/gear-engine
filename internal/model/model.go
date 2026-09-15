package model

import "time"

// Secret merepresentasikan satu secret yang disimpan dengan envelope encryption.
// EncryptedValue dan ValueNonce adalah hasil AES-256-GCM enkripsi nilai secret menggunakan DEK.
// EncryptedDEK dan DEKNonce adalah hasil AES-256-GCM enkripsi DEK menggunakan Master Key.
type Secret struct {
	ID             int64
	Path           string
	EncryptedValue []byte
	ValueNonce     []byte
	EncryptedDEK   []byte
	DEKNonce       []byte
	Version        int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Token merepresentasikan access token untuk autentikasi API.
// TokenHash menyimpan SHA-256 hex dari plaintext token — plaintext tidak pernah disimpan.
// ExpiresAt adalah pointer karena nilai NULL (no expiry) diperbolehkan.
type Token struct {
	ID        int64
	Name      string
	TokenHash string // hex SHA-256
	ExpiresAt *time.Time
	Revoked   bool
	CreatedAt time.Time
}

// Policy mendefinisikan permission akses sebuah token ke path pattern tertentu.
// PathPattern mendukung wildcard '*' di akhir (contoh: "app/*").
type Policy struct {
	ID          int64
	TokenID     int64
	PathPattern string
	CanRead     bool
	CanWrite    bool
	CanDelete   bool
	CreatedAt   time.Time
}

// AuditEntry adalah satu baris di audit log.
// TokenID, TokenName, Path, dan ErrorCode menggunakan pointer karena bisa NULL
// (contoh: request unauthenticated tidak memiliki TokenID, aksi login tidak memiliki Path).
type AuditEntry struct {
	ID        int64
	TokenID   *int64
	TokenName *string
	Path      *string
	Action    string
	Result    string
	ErrorCode *int
	IPAddress string
	Timestamp time.Time
}

// AuditFilter digunakan untuk mem-filter query audit log.
// Field pointer berarti filter opsional — nil berarti tidak difilter.
// Limit dan Offset digunakan untuk paginasi.
type AuditFilter struct {
	TokenID *int64
	Path    *string
	Since   *time.Time
	Until   *time.Time
	Result  *string
	Limit   int
	Offset  int
}

// Admin merepresentasikan akun administrator (single admin di Phase 1).
// PasswordHash menyimpan bcrypt atau argon2id hash dari password plaintext.
type Admin struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

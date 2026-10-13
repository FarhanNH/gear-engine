package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gear/engine/internal/crypto"
	"github.com/gear/engine/internal/middleware"
	"github.com/gear/engine/internal/service"
)

// AuthHandler menangani endpoint autentikasi admin.
type AuthHandler struct {
	db         *sql.DB
	tokenSvc   service.TokenService
	sessionTTL time.Duration
	bcrypt     func(hash, password string) error
}

// NewAuthHandler membuat instance baru AuthHandler.
func NewAuthHandler(db *sql.DB, tokenSvc service.TokenService, sessionTTL time.Duration) *AuthHandler {
	return &AuthHandler{
		db:         db,
		tokenSvc:   tokenSvc,
		sessionTTL: sessionTTL,
		bcrypt:     crypto.VerifyPassword,
	}
}

// loginRequest adalah body request untuk POST /v1/auth/login.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginResponse adalah body response sukses dari POST /v1/auth/login.
type loginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// writeAuthError menulis response 401 dengan pesan generic (tanpa detail).
// Selalu menggunakan pesan yang sama untuk mencegah user enumeration.
func writeAuthError(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "invalid credentials")
}

// Login menangani POST /v1/auth/login.
// Memvalidasi username/password, mengembalikan session token jika valid.
// TIDAK pernah mencatat password di log.
//
// Requirements: 3.1, 3.2, 3.3, 3.5, 7.6
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// 1. Decode JSON body.
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// 2. Query password hash dari DB berdasarkan username.
	// CATATAN: password dari req TIDAK pernah dilog di sini maupun di bawah.
	var passwordHash string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT password_hash FROM admins WHERE username = ?`,
		req.Username,
	).Scan(&passwordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Username tidak ditemukan — return 401 tanpa detail untuk mencegah user enumeration.
			writeAuthError(w)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// 3. Verifikasi password menggunakan bcrypt.
	// Return 401 dengan pesan yang sama jika tidak cocok (mencegah timing/enumeration attack).
	if err := h.bcrypt(passwordHash, req.Password); err != nil {
		writeAuthError(w)
		return
	}

	// 4. Buat session token.
	plaintext, _, err := h.tokenSvc.Create(r.Context(), "admin-session", h.sessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// 5. Return token + expires_at.
	expiresAt := time.Now().Add(h.sessionTTL).UTC().Format(time.RFC3339)
	writeJSON(w, http.StatusOK, loginResponse{
		Token:     plaintext,
		ExpiresAt: expiresAt,
	})
}

// changePasswordRequest adalah body request untuk POST /v1/auth/change-password.
type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword menangani POST /v1/auth/change-password.
// Memverifikasi password saat ini lalu menggantinya dengan password baru.
//
// Single-admin system: query `SELECT id, password_hash FROM admins LIMIT 1`
// karena sesi tidak menyimpan identitas admin (hanya token.ID dan token.Name).
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	// 1. Pastikan request sudah terautentikasi.
	if middleware.TokenIDFromContext(r.Context()) == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// 2. Decode request body.
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}

	// 3. Ambil id dan password_hash admin saat ini (single-admin system).
	var adminID int64
	var passwordHash string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT id, password_hash FROM admins LIMIT 1`,
	).Scan(&adminID, &passwordHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// 4. Verifikasi password saat ini.
	if err := h.bcrypt(passwordHash, req.CurrentPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// 5. Hash password baru.
	newHash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// 6. Update password hash di DB.
	if _, err := h.db.ExecContext(r.Context(),
		`UPDATE admins SET password_hash = ? WHERE id = ?`,
		newHash, adminID,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// 7. Return 204 No Content.
	w.WriteHeader(http.StatusNoContent)
}

// Logout menangani POST /v1/auth/logout.
// Me-revoke session token yang aktif dari context.
//
// Requirements: 3.2, 3.5
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// 1. Ambil token ID dari context (di-set oleh AuthMiddleware).
	tokenID := middleware.TokenIDFromContext(r.Context())
	if tokenID == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// 2. Revoke token.
	if err := h.tokenSvc.Revoke(r.Context(), *tokenID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// 3. Return 204 No Content.
	w.WriteHeader(http.StatusNoContent)
}

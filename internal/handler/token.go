package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gear/engine/internal/service"
)

// TokenHandler menangani endpoint manajemen access token.
type TokenHandler struct {
	service service.TokenService
}

// NewTokenHandler membuat instance baru TokenHandler.
func NewTokenHandler(svc service.TokenService) *TokenHandler {
	return &TokenHandler{service: svc}
}

// createTokenRequest adalah body request untuk POST /v1/token.
type createTokenRequest struct {
	Name string `json:"name"`
	TTL  string `json:"ttl"`
}

// createTokenResponse adalah body response sukses dari POST /v1/token.
// Field Token (plaintext) hanya muncul di response ini — tidak pernah lagi.
type createTokenResponse struct {
	ID        int64  `json:"id"`
	Token     string `json:"token"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// listTokenItem adalah representasi token dalam daftar — tanpa plaintext.
type listTokenItem struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Revoked   bool   `json:"revoked"`
	CreatedAt string `json:"created_at"`
}

// CreateToken menangani POST /v1/token.
// Parse TTL dari string (contoh: "720h"), buat token baru, return 201 dengan plaintext token.
// Plaintext token HANYA dikembalikan di sini — tidak pernah di endpoint lain.
//
// Requirements: 4.1, 4.2, 4.3, 4.4
func (h *TokenHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	// 1. Decode JSON body.
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	if req.TTL == "" {
		writeError(w, http.StatusBadRequest, "ttl is required")
		return
	}

	// 2. Parse TTL dari string — return 400 jika tidak valid.
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ttl: must be a valid duration (e.g. \"720h\")")
		return
	}

	// 3. Buat token via service.
	plaintext, id, err := h.service.Create(r.Context(), req.Name, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	// 4. Hitung expires_at dari TTL.
	var expiresAt string
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl).UTC().Format(time.RFC3339)
	}

	// 5. Return 201 dengan plaintext token (sekali saja).
	writeJSON(w, http.StatusCreated, createTokenResponse{
		ID:        id,
		Token:     plaintext,
		Name:      req.Name,
		ExpiresAt: expiresAt,
	})
}

// ListTokens menangani GET /v1/token.
// Mengembalikan semua token tanpa plaintext.
//
// Requirements: 4.3, 4.4
func (h *TokenHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	// 1. Ambil semua token dari service.
	tokens, err := h.service.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}

	// 2. Map ke response struct — tanpa plaintext token.
	items := make([]listTokenItem, 0, len(tokens))
	for _, t := range tokens {
		item := listTokenItem{
			ID:        t.ID,
			Name:      t.Name,
			Revoked:   t.Revoked,
			CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339),
		}
		if t.ExpiresAt != nil {
			item.ExpiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}

	// 3. Return 200.
	writeJSON(w, http.StatusOK, map[string]any{
		"tokens": items,
	})
}

// RevokeToken menangani DELETE /v1/token/{id}.
// Return 204 jika berhasil, 404 jika token tidak ditemukan.
//
// Requirements: 4.5, 4.6, 4.7
func (h *TokenHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	// 1. Ekstrak ID dari URL path: strip "/v1/token/" dan parse sebagai int64.
	rawID := strings.TrimPrefix(r.URL.Path, "/v1/token/")
	if rawID == "" {
		writeError(w, http.StatusBadRequest, "token id is required")
		return
	}

	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id: must be an integer")
		return
	}

	// 2. Revoke via service.
	if err := h.service.Revoke(r.Context(), id); err != nil {
		if errors.Is(err, service.ErrTokenNotFound) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}

	// 3. Return 204 No Content.
	w.WriteHeader(http.StatusNoContent)
}

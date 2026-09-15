package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gear/engine/internal/service"
)

// contextKey adalah tipe private untuk menghindari collision context keys.
type contextKey int

const (
	contextKeyTokenID   contextKey = iota
	contextKeyTokenName contextKey = iota
)

// TokenIDFromContext mengambil token ID yang di-set oleh AuthMiddleware dari context.
// Mengembalikan nil jika tidak ada (request unauthenticated).
func TokenIDFromContext(ctx context.Context) *int64 {
	v, _ := ctx.Value(contextKeyTokenID).(*int64)
	return v
}

// TokenNameFromContext mengambil token name yang di-set oleh AuthMiddleware dari context.
// Mengembalikan nil jika tidak ada (request unauthenticated).
func TokenNameFromContext(ctx context.Context) *string {
	v, _ := ctx.Value(contextKeyTokenName).(*string)
	return v
}

// WithTokenID menyimpan token ID ke context (dipakai oleh AuthMiddleware).
func WithTokenID(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, contextKeyTokenID, &id)
}

// WithTokenName menyimpan token name ke context (dipakai oleh AuthMiddleware).
func WithTokenName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, contextKeyTokenName, &name)
}

// writeJSONError writes a JSON error response with the given status code and message.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// AuthMiddleware validates the Bearer token from the Authorization header.
// It skips authentication for POST /v1/auth/login.
// On success, it stores the token ID and name in the request context.
//
// Validates: Requirements 3.2, 4.6, 9.1
func AuthMiddleware(tokenSvc service.TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip authentication for the login endpoint.
			if r.URL.Path == "/v1/auth/login" {
				next.ServeHTTP(w, r)
				return
			}

			// Extract Bearer token from Authorization header.
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			const prefix = "Bearer "
			if !strings.HasPrefix(authHeader, prefix) {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			plaintext := strings.TrimPrefix(authHeader, prefix)
			if plaintext == "" {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			// Validate the token: hash it, look up in DB, check revoked/expiry.
			tok, err := tokenSvc.Validate(r.Context(), plaintext)
			if err != nil {
				if errors.Is(err, service.ErrTokenNotFound) ||
					errors.Is(err, service.ErrTokenRevoked) ||
					errors.Is(err, service.ErrTokenExpired) {
					writeJSONError(w, http.StatusUnauthorized, "unauthorized")
					return
				}
				writeJSONError(w, http.StatusInternalServerError, "internal server error")
				return
			}

			// Store token metadata in context for downstream use.
			ctx := WithTokenID(r.Context(), tok.ID)
			ctx = WithTokenName(ctx, tok.Name)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

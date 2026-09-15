package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/gear/engine/internal/model"
	"github.com/gear/engine/internal/service"
)

// responseWriter wraps http.ResponseWriter untuk intercept status code yang ditulis handler.
// Default status code adalah 200 jika WriteHeader tidak pernah dipanggil.
type responseWriter struct {
	http.ResponseWriter
	statusCode    int
	headerWritten bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// WriteHeader intercepts status code dan meneruskan ke underlying ResponseWriter.
func (rw *responseWriter) WriteHeader(code int) {
	if !rw.headerWritten {
		rw.statusCode = code
		rw.headerWritten = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

// Write meneruskan body ke underlying ResponseWriter.
// Jika WriteHeader belum pernah dipanggil, header dianggap sudah tertulis dengan status 200.
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.headerWritten = true
		// statusCode sudah di-default ke 200 saat konstruksi
	}
	return rw.ResponseWriter.Write(b)
}

// methodToAction memetakan HTTP method ke string action untuk audit log.
func methodToAction(method string) string {
	switch method {
	case http.MethodGet:
		return "read"
	case http.MethodPut:
		return "write"
	case http.MethodDelete:
		return "delete"
	case http.MethodPost:
		return "create"
	default:
		return "access"
	}
}

// extractIPFromAddr mengambil IP address dari RemoteAddr string, membuang port jika ada.
func extractIPFromAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// RemoteAddr tidak memiliki port (jarang terjadi), gunakan langsung
		return remoteAddr
	}
	return host
}

// AuditMiddleware adalah middleware yang mencatat pre-request audit log (access attempt)
// SEBELUM meneruskan request ke handler. Ini memastikan setiap akses tercatat meskipun
// handler atau respons gagal di tengah jalan.
//
// Jika Log() gagal → kembalikan HTTP 500 dan JANGAN teruskan ke handler (requirement 7.5).
// Nilai secret TIDAK PERNAH dicatat — hanya metadata (path, action, IP, token ID/name).
//
// Validates: Requirements 7.1, 7.4, 7.5
func AuditMiddleware(auditSvc service.AuditService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Ambil token metadata dari context (di-set oleh AuthMiddleware sebelumnya).
			tokenID := TokenIDFromContext(ctx)
			tokenName := TokenNameFromContext(ctx)

			// Bangun path pointer — path selalu ada untuk request HTTP.
			path := r.URL.Path

			// Buat pre-request audit entry: result "attempt" karena handler belum dipanggil.
			preEntry := model.AuditEntry{
				TokenID:   tokenID,
				TokenName: tokenName,
				Path:      &path,
				Action:    methodToAction(r.Method),
				Result:    "attempt",
				IPAddress: extractIPFromAddr(r.RemoteAddr),
				Timestamp: time.Now(),
			}

			// Log pre-request entry SEBELUM memanggil handler.
			// Jika gagal → reject request dengan HTTP 500 (requirement 7.5).
			if err := auditSvc.Log(ctx, preEntry); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "audit log failed"})
				return
			}

			// Pre-request log berhasil — teruskan ke handler dengan wrapped ResponseWriter.
			rw := newResponseWriter(w)
			next.ServeHTTP(rw, r)
		})
	}
}

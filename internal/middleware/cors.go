package middleware

import (
	"net/http"
)

// isAllowed checks whether the given origin is present in the allowed list.
// Comparison is case-sensitive exact match.
func isAllowed(origin string, allowed []string) bool {
	if origin == "" {
		return false
	}
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}

// CORSMiddleware validates the Origin request header against a whitelist.
// Supports one or more origins via the allowedOrigins slice (populated from
// GEAR_CORS_ORIGIN, comma-separated, by the config layer).
//
// Behaviour:
//   - If the Origin is in the whitelist, the four CORS response headers are set.
//   - If the Origin is NOT in the whitelist, no CORS headers are set and the
//     browser will block the cross-origin request on its own.
//   - Pre-flight OPTIONS requests receive a 204 No Content response immediately,
//     without forwarding to the next handler, regardless of whether the origin is
//     allowed (returning 204 unconditionally is the standard CORS pre-flight pattern).
//   - If allowedOrigins is empty, no CORS headers are ever set.
//
// Validates: Requirements 8.2, 9.1
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if isAllowed(origin, allowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// Respond to pre-flight OPTIONS without invoking the downstream handler.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

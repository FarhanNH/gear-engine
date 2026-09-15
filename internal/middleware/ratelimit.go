package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ipEntry menyimpan daftar timestamp percobaan login untuk satu IP (sliding window).
type ipEntry struct {
	attempts []time.Time
}

// rateLimiter adalah in-memory store per-IP dengan sliding window counter.
type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*ipEntry
	max     int
	window  time.Duration
}

// newRateLimiter membuat instance rateLimiter baru dan menjalankan goroutine cleanup.
func newRateLimiter(max int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		entries: make(map[string]*ipEntry),
		max:     max,
		window:  window,
	}
	go rl.cleanupLoop()
	return rl
}

// cleanupLoop menjalankan pembersihan entry stale secara berkala untuk mencegah memory leak.
func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-rl.window)
		for ip, entry := range rl.entries {
			// Hapus timestamps yang sudah keluar dari window.
			filtered := entry.attempts[:0]
			for _, t := range entry.attempts {
				if t.After(cutoff) {
					filtered = append(filtered, t)
				}
			}
			if len(filtered) == 0 {
				delete(rl.entries, ip)
			} else {
				entry.attempts = filtered
			}
		}
		rl.mu.Unlock()
	}
}

// allow memeriksa apakah IP diizinkan (belum melebihi limit).
// Jika masih diizinkan, catat percobaan baru dan kembalikan (true, 0).
// Jika sudah melebihi limit, kembalikan (false, retryAfterSeconds).
func (rl *rateLimiter) allow(ip string) (allowed bool, retryAfter int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	entry, ok := rl.entries[ip]
	if !ok {
		entry = &ipEntry{}
		rl.entries[ip] = entry
	}

	// Hapus entri yang sudah keluar dari sliding window.
	filtered := entry.attempts[:0]
	for _, t := range entry.attempts {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	entry.attempts = filtered

	if len(entry.attempts) >= rl.max {
		// Hitung Retry-After: saat entry tertua keluar dari window.
		oldest := entry.attempts[0]
		retryAt := oldest.Add(rl.window)
		secs := int(time.Until(retryAt).Seconds()) + 1
		if secs < 1 {
			secs = 1
		}
		return false, secs
	}

	// Catat percobaan baru.
	entry.attempts = append(entry.attempts, now)
	return true, 0
}

// extractClientIP mengekstrak IP klien dari request dengan prioritas:
// 1) X-Real-IP header
// 2) X-Forwarded-For header (IP pertama dalam list)
// 3) r.RemoteAddr (strip port)
//
// Validasi: hanya menerima header proxy jika nilainya berupa IP valid untuk
// menghindari spoofing dengan nilai sembarang.
func extractClientIP(r *http.Request) string {
	// 1. X-Real-IP (biasanya di-set oleh nginx secara tepercaya)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
			return ip.String()
		}
	}

	// 2. X-Forwarded-For — ambil IP pertama (client IP), validasi format.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Format: "client, proxy1, proxy2"
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			candidate := strings.TrimSpace(parts[0])
			if ip := net.ParseIP(candidate); ip != nil {
				return ip.String()
			}
		}
	}

	// 3. Fallback ke RemoteAddr, strip port.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr tanpa port (edge case)
		if ip := net.ParseIP(r.RemoteAddr); ip != nil {
			return ip.String()
		}
		return r.RemoteAddr
	}
	return host
}

// RateLimitMiddleware mengembalikan middleware yang membatasi percobaan login per IP
// menggunakan algoritma sliding window in-memory.
//
// Hanya berlaku untuk path yang mengandung "/v1/auth/login".
// Request yang melebihi limit akan menerima HTTP 429 dengan header Retry-After.
//
// Parameter:
//   - max: jumlah maksimum percobaan per window per IP
//   - window: durasi sliding window
//
// Konfigurasi via env var: GEAR_RATE_LIMIT_MAX dan GEAR_RATE_LIMIT_WINDOW
//
// Validates: Requirements 3.4
func RateLimitMiddleware(max int, window time.Duration) func(http.Handler) http.Handler {
	rl := newRateLimiter(max, window)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Hanya rate-limit path login.
			if !strings.Contains(r.URL.Path, "/v1/auth/login") {
				next.ServeHTTP(w, r)
				return
			}

			ip := extractClientIP(r)
			allowed, retryAfter := rl.allow(ip)
			if !allowed {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", itoa(retryAfter))
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":       "too many requests",
					"retry_after": retryAfter,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// itoa mengkonversi int ke string tanpa import strconv tambahan
// (dipakai untuk set header Retry-After).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

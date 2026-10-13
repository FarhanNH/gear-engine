package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// LoginRateLimiter atomically checks and records a login attempt for an IP.
type LoginRateLimiter interface {
	Allow(ctx context.Context, ip string) (allowed bool, retryAfter int, err error)
}

// RedisRateLimiter stores login attempts in a Redis sorted set so every
// application replica shares the same sliding-window counter.
type RedisRateLimiter struct {
	client redis.UniversalClient
	max    int
	window time.Duration
	prefix string
}

// NewRedisRateLimiter constructs a Redis-backed login rate limiter.
func NewRedisRateLimiter(client redis.UniversalClient, max int, window time.Duration) *RedisRateLimiter {
	return &RedisRateLimiter{
		client: client,
		max:    max,
		window: window,
		prefix: "gear:ratelimit:login:",
	}
}

// allowScript performs cleanup, limit check, and insertion as one atomic Redis
// operation. Redis TIME keeps all replicas on the same clock.
var allowScript = redis.NewScript(`
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000000 + tonumber(time[2])
local window = tonumber(ARGV[2])
local cutoff = now - window

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
local count = redis.call('ZCARD', KEYS[1])
if count >= tonumber(ARGV[1]) then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  local retry = math.ceil((tonumber(oldest[2]) + window - now) / 1000000)
  if retry < 1 then retry = 1 end
  return {0, retry}
end

redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], math.ceil(window / 1000))
return {1, 0}
`)

// Allow returns whether the request is within the configured sliding window.
func (rl *RedisRateLimiter) Allow(ctx context.Context, ip string) (bool, int, error) {
	var memberBytes [16]byte
	if _, err := rand.Read(memberBytes[:]); err != nil {
		return false, 0, fmt.Errorf("generate rate limit member: %w", err)
	}

	keyHash := sha256.Sum256([]byte(ip))
	key := rl.prefix + hex.EncodeToString(keyHash[:])
	result, err := allowScript.Run(
		ctx,
		rl.client,
		[]string{key},
		int64(rl.max),
		rl.window.Microseconds(),
		hex.EncodeToString(memberBytes[:]),
	).Int64Slice()
	if err != nil {
		return false, 0, fmt.Errorf("check Redis rate limit: %w", err)
	}
	if len(result) != 2 {
		return false, 0, fmt.Errorf("unexpected Redis rate limit response length %d", len(result))
	}
	return result[0] == 1, int(result[1]), nil
}

// extractClientIP extracts the client IP, preferring proxy headers only when
// the header value is a valid IP address.
func extractClientIP(r *http.Request) string {
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
			return ip.String()
		}
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
				return ip.String()
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if ip := net.ParseIP(r.RemoteAddr); ip != nil {
			return ip.String()
		}
		return r.RemoteAddr
	}
	return host
}

// RateLimitMiddleware limits login attempts per IP using a shared limiter.
// Requests above the limit receive HTTP 429 and a Retry-After header. If the
// shared limiter is unavailable, login fails closed with HTTP 503.
func RateLimitMiddleware(limiter LoginRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Path, "/v1/auth/login") {
				next.ServeHTTP(w, r)
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			allowed, retryAfter, err := limiter.Allow(ctx, extractClientIP(r))
			if err != nil {
				log.Printf("WARN: login rate limiter unavailable: %v", err)
				writeRateLimitError(w, http.StatusServiceUnavailable, "rate limiter unavailable", 0)
				return
			}
			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				writeRateLimitError(w, http.StatusTooManyRequests, "too many requests", retryAfter)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeRateLimitError(w http.ResponseWriter, status int, message string, retryAfter int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	response := map[string]any{"error": message}
	if retryAfter > 0 {
		response["retry_after"] = retryAfter
	}
	_ = json.NewEncoder(w).Encode(response)
}

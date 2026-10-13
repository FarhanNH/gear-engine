package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gear/engine/internal/middleware"
	"github.com/gear/engine/internal/model"
	"github.com/gear/engine/internal/service"
)

// ─── Mock implementations ────────────────────────────────────────────────────

// mockTokenService implements service.TokenService for testing.
type mockTokenService struct {
	validateFn func(ctx context.Context, plaintext string) (*model.Token, error)
}

func (m *mockTokenService) Create(_ context.Context, _ string, _ time.Duration) (string, int64, error) {
	return "", 0, nil
}
func (m *mockTokenService) Revoke(_ context.Context, _ int64) error { return nil }
func (m *mockTokenService) List(_ context.Context) ([]model.Token, error) {
	return nil, nil
}
func (m *mockTokenService) Validate(ctx context.Context, plaintext string) (*model.Token, error) {
	if m.validateFn != nil {
		return m.validateFn(ctx, plaintext)
	}
	return nil, service.ErrTokenNotFound
}

// mockAuditService implements service.AuditService for testing.
type mockAuditService struct {
	logFn func(ctx context.Context, entry model.AuditEntry) error
}

func (m *mockAuditService) Log(ctx context.Context, entry model.AuditEntry) error {
	if m.logFn != nil {
		return m.logFn(ctx, entry)
	}
	return nil
}
func (m *mockAuditService) Query(_ context.Context, _ model.AuditFilter) ([]model.AuditEntry, error) {
	return nil, nil
}

// ─── Helper ───────────────────────────────────────────────────────────────────

// okHandler returns an http.Handler that always writes 200.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// testRateLimiter provides isolated state for middleware tests without Redis.
type testRateLimiter struct {
	mu       sync.Mutex
	max      int
	requests map[string]int
}

func newTestRateLimiter(max int) *testRateLimiter {
	return &testRateLimiter{max: max, requests: make(map[string]int)}
}

func (rl *testRateLimiter) Allow(_ context.Context, ip string) (bool, int, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.requests[ip]++
	if rl.requests[ip] > rl.max {
		return false, 30, nil
	}
	return true, 0, nil
}

// ─── AuthMiddleware tests ─────────────────────────────────────────────────────

// TestAuthMiddleware_ValidToken verifies that a request carrying a valid Bearer
// token is forwarded to the next handler with a 200 response.
func TestAuthMiddleware_ValidToken(t *testing.T) {
	tok := &model.Token{ID: 1, Name: "ci-token"}
	svc := &mockTokenService{
		validateFn: func(_ context.Context, _ string) (*model.Token, error) {
			return tok, nil
		},
	}

	mw := middleware.AuthMiddleware(svc)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
	req.Header.Set("Authorization", "Bearer validtoken123")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// TestAuthMiddleware_MissingHeader verifies that a request without an
// Authorization header is rejected with 401.
func TestAuthMiddleware_MissingHeader(t *testing.T) {
	svc := &mockTokenService{}
	mw := middleware.AuthMiddleware(svc)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestAuthMiddleware_InvalidFormat verifies that an Authorization header without
// the "Bearer " prefix is rejected with 401.
func TestAuthMiddleware_InvalidFormat(t *testing.T) {
	svc := &mockTokenService{}
	mw := middleware.AuthMiddleware(svc)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
	req.Header.Set("Authorization", "Token abc123") // wrong scheme
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestAuthMiddleware_ExpiredToken verifies that a token for which the service
// returns ErrTokenExpired results in a 401 response.
func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	svc := &mockTokenService{
		validateFn: func(_ context.Context, _ string) (*model.Token, error) {
			return nil, service.ErrTokenExpired
		},
	}
	mw := middleware.AuthMiddleware(svc)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
	req.Header.Set("Authorization", "Bearer expiredtoken")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestAuthMiddleware_RevokedToken verifies that ErrTokenRevoked also yields 401.
func TestAuthMiddleware_RevokedToken(t *testing.T) {
	svc := &mockTokenService{
		validateFn: func(_ context.Context, _ string) (*model.Token, error) {
			return nil, service.ErrTokenRevoked
		},
	}
	mw := middleware.AuthMiddleware(svc)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/bar", nil)
	req.Header.Set("Authorization", "Bearer revokedtoken")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestAuthMiddleware_SkipLoginPath verifies that POST /v1/auth/login bypasses
// authentication and is forwarded directly to the next handler.
func TestAuthMiddleware_SkipLoginPath(t *testing.T) {
	svc := &mockTokenService{} // validate is never called
	mw := middleware.AuthMiddleware(svc)(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	// No Authorization header — should still pass through.
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for login path, got %d", rr.Code)
	}
}

// ─── RateLimitMiddleware tests ────────────────────────────────────────────────

// TestRateLimitMiddleware_AllowsUnderLimit verifies that requests within the
// limit window are forwarded to the next handler.
func TestRateLimitMiddleware_AllowsUnderLimit(t *testing.T) {
	max := 3
	mw := middleware.RateLimitMiddleware(newTestRateLimiter(max))(okHandler())

	for i := 0; i < max; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
		req.RemoteAddr = "192.0.2.1:1234"
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rr.Code)
		}
	}
}

// TestRateLimitMiddleware_BlocksOverLimit verifies that the (max+1)-th request
// within the window receives a 429 response with a Retry-After header.
func TestRateLimitMiddleware_BlocksOverLimit(t *testing.T) {
	max := 3
	mw := middleware.RateLimitMiddleware(newTestRateLimiter(max))(okHandler())

	// Exhaust the limit.
	for i := 0; i < max; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
		req.RemoteAddr = "192.0.2.2:5678"
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
	}

	// max+1 request must be blocked.
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	req.RemoteAddr = "192.0.2.2:5678"
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr.Code)
	}

	retryAfter := rr.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("expected Retry-After header to be set")
	}
	secs, err := strconv.Atoi(retryAfter)
	if err != nil || secs <= 0 {
		t.Errorf("Retry-After must be a positive integer, got %q", retryAfter)
	}
}

// TestRateLimitMiddleware_SkipsNonLoginPath verifies that requests to paths
// other than /v1/auth/login are never rate-limited.
func TestRateLimitMiddleware_SkipsNonLoginPath(t *testing.T) {
	max := 1
	mw := middleware.RateLimitMiddleware(newTestRateLimiter(max))(okHandler())

	// Send more requests than the limit allows — should all pass because
	// the path is not /v1/auth/login.
	for i := 0; i < max+5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
		req.RemoteAddr = "192.0.2.3:9999"
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d to non-login path: expected 200, got %d", i+1, rr.Code)
		}
	}
}

// ─── CORSMiddleware tests ─────────────────────────────────────────────────────

// TestCORSMiddleware_AllowedOrigin verifies that a request from an allowed
// origin receives the four CORS response headers.
func TestCORSMiddleware_AllowedOrigin(t *testing.T) {
	allowed := []string{"https://app.example.com"}
	mw := middleware.CORSMiddleware(allowed)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	headers := map[string]string{
		"Access-Control-Allow-Origin":  "https://app.example.com",
		"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
		"Access-Control-Allow-Headers": "Authorization, Content-Type",
	}
	for k, want := range headers {
		if got := rr.Header().Get(k); got != want {
			t.Errorf("header %s: expected %q, got %q", k, want, got)
		}
	}
}

// TestCORSMiddleware_DisallowedOrigin verifies that a request from an origin
// not in the whitelist does NOT receive any CORS headers.
func TestCORSMiddleware_DisallowedOrigin(t *testing.T) {
	allowed := []string{"https://app.example.com"}
	mw := middleware.CORSMiddleware(allowed)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected no Access-Control-Allow-Origin header for disallowed origin, got %q", got)
	}
}

// TestCORSMiddleware_PreflightOptions verifies that an OPTIONS pre-flight
// request returns 204 and does NOT invoke the downstream handler.
func TestCORSMiddleware_PreflightOptions(t *testing.T) {
	allowed := []string{"https://app.example.com"}

	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := middleware.CORSMiddleware(allowed)(next)

	req := httptest.NewRequest(http.MethodOptions, "/v1/secret/foo", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for OPTIONS preflight, got %d", rr.Code)
	}
	if handlerCalled {
		t.Error("downstream handler must NOT be called for OPTIONS preflight")
	}
}

// ─── AuditMiddleware tests ────────────────────────────────────────────────────

// TestAuditMiddleware_AuditFailReturns500 verifies that when AuditService.Log
// returns an error the middleware returns 500 and does NOT forward to the handler.
//
// Validates: Requirements 7.5
func TestAuditMiddleware_AuditFailReturns500(t *testing.T) {
	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	svc := &mockAuditService{
		logFn: func(_ context.Context, _ model.AuditEntry) error {
			return errors.New("database unavailable")
		},
	}

	mw := middleware.AuditMiddleware(svc)(next)

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when audit fails, got %d", rr.Code)
	}
	if handlerCalled {
		t.Error("downstream handler must NOT be called when audit log fails")
	}
}

// TestAuditMiddleware_AuditSuccessForwardsToHandler verifies that when
// AuditService.Log succeeds the request is forwarded to the downstream handler.
//
// Validates: Requirements 7.5
func TestAuditMiddleware_AuditSuccessForwardsToHandler(t *testing.T) {
	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	svc := &mockAuditService{
		logFn: func(_ context.Context, _ model.AuditEntry) error {
			return nil // audit succeeds
		},
	}

	mw := middleware.AuditMiddleware(svc)(next)

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 when audit succeeds, got %d", rr.Code)
	}
	if !handlerCalled {
		t.Error("downstream handler must be called when audit log succeeds")
	}
}

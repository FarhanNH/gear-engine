package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gear/engine/internal/handler"
)

type mockTurnstileVerifier struct {
	fn func(ctx context.Context, token, remoteIP string) (bool, error)
}

func (m *mockTurnstileVerifier) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	return m.fn(ctx, token, remoteIP)
}

func newLoginRequest(username, password, turnstileToken string) *http.Request {
	req := newSecretRequest(http.MethodPost, "/v1/auth/login", map[string]string{
		"username":        username,
		"password":        password,
		"turnstile_token": turnstileToken,
	})
	req.RemoteAddr = "203.0.113.10:12345"
	return req
}

func TestLogin_TurnstileValidAllowsLogin(t *testing.T) {
	db := setupAdminsDB(t)
	tokenSvc := &mockTokenService{
		create: func(_ context.Context, name string, ttl time.Duration) (string, int64, error) {
			return "session-tok-123", 1, nil
		},
	}
	var gotToken, gotIP string
	verifier := &mockTurnstileVerifier{
		fn: func(_ context.Context, token, remoteIP string) (bool, error) {
			gotToken = token
			gotIP = remoteIP
			return true, nil
		},
	}
	h := handler.NewAuthHandler(db, tokenSvc, time.Hour, verifier)

	req := newLoginRequest("admin", "correct-password", "valid-cf-token")
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotToken != "valid-cf-token" {
		t.Errorf("expected token 'valid-cf-token', got %q", gotToken)
	}
	if gotIP != "203.0.113.10" {
		t.Errorf("expected remoteIP '203.0.113.10', got %q", gotIP)
	}
	var resp map[string]string
	decodeJSON(t, rr.Body, &resp)
	if resp["token"] != "session-tok-123" {
		t.Errorf("expected session token, got %q", resp["token"])
	}
}

func TestLogin_TurnstileEmptyTokenReturns401(t *testing.T) {
	db := setupAdminsDB(t)
	// Use real HTTPSTurnstileVerifier against a server that must not even be called for empty token.
	var called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	t.Cleanup(srv.Close)

	verifier := handler.NewTurnstileVerifierWithEndpoint("secret", time.Second, srv.URL)
	h := handler.NewAuthHandler(db, &mockTokenService{}, time.Hour, verifier)

	req := newLoginRequest("admin", "correct-password", "")
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if called.Load() != 0 {
		t.Errorf("expected siteverify not to be called for empty token, called %d times", called.Load())
	}
	var resp map[string]string
	decodeJSON(t, rr.Body, &resp)
	if resp["error"] != "invalid credentials" {
		t.Errorf("expected generic 'invalid credentials', got %q", resp["error"])
	}
}

func TestLogin_TurnstileInvalidTokenReturns401BeforePasswordCheck(t *testing.T) {
	db := setupAdminsDB(t)
	// Drop admins table to prove Turnstile runs before DB/password check.
	if _, err := db.Exec(`DROP TABLE admins`); err != nil {
		t.Fatalf("drop admins: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false})
	}))
	t.Cleanup(srv.Close)

	verifier := handler.NewTurnstileVerifierWithEndpoint("secret", time.Second, srv.URL)
	h := handler.NewAuthHandler(db, &mockTokenService{}, time.Hour, verifier)

	req := newLoginRequest("admin", "correct-password", "bad-token")
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	decodeJSON(t, rr.Body, &resp)
	if resp["error"] != "invalid credentials" {
		t.Errorf("expected generic 'invalid credentials', got %q", resp["error"])
	}
}

func TestLogin_TurnstileErrorOrTimeoutReturns401(t *testing.T) {
	db := setupAdminsDB(t)

	t.Run("verifier error", func(t *testing.T) {
		verifier := &mockTurnstileVerifier{
			fn: func(_ context.Context, _, _ string) (bool, error) {
				return false, errors.New("network failure")
			},
		}
		h := handler.NewAuthHandler(db, &mockTokenService{}, time.Hour, verifier)
		req := newLoginRequest("admin", "correct-password", "tok")
		rr := httptest.NewRecorder()
		h.Login(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("siteverify timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(150 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		}))
		t.Cleanup(srv.Close)

		verifier := handler.NewTurnstileVerifierWithEndpoint("secret", 30*time.Millisecond, srv.URL)
		h := handler.NewAuthHandler(db, &mockTokenService{}, time.Hour, verifier)
		req := newLoginRequest("admin", "correct-password", "tok")
		rr := httptest.NewRecorder()
		h.Login(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on timeout, got %d", rr.Code)
		}
	})

	t.Run("siteverify invalid json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not-json"))
		}))
		t.Cleanup(srv.Close)

		verifier := handler.NewTurnstileVerifierWithEndpoint("secret", time.Second, srv.URL)
		h := handler.NewAuthHandler(db, &mockTokenService{}, time.Hour, verifier)
		req := newLoginRequest("admin", "correct-password", "tok")
		rr := httptest.NewRecorder()
		h.Login(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on invalid JSON, got %d", rr.Code)
		}
	})
}

func TestLogin_TurnstileDisabledSkipsVerification(t *testing.T) {
	db := setupAdminsDB(t)
	tokenSvc := &mockTokenService{
		create: func(_ context.Context, name string, ttl time.Duration) (string, int64, error) {
			return "session-tok-disabled", 1, nil
		},
	}
	h := handler.NewAuthHandler(db, tokenSvc, time.Hour, nil)

	req := newLoginRequest("admin", "correct-password", "")
	rr := httptest.NewRecorder()
	h.Login(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 when Turnstile disabled, got %d: %s", rr.Code, rr.Body.String())
	}
}

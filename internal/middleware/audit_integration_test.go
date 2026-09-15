// Package middleware_test contains integration tests for AuditMiddleware
// specifically validating the fail-safe behaviour (Requirement 7.5):
// when AuditService.Log() fails, the middleware must return HTTP 500 and
// must NOT process the request or persist any data.
package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gear/engine/internal/crypto"
	"github.com/gear/engine/internal/database"
	"github.com/gear/engine/internal/handler"
	"github.com/gear/engine/internal/middleware"
	"github.com/gear/engine/internal/model"
	"github.com/gear/engine/internal/service"
)

// alwaysFailAuditService is an AuditService that always returns an error from Log.
type alwaysFailAuditService struct{}

func (a *alwaysFailAuditService) Log(_ context.Context, _ model.AuditEntry) error {
	return errors.New("audit log unavailable")
}

func (a *alwaysFailAuditService) Query(_ context.Context, _ model.AuditFilter) ([]model.AuditEntry, error) {
	return nil, nil
}

// TestAuditMiddleware_FailSafe_Returns500WhenLogFails verifies that when
// AuditService.Log() always errors, the middleware returns HTTP 500.
//
// Validates: Requirements 7.5
func TestAuditMiddleware_FailSafe_Returns500WhenLogFails(t *testing.T) {
	auditSvc := &alwaysFailAuditService{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := middleware.AuditMiddleware(auditSvc)(next)

	req := httptest.NewRequest(http.MethodPut, "/v1/secret/test/key", strings.NewReader(`{"value":"secret-value"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected HTTP 500 when audit log fails, got %d", rr.Code)
	}
}

// TestAuditMiddleware_FailSafe_HandlerNotCalled verifies that when
// AuditService.Log() returns an error, the downstream handler is NOT called.
//
// Validates: Requirements 7.5
func TestAuditMiddleware_FailSafe_HandlerNotCalled(t *testing.T) {
	auditSvc := &alwaysFailAuditService{}

	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	mw := middleware.AuditMiddleware(auditSvc)(next)

	req := httptest.NewRequest(http.MethodPut, "/v1/secret/test/key", strings.NewReader(`{"value":"secret-value"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if callCount != 0 {
		t.Errorf("downstream handler must NOT be called when audit log fails, got %d call(s)", callCount)
	}
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected HTTP 500, got %d", rr.Code)
	}
}

// TestAuditMiddleware_FailSafe_NoDatabaseChanges verifies the end-to-end
// fail-safe: with a real in-memory SQLite DB and a real SecretService, a PUT
// request through AuditMiddleware (with a failing audit service) must NOT
// persist any secret in the database.
//
// Validates: Requirements 7.5
func TestAuditMiddleware_FailSafe_NoDatabaseChanges(t *testing.T) {
	// Open real in-memory SQLite with migrations applied.
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory database: %v", err)
	}
	defer database.Close(db)

	// Generate a real 32-byte master key.
	masterKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	// Real SecretService backed by the in-memory DB.
	secretSvc := service.NewSecretService(db, masterKey)

	// Real SecretHandler using the SecretService.
	secretHandler := handler.NewSecretHandler(secretSvc)

	// AuditMiddleware wrapping the real handler, with a failing audit service.
	auditSvc := &alwaysFailAuditService{}
	handlerChain := middleware.AuditMiddleware(auditSvc)(http.HandlerFunc(secretHandler.PutSecret))

	// Send PUT /v1/secret/test/key with a JSON body.
	body := strings.NewReader(`{"value":"should-not-be-stored"}`)
	req := httptest.NewRequest(http.MethodPut, "/v1/secret/test/key", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handlerChain.ServeHTTP(rr, req)

	// The middleware must have rejected with HTTP 500.
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected HTTP 500, got %d", rr.Code)
	}

	// Verify that no secret was written to the database.
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM secrets").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query secrets table: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 secrets in DB after audit fail-safe, got %d", count)
	}
}

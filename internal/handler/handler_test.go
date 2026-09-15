package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gear/engine/internal/handler"
	"github.com/gear/engine/internal/model"
	"github.com/gear/engine/internal/service"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

// mockSecretService implements service.SecretService via function fields.
type mockSecretService struct {
	put    func(ctx context.Context, path, value string) error
	get    func(ctx context.Context, path string) (string, error)
	delete func(ctx context.Context, path string) error
	list   func(ctx context.Context, prefix string) ([]string, error)
}

func (m *mockSecretService) Put(ctx context.Context, path, value string) error {
	return m.put(ctx, path, value)
}
func (m *mockSecretService) Get(ctx context.Context, path string) (string, error) {
	return m.get(ctx, path)
}
func (m *mockSecretService) Delete(ctx context.Context, path string) error {
	return m.delete(ctx, path)
}
func (m *mockSecretService) List(ctx context.Context, prefix string) ([]string, error) {
	return m.list(ctx, prefix)
}

// mockTokenService implements service.TokenService via function fields.
type mockTokenService struct {
	create   func(ctx context.Context, name string, ttl time.Duration) (string, int64, error)
	revoke   func(ctx context.Context, id int64) error
	validate func(ctx context.Context, plaintext string) (*model.Token, error)
	list     func(ctx context.Context) ([]model.Token, error)
}

func (m *mockTokenService) Create(ctx context.Context, name string, ttl time.Duration) (string, int64, error) {
	return m.create(ctx, name, ttl)
}
func (m *mockTokenService) Revoke(ctx context.Context, id int64) error {
	return m.revoke(ctx, id)
}
func (m *mockTokenService) Validate(ctx context.Context, plaintext string) (*model.Token, error) {
	return m.validate(ctx, plaintext)
}
func (m *mockTokenService) List(ctx context.Context) ([]model.Token, error) {
	return m.list(ctx)
}

// mockAuditService implements service.AuditService via function fields.
type mockAuditService struct {
	log   func(ctx context.Context, entry model.AuditEntry) error
	query func(ctx context.Context, filter model.AuditFilter) ([]model.AuditEntry, error)
}

func (m *mockAuditService) Log(ctx context.Context, entry model.AuditEntry) error {
	return m.log(ctx, entry)
}
func (m *mockAuditService) Query(ctx context.Context, filter model.AuditFilter) ([]model.AuditEntry, error) {
	return m.query(ctx, filter)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func decodeJSON(t *testing.T, body *bytes.Buffer, v any) {
	t.Helper()
	if err := json.NewDecoder(body).Decode(v); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}
}

func newSecretRequest(method, url string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	return httptest.NewRequest(method, url, &buf)
}

// ---------------------------------------------------------------------------
// SecretHandler tests
// ---------------------------------------------------------------------------

// TestSecretHandler_PutSecret_Success — PUT valid path + body → 204
func TestSecretHandler_PutSecret_Success(t *testing.T) {
	svc := &mockSecretService{
		put: func(_ context.Context, path, value string) error { return nil },
	}
	h := handler.NewSecretHandler(svc)

	req := newSecretRequest(http.MethodPut, "/v1/secret/app/db-password", map[string]string{"value": "s3cr3t"})
	rr := httptest.NewRecorder()
	h.PutSecret(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
}

// TestSecretHandler_PutSecret_InvalidPath — PUT with ".." in path → 400
func TestSecretHandler_PutSecret_InvalidPath(t *testing.T) {
	svc := &mockSecretService{}
	h := handler.NewSecretHandler(svc)

	req := newSecretRequest(http.MethodPut, "/v1/secret/app/../etc/passwd", map[string]string{"value": "x"})
	rr := httptest.NewRecorder()
	h.PutSecret(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	decodeJSON(t, rr.Body, &resp)
	if _, ok := resp["error"]; !ok {
		t.Error("expected JSON error field in response")
	}
}

// TestSecretHandler_PutSecret_MissingValue — PUT empty value → 400
func TestSecretHandler_PutSecret_MissingValue(t *testing.T) {
	svc := &mockSecretService{}
	h := handler.NewSecretHandler(svc)

	req := newSecretRequest(http.MethodPut, "/v1/secret/app/key", map[string]string{"value": ""})
	rr := httptest.NewRecorder()
	h.PutSecret(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestSecretHandler_GetSecret_Success — GET existing → 200 + JSON with path/value
func TestSecretHandler_GetSecret_Success(t *testing.T) {
	svc := &mockSecretService{
		get: func(_ context.Context, path string) (string, error) { return "my-value", nil },
	}
	h := handler.NewSecretHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/app/key", nil)
	rr := httptest.NewRecorder()
	h.GetSecret(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]string
	decodeJSON(t, rr.Body, &resp)
	if resp["value"] != "my-value" {
		t.Errorf("expected value 'my-value', got %q", resp["value"])
	}
	if resp["path"] != "app/key" {
		t.Errorf("expected path 'app/key', got %q", resp["path"])
	}
}

// TestSecretHandler_GetSecret_NotFound — GET missing → 404
func TestSecretHandler_GetSecret_NotFound(t *testing.T) {
	svc := &mockSecretService{
		get: func(_ context.Context, path string) (string, error) { return "", service.ErrSecretNotFound },
	}
	h := handler.NewSecretHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/missing/key", nil)
	rr := httptest.NewRecorder()
	h.GetSecret(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// TestSecretHandler_DeleteSecret_Success — DELETE existing → 204
func TestSecretHandler_DeleteSecret_Success(t *testing.T) {
	svc := &mockSecretService{
		delete: func(_ context.Context, path string) error { return nil },
	}
	h := handler.NewSecretHandler(svc)

	req := httptest.NewRequest(http.MethodDelete, "/v1/secret/app/key", nil)
	rr := httptest.NewRecorder()
	h.DeleteSecret(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
}

// TestSecretHandler_DeleteSecret_NotFound — DELETE missing → 404
func TestSecretHandler_DeleteSecret_NotFound(t *testing.T) {
	svc := &mockSecretService{
		delete: func(_ context.Context, path string) error { return service.ErrSecretNotFound },
	}
	h := handler.NewSecretHandler(svc)

	req := httptest.NewRequest(http.MethodDelete, "/v1/secret/missing/key", nil)
	rr := httptest.NewRecorder()
	h.DeleteSecret(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// TestSecretHandler_ListSecrets_Success — LIST with results → 200 + {"paths":[...]}
func TestSecretHandler_ListSecrets_Success(t *testing.T) {
	svc := &mockSecretService{
		list: func(_ context.Context, prefix string) ([]string, error) {
			return []string{"app/db", "app/redis"}, nil
		},
	}
	h := handler.NewSecretHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/list/app/", nil)
	rr := httptest.NewRecorder()
	h.ListSecrets(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string][]string
	decodeJSON(t, rr.Body, &resp)
	if len(resp["paths"]) != 2 {
		t.Errorf("expected 2 paths, got %d", len(resp["paths"]))
	}
}

// TestSecretHandler_ListSecrets_Empty — LIST no results → 404
func TestSecretHandler_ListSecrets_Empty(t *testing.T) {
	svc := &mockSecretService{
		list: func(_ context.Context, prefix string) ([]string, error) {
			return []string{}, nil
		},
	}
	h := handler.NewSecretHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/list/empty/", nil)
	rr := httptest.NewRecorder()
	h.ListSecrets(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// TokenHandler tests
// ---------------------------------------------------------------------------

// TestTokenHandler_CreateToken_Success — POST valid → 201 + token in body
func TestTokenHandler_CreateToken_Success(t *testing.T) {
	svc := &mockTokenService{
		create: func(_ context.Context, name string, ttl time.Duration) (string, int64, error) {
			return "plaintexttoken123", 42, nil
		},
	}
	h := handler.NewTokenHandler(svc)

	req := newSecretRequest(http.MethodPost, "/v1/token", map[string]string{
		"name": "ci-token",
		"ttl":  "720h",
	})
	rr := httptest.NewRecorder()
	h.CreateToken(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}
	var resp map[string]any
	decodeJSON(t, rr.Body, &resp)
	if resp["token"] != "plaintexttoken123" {
		t.Errorf("expected token in body, got %v", resp["token"])
	}
	if int64(resp["id"].(float64)) != 42 {
		t.Errorf("expected id 42, got %v", resp["id"])
	}
}

// TestTokenHandler_CreateToken_InvalidTTL — POST with bad TTL → 400
func TestTokenHandler_CreateToken_InvalidTTL(t *testing.T) {
	svc := &mockTokenService{}
	h := handler.NewTokenHandler(svc)

	req := newSecretRequest(http.MethodPost, "/v1/token", map[string]string{
		"name": "ci-token",
		"ttl":  "not-a-duration",
	})
	rr := httptest.NewRecorder()
	h.CreateToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	decodeJSON(t, rr.Body, &resp)
	if _, ok := resp["error"]; !ok {
		t.Error("expected JSON error field")
	}
}

// TestTokenHandler_ListTokens_Success — GET → 200 + {"tokens":[...]}
func TestTokenHandler_ListTokens_Success(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	svc := &mockTokenService{
		list: func(_ context.Context) ([]model.Token, error) {
			return []model.Token{
				{ID: 1, Name: "ci-token", ExpiresAt: &exp, Revoked: false, CreatedAt: time.Now()},
			}, nil
		},
	}
	h := handler.NewTokenHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/token", nil)
	rr := httptest.NewRecorder()
	h.ListTokens(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]any
	decodeJSON(t, rr.Body, &resp)
	tokens, ok := resp["tokens"].([]any)
	if !ok || len(tokens) != 1 {
		t.Errorf("expected 1 token in response, got %v", resp["tokens"])
	}
}

// TestTokenHandler_RevokeToken_Success — DELETE /{id} → 204
func TestTokenHandler_RevokeToken_Success(t *testing.T) {
	svc := &mockTokenService{
		revoke: func(_ context.Context, id int64) error { return nil },
	}
	h := handler.NewTokenHandler(svc)

	req := httptest.NewRequest(http.MethodDelete, "/v1/token/7", nil)
	rr := httptest.NewRecorder()
	h.RevokeToken(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
}

// TestTokenHandler_RevokeToken_NotFound — DELETE non-existent → 404
func TestTokenHandler_RevokeToken_NotFound(t *testing.T) {
	svc := &mockTokenService{
		revoke: func(_ context.Context, id int64) error { return service.ErrTokenNotFound },
	}
	h := handler.NewTokenHandler(svc)

	req := httptest.NewRequest(http.MethodDelete, "/v1/token/999", nil)
	rr := httptest.NewRecorder()
	h.RevokeToken(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// AuditHandler tests
// ---------------------------------------------------------------------------

// TestAuditHandler_GetAuditLog_Success — GET basic → 200 + entries JSON
func TestAuditHandler_GetAuditLog_Success(t *testing.T) {
	tokenName := "ci-token"
	path := "app/key"
	svc := &mockAuditService{
		query: func(_ context.Context, filter model.AuditFilter) ([]model.AuditEntry, error) {
			return []model.AuditEntry{
				{
					ID:        1,
					TokenName: &tokenName,
					Path:      &path,
					Action:    "read",
					Result:    "success",
					IPAddress: "127.0.0.1",
					Timestamp: time.Now(),
				},
			}, nil
		},
	}
	h := handler.NewAuditHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	rr := httptest.NewRecorder()
	h.GetAuditLog(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]any
	decodeJSON(t, rr.Body, &resp)
	entries, ok := resp["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Errorf("expected 1 audit entry, got %v", resp["entries"])
	}
	if int(resp["total"].(float64)) != 1 {
		t.Errorf("expected total=1, got %v", resp["total"])
	}
}

// TestAuditHandler_GetAuditLog_InvalidSince — GET with bad since → 400
func TestAuditHandler_GetAuditLog_InvalidSince(t *testing.T) {
	svc := &mockAuditService{}
	h := handler.NewAuditHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/v1/audit?since=not-a-date", nil)
	rr := httptest.NewRecorder()
	h.GetAuditLog(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	decodeJSON(t, rr.Body, &resp)
	if _, ok := resp["error"]; !ok {
		t.Error("expected JSON error field")
	}
}

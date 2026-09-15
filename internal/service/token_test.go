package service_test

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/gear/engine/internal/service"
)

// TestTokenService_CreateReturnsPlaintext memverifikasi bahwa Create mengembalikan
// plaintext token 64-char hex dan ID yang valid (> 0).
func TestTokenService_CreateReturnsPlaintext(t *testing.T) {
	svc := service.NewTokenService(mustOpenDB(t))
	ctx := context.Background()

	plaintext, id, err := svc.Create(ctx, "test-token", time.Hour)
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}

	// ID harus positif
	if id <= 0 {
		t.Errorf("Create: expected id > 0, got %d", id)
	}

	// Plaintext harus 64 karakter (32 bytes hex-encoded)
	if len(plaintext) != 64 {
		t.Errorf("Create: expected plaintext length 64, got %d", len(plaintext))
	}

	// Plaintext harus valid hex
	if _, err := hex.DecodeString(plaintext); err != nil {
		t.Errorf("Create: plaintext is not valid hex: %v", err)
	}
}

// TestTokenService_ValidateValidToken memverifikasi bahwa token yang baru dibuat
// dapat langsung di-Validate dan mengembalikan *model.Token yang valid.
func TestTokenService_ValidateValidToken(t *testing.T) {
	svc := service.NewTokenService(mustOpenDB(t))
	ctx := context.Background()

	plaintext, id, err := svc.Create(ctx, "valid-token", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	tok, err := svc.Validate(ctx, plaintext)
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
	if tok == nil {
		t.Fatal("Validate: returned nil token")
	}
	if tok.ID != id {
		t.Errorf("Validate: expected ID %d, got %d", id, tok.ID)
	}
	if tok.Name != "valid-token" {
		t.Errorf("Validate: expected Name %q, got %q", "valid-token", tok.Name)
	}
	if tok.Revoked {
		t.Error("Validate: expected Revoked=false")
	}
}

// TestTokenService_ValidateExpiredToken memverifikasi bahwa token yang sudah
// kedaluwarsa mengembalikan ErrTokenExpired.
func TestTokenService_ValidateExpiredToken(t *testing.T) {
	db := mustOpenDB(t)
	svc := service.NewTokenService(db)
	ctx := context.Background()

	// Buat token dengan TTL normal, lalu langsung update expires_at ke masa lalu.
	plaintext, id, err := svc.Create(ctx, "expiring-token", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Update expires_at ke 1 detik yang lalu
	past := time.Now().Add(-time.Second).Unix()
	_, err = db.ExecContext(ctx, `UPDATE tokens SET expires_at = ? WHERE id = ?`, past, id)
	if err != nil {
		t.Fatalf("UPDATE expires_at: %v", err)
	}

	_, err = svc.Validate(ctx, plaintext)
	if err == nil {
		t.Fatal("Validate: expected ErrTokenExpired, got nil")
	}
	if err != service.ErrTokenExpired {
		t.Errorf("Validate: expected ErrTokenExpired, got %v", err)
	}
}

// TestTokenService_ValidateRevokedToken memverifikasi bahwa token yang di-revoke
// mengembalikan ErrTokenRevoked.
func TestTokenService_ValidateRevokedToken(t *testing.T) {
	svc := service.NewTokenService(mustOpenDB(t))
	ctx := context.Background()

	plaintext, id, err := svc.Create(ctx, "revoke-me", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.Revoke(ctx, id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err = svc.Validate(ctx, plaintext)
	if err == nil {
		t.Fatal("Validate: expected ErrTokenRevoked, got nil")
	}
	if err != service.ErrTokenRevoked {
		t.Errorf("Validate: expected ErrTokenRevoked, got %v", err)
	}
}

// TestTokenService_ValidateNotFound memverifikasi bahwa Validate token acak
// yang tidak ada di DB mengembalikan ErrTokenNotFound.
func TestTokenService_ValidateNotFound(t *testing.T) {
	svc := service.NewTokenService(mustOpenDB(t))
	ctx := context.Background()

	// Token acak yang pasti tidak ada di DB
	fakeToken := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	_, err := svc.Validate(ctx, fakeToken)
	if err == nil {
		t.Fatal("Validate: expected ErrTokenNotFound, got nil")
	}
	if err != service.ErrTokenNotFound {
		t.Errorf("Validate: expected ErrTokenNotFound, got %v", err)
	}
}

// TestTokenService_RevokeNotFound memverifikasi bahwa Revoke ID yang tidak ada
// mengembalikan ErrTokenNotFound.
func TestTokenService_RevokeNotFound(t *testing.T) {
	svc := service.NewTokenService(mustOpenDB(t))
	ctx := context.Background()

	err := svc.Revoke(ctx, 99999)
	if err == nil {
		t.Fatal("Revoke: expected ErrTokenNotFound, got nil")
	}
	if err != service.ErrTokenNotFound {
		t.Errorf("Revoke: expected ErrTokenNotFound, got %v", err)
	}
}

// TestTokenService_List memverifikasi bahwa List mengembalikan semua token yang dibuat.
func TestTokenService_List(t *testing.T) {
	svc := service.NewTokenService(mustOpenDB(t))
	ctx := context.Background()

	_, _, err := svc.Create(ctx, "token-alpha", time.Hour)
	if err != nil {
		t.Fatalf("Create token-alpha: %v", err)
	}
	_, _, err = svc.Create(ctx, "token-beta", time.Hour)
	if err != nil {
		t.Fatalf("Create token-beta: %v", err)
	}

	tokens, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("List: expected 2 tokens, got %d", len(tokens))
	}

	// Verifikasi nama token ada dalam hasil (urutan DESC by created_at)
	names := map[string]bool{}
	for _, tok := range tokens {
		names[tok.Name] = true
	}
	for _, want := range []string{"token-alpha", "token-beta"} {
		if !names[want] {
			t.Errorf("List: token %q not found in results", want)
		}
	}
}

// TestTokenService_RevokeToValidate memverifikasi alur lengkap:
// Create → Revoke → Validate mengembalikan ErrTokenRevoked.
func TestTokenService_RevokeToValidate(t *testing.T) {
	svc := service.NewTokenService(mustOpenDB(t))
	ctx := context.Background()

	plaintext, id, err := svc.Create(ctx, "full-flow", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Pastikan valid sebelum revoke
	tok, err := svc.Validate(ctx, plaintext)
	if err != nil {
		t.Fatalf("Validate before revoke: %v", err)
	}
	if tok.ID != id {
		t.Errorf("Validate before revoke: wrong ID %d", tok.ID)
	}

	// Revoke
	if err := svc.Revoke(ctx, id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Validate setelah revoke harus ErrTokenRevoked
	_, err = svc.Validate(ctx, plaintext)
	if err == nil {
		t.Fatal("Validate after revoke: expected ErrTokenRevoked, got nil")
	}
	if err != service.ErrTokenRevoked {
		t.Errorf("Validate after revoke: expected ErrTokenRevoked, got %v", err)
	}
}

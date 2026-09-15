package service_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/gear/engine/internal/crypto"
	"github.com/gear/engine/internal/database"
	"github.com/gear/engine/internal/service"
)

// mustOpenDB opens an in-memory SQLite database with migrations applied.
// It registers a cleanup function to close the DB at the end of the test.
func mustOpenDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("mustOpenDB: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(db); err != nil {
			t.Errorf("mustOpenDB cleanup: %v", err)
		}
	})
	return db
}

// mustNewService creates a SecretService backed by an in-memory DB and a
// freshly generated master key.
func mustNewService(t *testing.T) service.SecretService {
	t.Helper()
	db := mustOpenDB(t)
	masterKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("mustNewService: generate master key: %v", err)
	}
	return service.NewSecretService(db, masterKey)
}

// TestSecretService_PutGetRoundTrip verifies that a value stored with Put
// can be retrieved unchanged with Get.
// Validates: Requirements 2.1–2.7, 6.1, 6.2
func TestSecretService_PutGetRoundTrip(t *testing.T) {
	svc := mustNewService(t)
	ctx := context.Background()

	const path = "app/db/password"
	const value = "super-secret-value-123"

	if err := svc.Put(ctx, path, value); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := svc.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got != value {
		t.Errorf("Get = %q, want %q", got, value)
	}
}

// TestSecretService_PutUpdatesExistingSecret verifies that a second Put to the
// same path overwrites the previous value.
// Validates: Requirements 2.5, 6.1, 6.2
func TestSecretService_PutUpdatesExistingSecret(t *testing.T) {
	svc := mustNewService(t)
	ctx := context.Background()

	const path = "app/token"
	const first = "first-value"
	const second = "second-value"

	if err := svc.Put(ctx, path, first); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	if err := svc.Put(ctx, path, second); err != nil {
		t.Fatalf("Put second: %v", err)
	}

	got, err := svc.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}

	if got != second {
		t.Errorf("Get = %q, want %q (second value)", got, second)
	}
}

// TestSecretService_GetNotFound verifies that Get returns ErrSecretNotFound
// when the path does not exist.
// Validates: Requirements 6.2
func TestSecretService_GetNotFound(t *testing.T) {
	svc := mustNewService(t)
	ctx := context.Background()

	_, err := svc.Get(ctx, "nonexistent/path")
	if !errors.Is(err, service.ErrSecretNotFound) {
		t.Errorf("Get non-existent: got %v, want ErrSecretNotFound", err)
	}
}

// TestSecretService_Delete verifies that a secret can be deleted and that
// subsequent Get returns ErrSecretNotFound.
// Validates: Requirements 6.3
func TestSecretService_Delete(t *testing.T) {
	svc := mustNewService(t)
	ctx := context.Background()

	const path = "app/api-key"
	if err := svc.Put(ctx, path, "key-value"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := svc.Delete(ctx, path); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := svc.Get(ctx, path)
	if !errors.Is(err, service.ErrSecretNotFound) {
		t.Errorf("Get after Delete: got %v, want ErrSecretNotFound", err)
	}
}

// TestSecretService_DeleteNotFound verifies that Delete returns ErrSecretNotFound
// when the path does not exist.
// Validates: Requirements 6.3, 6.5
func TestSecretService_DeleteNotFound(t *testing.T) {
	svc := mustNewService(t)
	ctx := context.Background()

	err := svc.Delete(ctx, "nonexistent/path")
	if !errors.Is(err, service.ErrSecretNotFound) {
		t.Errorf("Delete non-existent: got %v, want ErrSecretNotFound", err)
	}
}

// TestSecretService_ListWithPrefix verifies that List returns only paths whose
// path column starts with the given prefix.
// Validates: Requirements 6.4
func TestSecretService_ListWithPrefix(t *testing.T) {
	svc := mustNewService(t)
	ctx := context.Background()

	seeds := []string{
		"app/db/password",
		"app/db/username",
		"app/api-key",
		"infra/dns/key",
		"infra/tls/cert",
	}
	for _, p := range seeds {
		if err := svc.Put(ctx, p, "val"); err != nil {
			t.Fatalf("Put %q: %v", p, err)
		}
	}

	// List with prefix "app/db/"
	got, err := svc.List(ctx, "app/db/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	want := []string{"app/db/password", "app/db/username"}
	if len(got) != len(want) {
		t.Fatalf("List(\"app/db/\") returned %d paths, want %d: %v", len(got), len(want), got)
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("List[%d] = %q, want %q", i, got[i], p)
		}
	}

	// List with prefix "infra/" should return both infra paths.
	infraPaths, err := svc.List(ctx, "infra/")
	if err != nil {
		t.Fatalf("List infra/: %v", err)
	}
	if len(infraPaths) != 2 {
		t.Errorf("List(\"infra/\") returned %d paths, want 2: %v", len(infraPaths), infraPaths)
	}
}

// TestSecretService_ListEmpty verifies that List returns a non-nil empty slice
// (not an error) when no paths match the prefix.
// Validates: Requirements 6.4
func TestSecretService_ListEmpty(t *testing.T) {
	svc := mustNewService(t)
	ctx := context.Background()

	paths, err := svc.List(ctx, "nonexistent/prefix/")
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if paths == nil {
		t.Error("List empty: returned nil slice, want non-nil empty slice")
	}
	if len(paths) != 0 {
		t.Errorf("List empty: returned %d paths, want 0: %v", len(paths), paths)
	}
}

// TestSecretService_EncryptionPreventsDirect verifies that the plaintext value
// is NOT present verbatim in the raw SQLite row — i.e. the value is actually
// encrypted at rest.
// Validates: Requirements 2.1, 2.2, 2.4, 2.7
func TestSecretService_EncryptionPreventsDirect(t *testing.T) {
	db := mustOpenDB(t)
	masterKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	svc := service.NewSecretService(db, masterKey)
	ctx := context.Background()

	const path = "app/plaintext-check"
	const value = "my-super-secret-plaintext-value"

	if err := svc.Put(ctx, path, value); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Read the raw bytes directly from the database row.
	var encryptedValue, valueNonce, encryptedDEK, dekNonce []byte
	row := db.QueryRowContext(ctx,
		`SELECT encrypted_value, value_nonce, encrypted_dek, dek_nonce FROM secrets WHERE path = ?`,
		path,
	)
	if err := row.Scan(&encryptedValue, &valueNonce, &encryptedDEK, &dekNonce); err != nil {
		t.Fatalf("raw SELECT: %v", err)
	}

	plainBytes := []byte(value)

	if bytes.Contains(encryptedValue, plainBytes) {
		t.Error("encrypted_value column contains the plaintext value — encryption is not working")
	}
	if bytes.Contains(valueNonce, plainBytes) {
		t.Error("value_nonce column contains the plaintext value")
	}
	if bytes.Contains(encryptedDEK, plainBytes) {
		t.Error("encrypted_dek column contains the plaintext value")
	}
	if bytes.Contains(dekNonce, plainBytes) {
		t.Error("dek_nonce column contains the plaintext value")
	}
}

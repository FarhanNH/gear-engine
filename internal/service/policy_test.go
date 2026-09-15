package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gear/engine/internal/service"
)

// mustCreateToken adalah helper untuk membuat token dan mendapatkan ID-nya.
// Digunakan sebagai prasyarat test PolicyService yang membutuhkan token_id valid.
func mustCreateToken(t *testing.T, tokenSvc service.TokenService, name string) int64 {
	t.Helper()
	_, id, err := tokenSvc.Create(context.Background(), name, time.Hour)
	if err != nil {
		t.Fatalf("mustCreateToken %q: %v", name, err)
	}
	return id
}

// TestPolicyService_CreateAndEvaluate_ExactMatch memverifikasi bahwa policy dengan
// path persis (exact match) mengizinkan aksi yang sesuai.
// Validates: Requirements 5.1, 5.2, 5.3
func TestPolicyService_CreateAndEvaluate_ExactMatch(t *testing.T) {
	db := mustOpenDB(t)
	tokenSvc := service.NewTokenService(db)
	policySvc := service.NewPolicyService(db)
	ctx := context.Background()

	tokenID := mustCreateToken(t, tokenSvc, "exact-match-token")

	if err := policySvc.Create(ctx, tokenID, "app/db/password", []string{"read"}); err != nil {
		t.Fatalf("Create policy: %v", err)
	}

	allowed, err := policySvc.Evaluate(ctx, tokenID, "app/db/password", "read")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !allowed {
		t.Error("Evaluate: expected true for exact match with read permission, got false")
	}
}

// TestPolicyService_Evaluate_WildcardMatch memverifikasi bahwa pattern "app/*"
// cocok dengan "app/db" dan "app/db/password".
// Validates: Requirements 5.5
func TestPolicyService_Evaluate_WildcardMatch(t *testing.T) {
	db := mustOpenDB(t)
	tokenSvc := service.NewTokenService(db)
	policySvc := service.NewPolicyService(db)
	ctx := context.Background()

	tokenID := mustCreateToken(t, tokenSvc, "wildcard-token")

	if err := policySvc.Create(ctx, tokenID, "app/*", []string{"read"}); err != nil {
		t.Fatalf("Create policy: %v", err)
	}

	cases := []string{"app/db", "app/db/password"}
	for _, path := range cases {
		allowed, err := policySvc.Evaluate(ctx, tokenID, path, "read")
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", path, err)
		}
		if !allowed {
			t.Errorf("Evaluate(%q): expected true for wildcard match, got false", path)
		}
	}
}

// TestPolicyService_Evaluate_NoMatch memverifikasi bahwa policy "app/*" tidak
// cocok dengan path dari namespace lain seperti "other/path".
// Validates: Requirements 5.2, 5.3
func TestPolicyService_Evaluate_NoMatch(t *testing.T) {
	db := mustOpenDB(t)
	tokenSvc := service.NewTokenService(db)
	policySvc := service.NewPolicyService(db)
	ctx := context.Background()

	tokenID := mustCreateToken(t, tokenSvc, "no-match-token")

	if err := policySvc.Create(ctx, tokenID, "app/*", []string{"read"}); err != nil {
		t.Fatalf("Create policy: %v", err)
	}

	allowed, err := policySvc.Evaluate(ctx, tokenID, "other/path", "read")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed {
		t.Error("Evaluate: expected false for non-matching path, got true")
	}
}

// TestPolicyService_Evaluate_WrongPermission memverifikasi bahwa policy read-only
// mengembalikan false saat Evaluate untuk aksi "write".
// Validates: Requirements 5.3, 5.4
func TestPolicyService_Evaluate_WrongPermission(t *testing.T) {
	db := mustOpenDB(t)
	tokenSvc := service.NewTokenService(db)
	policySvc := service.NewPolicyService(db)
	ctx := context.Background()

	tokenID := mustCreateToken(t, tokenSvc, "readonly-token")

	if err := policySvc.Create(ctx, tokenID, "app/secret", []string{"read"}); err != nil {
		t.Fatalf("Create policy: %v", err)
	}

	allowed, err := policySvc.Evaluate(ctx, tokenID, "app/secret", "write")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed {
		t.Error("Evaluate: expected false for write on read-only policy, got true")
	}
}

// TestPolicyService_Evaluate_MultiplePermissions memverifikasi bahwa policy dengan
// read+write mengizinkan read=true dan write=true, namun delete=false.
// Validates: Requirements 5.3, 5.4
func TestPolicyService_Evaluate_MultiplePermissions(t *testing.T) {
	db := mustOpenDB(t)
	tokenSvc := service.NewTokenService(db)
	policySvc := service.NewPolicyService(db)
	ctx := context.Background()

	tokenID := mustCreateToken(t, tokenSvc, "readwrite-token")

	if err := policySvc.Create(ctx, tokenID, "data/*", []string{"read", "write"}); err != nil {
		t.Fatalf("Create policy: %v", err)
	}

	tests := []struct {
		action  string
		want    bool
	}{
		{"read", true},
		{"write", true},
		{"delete", false},
	}

	for _, tc := range tests {
		got, err := policySvc.Evaluate(ctx, tokenID, "data/item", tc.action)
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", tc.action, err)
		}
		if got != tc.want {
			t.Errorf("Evaluate(%q): expected %v, got %v", tc.action, tc.want, got)
		}
	}
}

// TestPolicyService_Delete memverifikasi bahwa setelah policy dihapus,
// Evaluate mengembalikan false.
// Validates: Requirements 5.1, 5.2
func TestPolicyService_Delete(t *testing.T) {
	db := mustOpenDB(t)
	tokenSvc := service.NewTokenService(db)
	policySvc := service.NewPolicyService(db)
	ctx := context.Background()

	tokenID := mustCreateToken(t, tokenSvc, "delete-policy-token")

	if err := policySvc.Create(ctx, tokenID, "vault/key", []string{"read"}); err != nil {
		t.Fatalf("Create policy: %v", err)
	}

	// Dapatkan ID policy yang baru dibuat
	policies, err := policySvc.ListByToken(ctx, tokenID)
	if err != nil {
		t.Fatalf("ListByToken: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	policyID := policies[0].ID

	// Verifikasi Evaluate true sebelum dihapus
	allowed, err := policySvc.Evaluate(ctx, tokenID, "vault/key", "read")
	if err != nil {
		t.Fatalf("Evaluate before delete: %v", err)
	}
	if !allowed {
		t.Fatal("Evaluate before delete: expected true, got false")
	}

	// Hapus policy
	if err := policySvc.Delete(ctx, policyID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Evaluate setelah hapus harus false
	allowed, err = policySvc.Evaluate(ctx, tokenID, "vault/key", "read")
	if err != nil {
		t.Fatalf("Evaluate after delete: %v", err)
	}
	if allowed {
		t.Error("Evaluate after delete: expected false, got true")
	}
}

// TestPolicyService_DeleteNotFound memverifikasi bahwa Delete ID yang tidak ada
// mengembalikan ErrPolicyNotFound.
// Validates: Requirements 5.1
func TestPolicyService_DeleteNotFound(t *testing.T) {
	db := mustOpenDB(t)
	policySvc := service.NewPolicyService(db)
	ctx := context.Background()

	err := policySvc.Delete(ctx, 99999)
	if err == nil {
		t.Fatal("Delete: expected ErrPolicyNotFound, got nil")
	}
	if !errors.Is(err, service.ErrPolicyNotFound) {
		t.Errorf("Delete: expected ErrPolicyNotFound, got %v", err)
	}
}

// TestPolicyService_Evaluate_EmptyPolicies memverifikasi bahwa token tanpa policy
// selalu menghasilkan Evaluate = false untuk path dan aksi apapun.
// Validates: Requirements 5.2, 5.3
func TestPolicyService_Evaluate_EmptyPolicies(t *testing.T) {
	db := mustOpenDB(t)
	tokenSvc := service.NewTokenService(db)
	policySvc := service.NewPolicyService(db)
	ctx := context.Background()

	tokenID := mustCreateToken(t, tokenSvc, "no-policy-token")

	cases := []struct {
		path   string
		action string
	}{
		{"app/secret", "read"},
		{"app/secret", "write"},
		{"app/secret", "delete"},
		{"other/path", "read"},
	}

	for _, tc := range cases {
		allowed, err := policySvc.Evaluate(ctx, tokenID, tc.path, tc.action)
		if err != nil {
			t.Fatalf("Evaluate(%q, %q): %v", tc.path, tc.action, err)
		}
		if allowed {
			t.Errorf("Evaluate(%q, %q): expected false for token with no policies, got true", tc.path, tc.action)
		}
	}
}

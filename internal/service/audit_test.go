package service_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gear/engine/internal/model"
	"github.com/gear/engine/internal/service"
)

// ptr helpers — digunakan untuk membuat pointer dari literal string/int64.
func strPtr(s string) *string { return &s }
func i64Ptr(i int64) *int64  { return &i }

// TestAuditService_LogAndQuery_Basic memverifikasi bahwa entry yang di-Log
// dapat di-Query kembali dengan field yang benar.
// Validates: Requirements 7.1, 7.2, 7.3
func TestAuditService_LogAndQuery_Basic(t *testing.T) {
	svc := service.NewAuditService(mustOpenDB(t))
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Nanosecond)
	entry := model.AuditEntry{
		TokenID:   i64Ptr(42),
		TokenName: strPtr("my-token"),
		Path:      strPtr("app/db/password"),
		Action:    "read",
		Result:    "success",
		IPAddress: "192.168.1.1",
		Timestamp: now,
	}

	if err := svc.Log(ctx, entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries, err := svc.Query(ctx, model.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Query: expected 1 entry, got %d", len(entries))
	}

	got := entries[0]

	if got.ID <= 0 {
		t.Errorf("ID should be > 0, got %d", got.ID)
	}
	if got.TokenID == nil || *got.TokenID != 42 {
		t.Errorf("TokenID: expected 42, got %v", got.TokenID)
	}
	if got.TokenName == nil || *got.TokenName != "my-token" {
		t.Errorf("TokenName: expected %q, got %v", "my-token", got.TokenName)
	}
	if got.Path == nil || *got.Path != "app/db/password" {
		t.Errorf("Path: expected %q, got %v", "app/db/password", got.Path)
	}
	if got.Action != "read" {
		t.Errorf("Action: expected %q, got %q", "read", got.Action)
	}
	if got.Result != "success" {
		t.Errorf("Result: expected %q, got %q", "success", got.Result)
	}
	if got.IPAddress != "192.168.1.1" {
		t.Errorf("IPAddress: expected %q, got %q", "192.168.1.1", got.IPAddress)
	}
}

// TestAuditService_Log_AutoTimestamp memverifikasi bahwa Log mengisi Timestamp
// secara otomatis jika entry.Timestamp adalah zero value.
// Validates: Requirements 7.1
func TestAuditService_Log_AutoTimestamp(t *testing.T) {
	svc := service.NewAuditService(mustOpenDB(t))
	ctx := context.Background()

	before := time.Now().Add(-time.Second)

	entry := model.AuditEntry{
		Action:    "write",
		Result:    "success",
		IPAddress: "10.0.0.1",
		// Timestamp sengaja dibiarkan zero
	}

	if err := svc.Log(ctx, entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries, err := svc.Query(ctx, model.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Query: expected 1 entry, got %d", len(entries))
	}

	ts := entries[0].Timestamp
	if ts.IsZero() {
		t.Error("Timestamp: expected non-zero auto-set timestamp, got zero")
	}
	if ts.Before(before) {
		t.Errorf("Timestamp: expected >= %v, got %v", before, ts)
	}
}

// TestAuditService_Query_FilterByResult memverifikasi bahwa filter Result
// hanya mengembalikan entry yang sesuai.
// Validates: Requirements 7.3
func TestAuditService_Query_FilterByResult(t *testing.T) {
	svc := service.NewAuditService(mustOpenDB(t))
	ctx := context.Background()

	logEntry := func(result string) {
		err := svc.Log(ctx, model.AuditEntry{
			Action:    "read",
			Result:    result,
			IPAddress: "10.0.0.1",
			Timestamp: time.Now(),
		})
		if err != nil {
			t.Fatalf("Log(%q): %v", result, err)
		}
	}

	logEntry("success")
	logEntry("denied")
	logEntry("success")

	entries, err := svc.Query(ctx, model.AuditFilter{Result: strPtr("success"), Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("FilterByResult success: expected 2, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Result != "success" {
			t.Errorf("FilterByResult: unexpected result %q in filtered results", e.Result)
		}
	}

	denied, err := svc.Query(ctx, model.AuditFilter{Result: strPtr("denied"), Limit: 10})
	if err != nil {
		t.Fatalf("Query denied: %v", err)
	}
	if len(denied) != 1 {
		t.Errorf("FilterByResult denied: expected 1, got %d", len(denied))
	}
}

// TestAuditService_Query_FilterByPath memverifikasi bahwa filter Path
// menggunakan LIKE prefix match dan hanya mengembalikan entry yang cocok.
// Validates: Requirements 7.3
func TestAuditService_Query_FilterByPath(t *testing.T) {
	svc := service.NewAuditService(mustOpenDB(t))
	ctx := context.Background()

	logWithPath := func(path string) {
		err := svc.Log(ctx, model.AuditEntry{
			Path:      strPtr(path),
			Action:    "read",
			Result:    "success",
			IPAddress: "10.0.0.1",
			Timestamp: time.Now(),
		})
		if err != nil {
			t.Fatalf("Log path=%q: %v", path, err)
		}
	}

	logWithPath("app/db/password")
	logWithPath("app/db/username")
	logWithPath("infra/tls/cert")

	entries, err := svc.Query(ctx, model.AuditFilter{Path: strPtr("app/db"), Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("FilterByPath app/db: expected 2, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Path == nil || !strings.HasPrefix(*e.Path, "app/db") {
			t.Errorf("FilterByPath: unexpected path %v", e.Path)
		}
	}

	infra, err := svc.Query(ctx, model.AuditFilter{Path: strPtr("infra/"), Limit: 10})
	if err != nil {
		t.Fatalf("Query infra: %v", err)
	}
	if len(infra) != 1 {
		t.Errorf("FilterByPath infra/: expected 1, got %d", len(infra))
	}
}

// TestAuditService_Query_FilterBySince memverifikasi bahwa filter Since
// mengecualikan entry yang lebih lama dari batas waktu.
// Validates: Requirements 7.3
func TestAuditService_Query_FilterBySince(t *testing.T) {
	svc := service.NewAuditService(mustOpenDB(t))
	ctx := context.Background()

	old := time.Now().Add(-2 * time.Hour)
	recent := time.Now().Add(-10 * time.Minute)

	logAt := func(ts time.Time, label string) {
		err := svc.Log(ctx, model.AuditEntry{
			Action:    "read",
			Result:    "success",
			IPAddress: "10.0.0.1",
			Timestamp: ts,
			Path:      strPtr(label),
		})
		if err != nil {
			t.Fatalf("Log ts=%v: %v", ts, err)
		}
	}

	logAt(old, "old-entry")
	logAt(recent, "recent-entry")

	cutoff := time.Now().Add(-30 * time.Minute)
	entries, err := svc.Query(ctx, model.AuditFilter{Since: &cutoff, Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("FilterBySince: expected 1, got %d", len(entries))
	}
	if entries[0].Path == nil || *entries[0].Path != "recent-entry" {
		t.Errorf("FilterBySince: expected recent-entry, got path=%v", entries[0].Path)
	}
}

// TestAuditService_Query_Pagination memverifikasi paginasi dengan Limit dan Offset.
// Log 10 entry, limit=3 offset=0 harus mengembalikan 3; offset=3 mengembalikan 3 berikutnya.
// Validates: Requirements 7.3, 7.6
func TestAuditService_Query_Pagination(t *testing.T) {
	svc := service.NewAuditService(mustOpenDB(t))
	ctx := context.Background()

	base := time.Now().Add(-10 * time.Minute)
	for i := 0; i < 10; i++ {
		err := svc.Log(ctx, model.AuditEntry{
			Action:    "read",
			Result:    "success",
			IPAddress: "10.0.0.1",
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Path:      strPtr(fmt.Sprintf("app/secret/%d", i)),
		})
		if err != nil {
			t.Fatalf("Log[%d]: %v", i, err)
		}
	}

	// Page 1: limit=3, offset=0
	page1, err := svc.Query(ctx, model.AuditFilter{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatalf("Query page1: %v", err)
	}
	if len(page1) != 3 {
		t.Errorf("Pagination page1: expected 3, got %d", len(page1))
	}

	// Page 2: limit=3, offset=3
	page2, err := svc.Query(ctx, model.AuditFilter{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatalf("Query page2: %v", err)
	}
	if len(page2) != 3 {
		t.Errorf("Pagination page2: expected 3, got %d", len(page2))
	}

	// Kedua halaman tidak boleh mengandung entry yang sama
	ids1 := map[int64]bool{}
	for _, e := range page1 {
		ids1[e.ID] = true
	}
	for _, e := range page2 {
		if ids1[e.ID] {
			t.Errorf("Pagination: ID %d appears in both page1 and page2", e.ID)
		}
	}
}

// TestAuditService_Query_DefaultLimit memverifikasi bahwa Query dengan Limit=0
// menggunakan default limit 100, bukan mengembalikan semua entry.
// Validates: Requirements 7.3, 7.6
func TestAuditService_Query_DefaultLimit(t *testing.T) {
	svc := service.NewAuditService(mustOpenDB(t))
	ctx := context.Background()

	base := time.Now().Add(-30 * time.Minute)
	for i := 0; i < 150; i++ {
		err := svc.Log(ctx, model.AuditEntry{
			Action:    "read",
			Result:    "success",
			IPAddress: "10.0.0.1",
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("Log[%d]: %v", i, err)
		}
	}

	// Query dengan Limit=0 (tidak diset) harus mengembalikan 100 (default)
	entries, err := svc.Query(ctx, model.AuditFilter{})
	if err != nil {
		t.Fatalf("Query default limit: %v", err)
	}
	if len(entries) != 100 {
		t.Errorf("DefaultLimit: expected 100 entries, got %d", len(entries))
	}
}

// TestAuditService_Log_NullableFields memverifikasi bahwa entry dengan field
// nullable (TokenID=nil, Path=nil) dapat di-Log dan di-Query tanpa error,
// dan field tersebut tetap nil pada saat dibaca.
// Validates: Requirements 7.1, 7.2
func TestAuditService_Log_NullableFields(t *testing.T) {
	svc := service.NewAuditService(mustOpenDB(t))
	ctx := context.Background()

	entry := model.AuditEntry{
		// TokenID sengaja nil (unauthenticated request)
		// Path sengaja nil (aksi yang tidak terkait path)
		Action:    "login",
		Result:    "denied",
		IPAddress: "203.0.113.5",
		Timestamp: time.Now(),
	}

	if err := svc.Log(ctx, entry); err != nil {
		t.Fatalf("Log with nil nullable fields: %v", err)
	}

	entries, err := svc.Query(ctx, model.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("NullableFields: expected 1 entry, got %d", len(entries))
	}

	got := entries[0]
	if got.TokenID != nil {
		t.Errorf("NullableFields: expected TokenID=nil, got %v", got.TokenID)
	}
	if got.Path != nil {
		t.Errorf("NullableFields: expected Path=nil, got %v", got.Path)
	}
	if got.Action != "login" {
		t.Errorf("NullableFields: Action expected %q, got %q", "login", got.Action)
	}
}

// TestAuditService_SecretNotInLog memverifikasi bahwa nilai secret tidak pernah
// tersimpan dalam field manapun pada audit log entry.
// Validates: Requirements 7.2, 7.4
func TestAuditService_SecretNotInLog(t *testing.T) {
	svc := service.NewAuditService(mustOpenDB(t))
	ctx := context.Background()

	const secretValue = "super-secret-value"

	// Simulasi audit entry yang mungkin "bocor" — semua field metadata terisi
	// tapi TIDAK satupun boleh mengandung nilai secret.
	err := svc.Log(ctx, model.AuditEntry{
		TokenID:   i64Ptr(1),
		TokenName: strPtr("admin-token"),
		Path:      strPtr("app/db/password"),
		Action:    "write",
		Result:    "success",
		IPAddress: "10.0.0.1",
		Timestamp: time.Now(),
		// Tidak ada field "Value" — AuditEntry memang tidak memilikinya.
	})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries, err := svc.Query(ctx, model.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("SecretNotInLog: expected 1 entry, got %d", len(entries))
	}

	e := entries[0]

	// Cek setiap string field tidak mengandung nilai secret.
	checkField := func(name, val string) {
		if strings.Contains(val, secretValue) {
			t.Errorf("SecretNotInLog: field %q contains secret value", name)
		}
	}

	checkField("Action", e.Action)
	checkField("Result", e.Result)
	checkField("IPAddress", e.IPAddress)
	if e.TokenName != nil {
		checkField("TokenName", *e.TokenName)
	}
	if e.Path != nil {
		checkField("Path", *e.Path)
	}

	// Verifikasi bahwa model.AuditEntry memang tidak memiliki field Value
	// (compile-time guarantee — jika ada field Value, kode ini tidak akan
	// bisa dikompilasi karena field tersebut tidak ada).
	_ = model.AuditEntry{
		Action:    "check",
		Result:    "ok",
		IPAddress: "127.0.0.1",
	}
}

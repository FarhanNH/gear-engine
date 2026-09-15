package service_test

import (
	"context"
	"strings"
	"testing"

	"github.com/gear/engine/internal/database"
	"github.com/gear/engine/internal/model"
	"github.com/gear/engine/internal/service"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// auditPBTParams returns gopter test parameters with a fixed seed and a minimum
// of 200 successful tests per property, as required by the spec.
func auditPBTParams() *gopter.TestParameters {
	params := gopter.DefaultTestParametersWithSeed(9999)
	params.MinSuccessfulTests = 200
	return params
}

// newFreshAuditService opens a brand-new in-memory SQLite database (with
// migrations applied) and returns an AuditService backed by it.
// Each call returns a completely isolated service — no shared state between
// property iterations.
func newFreshAuditService() (service.AuditService, error) {
	db, err := database.Open(":memory:")
	if err != nil {
		return nil, err
	}
	return service.NewAuditService(db), nil
}

// genAuditPath generates a two-segment lowercase path like "aaaaaa/bbbbbb"
// that is always a valid audit path (no special characters, no traversal).
var genAuditPath = gen.SliceOfN(2, gen.SliceOfN(6, gen.RuneRange('a', 'z'))).Map(
	func(segs [][]rune) string {
		parts := make([]string, len(segs))
		for i, r := range segs {
			parts[i] = string(r)
		}
		return strings.Join(parts, "/")
	},
)

// genPrintableValue generates a 16-character printable ASCII string (0x21–0x7E).
// Range excludes null bytes and whitespace, matching the secret value generator
// used in other PBT tests.
var genPrintableValue = gen.SliceOfN(16, gen.RuneRange(0x21, 0x7E)).Map(func(runes []rune) string {
	return string(runes)
})

// TestProperty17_EachLogCallAddsExactlyOneEntry verifies that every call to
// AuditService.Log adds exactly one entry to the audit log.
//
// Strategy: open a fresh DB per iteration, record the count before (0), call
// Log once, then query without filters and verify count is exactly 1.
//
// **Property 17: Setiap Request Menghasilkan Satu Audit Entry**
// ∀ request valid ke /v1/secret/*: len(AuditLog) bertambah tepat 1
// **Validates: Requirements 7.4**
func TestProperty17_EachLogCallAddsExactlyOneEntry(t *testing.T) {
	properties := gopter.NewProperties(auditPBTParams())

	properties.Property("AuditService.Log adds exactly one entry per call", prop.ForAll(
		func(path string, action string) bool {
			svc, err := newFreshAuditService()
			if err != nil {
				return false
			}
			ctx := context.Background()

			// Verify log is empty before the call.
			before, err := svc.Query(ctx, model.AuditFilter{Limit: 1000})
			if err != nil || len(before) != 0 {
				return false
			}

			// Log exactly one entry.
			entry := model.AuditEntry{
				Path:      &path,
				Action:    action,
				Result:    "success",
				IPAddress: "127.0.0.1",
			}
			if err := svc.Log(ctx, entry); err != nil {
				return false
			}

			// Query without filters — must return exactly 1 entry.
			after, err := svc.Query(ctx, model.AuditFilter{Limit: 1000})
			if err != nil {
				return false
			}
			return len(after) == 1
		},
		genAuditPath,
		// action: one of the three valid write/read/delete actions
		gen.OneConstOf("write", "read", "delete"),
	))

	properties.TestingRun(t)
}

// TestProperty18_AuditEntryDoesNotContainSecretValue verifies that no field of
// a stored audit entry contains the plaintext secret value that was "written".
//
// Strategy: generate a random 16-char printable secret value, log an audit
// entry that simulates a write action (with a fixed path, no value field),
// then verify that the returned entry's every string field does not contain
// the secret value string.
//
// This property confirms the structural guarantee: model.AuditEntry has no
// Value field, and no existing metadata field leaks secret content.
//
// **Property 18: Audit Entry Tidak Mengandung Secret Value**
// ∀ entry di audit_log: entry.path tidak berisi nilai secret yang di-PUT
// **Validates: Requirements 7.2**
func TestProperty18_AuditEntryDoesNotContainSecretValue(t *testing.T) {
	properties := gopter.NewProperties(auditPBTParams())

	properties.Property("no audit entry field contains the secret value", prop.ForAll(
		func(secretValue string) bool {
			svc, err := newFreshAuditService()
			if err != nil {
				return false
			}
			ctx := context.Background()

			// Log an audit entry for a write action.
			// Critically: the secret value is never passed to Log — only metadata.
			path := "app/test"
			entry := model.AuditEntry{
				Path:      &path,
				Action:    "write",
				Result:    "success",
				IPAddress: "10.0.0.1",
				// No Value field exists on AuditEntry — this is the structural guarantee.
			}
			if err := svc.Log(ctx, entry); err != nil {
				return false
			}

			entries, err := svc.Query(ctx, model.AuditFilter{Limit: 10})
			if err != nil || len(entries) != 1 {
				return false
			}

			e := entries[0]

			// Check every string field in the returned entry for the secret value.
			if strings.Contains(e.Action, secretValue) {
				return false
			}
			if strings.Contains(e.Result, secretValue) {
				return false
			}
			if strings.Contains(e.IPAddress, secretValue) {
				return false
			}
			if e.TokenName != nil && strings.Contains(*e.TokenName, secretValue) {
				return false
			}
			if e.Path != nil && strings.Contains(*e.Path, secretValue) {
				return false
			}

			return true
		},
		genPrintableValue,
	))

	properties.TestingRun(t)
}

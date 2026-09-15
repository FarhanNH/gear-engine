package service_test

import (
	"bytes"
	"context"
	"database/sql"
	"testing"

	"github.com/gear/engine/internal/database"
	"github.com/gear/engine/internal/service"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// envelopePBTParams returns gopter test parameters with a fixed seed and
// minimum 200 successful tests per property, as required by the spec.
func envelopePBTParams() *gopter.TestParameters {
	params := gopter.DefaultTestParametersWithSeed(9999)
	params.MinSuccessfulTests = 200
	return params
}

// newEnvelopeDB opens a fresh in-memory SQLite database with migrations applied.
// The caller is responsible for closing it. Returns the *sql.DB directly so
// properties can query encrypted_dek values from the DB.
func newEnvelopeDB() (*sql.DB, error) {
	return database.Open(":memory:")
}

// genMasterKey generates a random 32-byte master key via crypto.GenerateKey.
var genMasterKey = gen.SliceOfN(32, gen.UInt8Range(0, 255)).Map(func(b []uint8) []byte {
	return b
}).SuchThat(func(b []byte) bool {
	return len(b) == 32
})

// genSecretValue generates a non-empty printable ASCII string (8–24 chars).
var genEnvelopeValue = gen.SliceOfN(16, gen.RuneRange(0x21, 0x7E)).Map(func(runes []rune) string {
	return string(runes)
})

// TestProperty19_WrongMasterKeyCannotDecrypt verifies that a SecretService
// using a different master key cannot decrypt a secret stored by another
// SecretService. Every iteration uses a fresh DB and two distinct 32-byte keys.
//
// **Validates: Requirements 2.4, 2.7**
func TestProperty19_WrongMasterKeyCannotDecrypt(t *testing.T) {
	properties := gopter.NewProperties(envelopePBTParams())

	properties.Property("decrypt with wrong master key returns error", prop.ForAll(
		func(key1 []byte, key2 []byte, path string, value string) bool {
			// Skip if the two keys happen to be identical — that would not
			// exercise the "wrong key" scenario.
			if bytes.Equal(key1, key2) {
				return true
			}

			db, err := newEnvelopeDB()
			if err != nil {
				return false
			}
			defer database.Close(db)

			ctx := context.Background()

			// Store secret using the correct master key.
			svcWriter := service.NewSecretService(db, key1)
			if err := svcWriter.Put(ctx, path, value); err != nil {
				return false
			}

			// Attempt to read the secret using the wrong master key.
			svcReader := service.NewSecretService(db, key2)
			_, err = svcReader.Get(ctx, path)

			// Decryption MUST fail when the wrong master key is used.
			return err != nil
		},
		genMasterKey,     // key1 — used to write
		genMasterKey,     // key2 — used to read (wrong key)
		genValidPath,     // path — reuse generator from secret_pbt_test.go
		genEnvelopeValue, // value
	))

	properties.TestingRun(t)
}

// TestProperty20_EachSecretHasUniqueDEK verifies that two secrets stored under
// different paths each receive a unique encrypted DEK (stored in the
// encrypted_dek column), meaning DEK generation is non-deterministic and
// per-secret. Also verifies both secrets are still readable (Put-Get round trip).
//
// **Validates: Requirements 2.1**
func TestProperty20_EachSecretHasUniqueDEK(t *testing.T) {
	properties := gopter.NewProperties(envelopePBTParams())

	// Generate two distinct path segments so path1 != path2.
	genTwoDistinctSegments := gen.SliceOfN(2, genSegment).SuchThat(func(segs []string) bool {
		return segs[0] != segs[1]
	})

	properties.Property("two different secrets have distinct encrypted DEKs", prop.ForAll(
		func(masterKey []byte, segments []string, val1 string, val2 string) bool {
			path1 := segments[0] + "/secret"
			path2 := segments[1] + "/secret"

			db, err := newEnvelopeDB()
			if err != nil {
				return false
			}
			defer database.Close(db)

			ctx := context.Background()
			svc := service.NewSecretService(db, masterKey)

			// Store both secrets.
			if err := svc.Put(ctx, path1, val1); err != nil {
				return false
			}
			if err := svc.Put(ctx, path2, val2); err != nil {
				return false
			}

			// Read encrypted_dek directly from the DB.
			var dek1, dek2 []byte
			row1 := db.QueryRowContext(ctx, `SELECT encrypted_dek FROM secrets WHERE path = ?`, path1)
			if err := row1.Scan(&dek1); err != nil {
				return false
			}
			row2 := db.QueryRowContext(ctx, `SELECT encrypted_dek FROM secrets WHERE path = ?`, path2)
			if err := row2.Scan(&dek2); err != nil {
				return false
			}

			// The encrypted DEKs must differ — each secret has its own DEK.
			if bytes.Equal(dek1, dek2) {
				return false
			}

			// Both secrets must still be decryptable (Put-Get round trip).
			got1, err := svc.Get(ctx, path1)
			if err != nil || got1 != val1 {
				return false
			}
			got2, err := svc.Get(ctx, path2)
			if err != nil || got2 != val2 {
				return false
			}

			return true
		},
		genMasterKey,            // master key shared by both secrets
		genTwoDistinctSegments,  // [segment1, segment2] guaranteed distinct
		genEnvelopeValue,        // val1
		genEnvelopeValue,        // val2
	))

	properties.TestingRun(t)
}

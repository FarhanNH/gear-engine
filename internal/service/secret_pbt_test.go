package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gear/engine/internal/crypto"
	"github.com/gear/engine/internal/database"
	"github.com/gear/engine/internal/service"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// secretPBTParams returns gopter test parameters with a fixed seed and minimum
// 200 successful tests per property, as required by the spec.
func secretPBTParams() *gopter.TestParameters {
	params := gopter.DefaultTestParametersWithSeed(5678)
	params.MinSuccessfulTests = 200
	return params
}

// newSecretServiceFresh creates a brand-new SecretService backed by an
// in-memory SQLite database and a freshly generated Master Key.
// Each call returns a completely isolated service — no shared state.
func newSecretServiceFresh() (service.SecretService, error) {
	db, err := database.Open(":memory:")
	if err != nil {
		return nil, err
	}
	masterKey, err := crypto.GenerateKey()
	if err != nil {
		database.Close(db)
		return nil, err
	}
	return service.NewSecretService(db, masterKey), nil
}

// genSegment generates a fixed 6-character lowercase alphabetic string.
// This is a valid single path segment with no special characters.
var genSegment = gen.SliceOfN(6, gen.RuneRange('a', 'z')).Map(func(runes []rune) string {
	return string(runes)
})

// genValidPath generates a two-segment valid path "aaaaaa/bbbbbb".
// Total length is always 13 chars — well within the 512-char limit.
// Contains only [a-z] and '/', no traversal sequences.
var genValidPath = gen.SliceOfN(2, gen.SliceOfN(6, gen.RuneRange('a', 'z'))).Map(
	func(segRunes [][]rune) string {
		parts := make([]string, len(segRunes))
		for i, r := range segRunes {
			parts[i] = string(r)
		}
		return strings.Join(parts, "/")
	},
)

// genStringValue generates a 16-character printable ASCII string value.
// Range 0x21 ('!') to 0x7E ('~') ensures no null bytes, no whitespace.
var genStringValue = gen.SliceOfN(16, gen.RuneRange(0x21, 0x7E)).Map(func(runes []rune) string {
	return string(runes)
})

// TestProperty10_PutGetRoundTrip verifies that for any valid path and any
// string value, Get returns the exact same value after a Put.
//
// **Validates: Requirements 2.6, 6.1, 6.2**
func TestProperty10_PutGetRoundTrip(t *testing.T) {
	properties := gopter.NewProperties(secretPBTParams())

	properties.Property("Get(path) == value after Put(path, value)", prop.ForAll(
		func(path string, value string) bool {
			svc, err := newSecretServiceFresh()
			if err != nil {
				return false
			}
			ctx := context.Background()

			if err := svc.Put(ctx, path, value); err != nil {
				return false
			}
			got, err := svc.Get(ctx, path)
			if err != nil {
				return false
			}
			return got == value
		},
		genValidPath,
		genStringValue,
	))

	properties.TestingRun(t)
}

// TestProperty11_DeleteIdempotent verifies that after a successful Delete,
// a second Delete on the same path returns ErrSecretNotFound.
//
// **Validates: Requirements 6.3, 6.5**
func TestProperty11_DeleteIdempotent(t *testing.T) {
	properties := gopter.NewProperties(secretPBTParams())

	properties.Property("second Delete returns ErrSecretNotFound", prop.ForAll(
		func(path string) bool {
			svc, err := newSecretServiceFresh()
			if err != nil {
				return false
			}
			ctx := context.Background()

			// Seed a secret so the first Delete has something to remove.
			if err := svc.Put(ctx, path, "some-value"); err != nil {
				return false
			}

			// First delete — must succeed.
			if err := svc.Delete(ctx, path); err != nil {
				return false
			}

			// Second delete — must return ErrSecretNotFound.
			err = svc.Delete(ctx, path)
			return errors.Is(err, service.ErrSecretNotFound)
		},
		genValidPath,
	))

	properties.TestingRun(t)
}

// TestProperty12_ListPrefixConsistent verifies that every path returned by
// List(prefix) starts with the requested prefix.
//
// Strategy: generate a 6-char prefix and a 6-char child token. Derive three
// child paths ("prefix/childXa", "prefix/childXb", "prefix/childXc"), insert
// them plus decoy secrets under an unrelated prefix, then verify every path
// returned by List(prefix) starts with the prefix.
//
// **Validates: Requirements 6.4**
func TestProperty12_ListPrefixConsistent(t *testing.T) {
	properties := gopter.NewProperties(secretPBTParams())

	// Generate two independent segments: one is the prefix, the other the child base.
	properties.Property("all paths returned by List have the requested prefix", prop.ForAll(
		func(prefix string, child string) bool {
			svc, err := newSecretServiceFresh()
			if err != nil {
				return false
			}
			ctx := context.Background()

			// Build three child paths under the prefix.
			childPaths := []string{
				prefix + "/" + child + "x",
				prefix + "/" + child + "y",
				prefix + "/" + child + "z",
			}
			for _, p := range childPaths {
				if err := svc.Put(ctx, p, "val"); err != nil {
					return false
				}
			}

			// Insert decoy secrets under a clearly different prefix so the
			// List query has something to exclude.
			for _, sfx := range []string{"decoya", "decoyb", "decoyc"} {
				_ = svc.Put(ctx, "zzzfix/"+sfx, "decoy")
			}

			got, err := svc.List(ctx, prefix)
			if err != nil {
				return false
			}

			// Every returned path must start with the requested prefix.
			for _, p := range got {
				if !strings.HasPrefix(p, prefix) {
					return false
				}
			}

			// We must get at least the 3 child paths we inserted.
			return len(got) >= len(childPaths)
		},
		genSegment, // prefix
		genSegment, // child base
	))

	properties.TestingRun(t)
}

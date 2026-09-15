package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/gear/engine/internal/database"
	"github.com/gear/engine/internal/service"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// policyPBTParameters returns gopter test parameters with a fixed seed and
// minimum 200 successful tests per property, as required by the spec.
func policyPBTParameters() *gopter.TestParameters {
	params := gopter.DefaultTestParametersWithSeed(9012)
	params.MinSuccessfulTests = 200
	return params
}

// genSixCharLower generates a fixed 6-character lowercase alphabetic string.
// Used to generate both the prefix and the child path segment for Properties 15 and 16.
var genSixCharLower = gen.SliceOfN(6, gen.RuneRange('a', 'z')).Map(func(runes []rune) string {
	return string(runes)
})

// TestProperty15_WildcardPolicyConsistent verifies that a policy created with
// pattern "prefix/*" allows access to any path that starts with "prefix/".
//
// For each iteration:
//  1. Open a fresh in-memory DB.
//  2. Create a token via TokenService.Create().
//  3. Create a policy: pattern = prefix + "/*", action = "read".
//  4. Evaluate for path = prefix + "/" + child — must return true.
//
// Property: ∀ prefix, path having prefix: Evaluate("prefix/*") == allowed
// **Validates: Requirements 5.5**
func TestProperty15_WildcardPolicyConsistent(t *testing.T) {
	properties := gopter.NewProperties(policyPBTParameters())

	properties.Property("wildcard policy prefix/* always allows prefix/child", prop.ForAll(
		func(prefix string, child string) bool {
			// Fresh DB per iteration.
			db, err := database.Open(":memory:")
			if err != nil {
				return false
			}
			defer database.Close(db) //nolint:errcheck

			ctx := context.Background()
			tokenSvc := service.NewTokenService(db)
			policySvc := service.NewPolicyService(db)

			// Create a real token to get a valid token_id.
			_, tokenID, err := tokenSvc.Create(ctx, "pbt-token", time.Hour)
			if err != nil {
				return false
			}

			// Create wildcard policy: pattern = prefix + "/*", permission = "read".
			pattern := prefix + "/*"
			if err := policySvc.Create(ctx, tokenID, pattern, []string{"read"}); err != nil {
				return false
			}

			// Path under the prefix: prefix + "/" + child.
			path := prefix + "/" + child

			// Evaluate must return true.
			allowed, err := policySvc.Evaluate(ctx, tokenID, path, "read")
			if err != nil {
				return false
			}
			return allowed
		},
		genSixCharLower, // prefix
		genSixCharLower, // child segment
	))

	properties.TestingRun(t)
}

// TestProperty16_NoPolicyAlwaysDenied verifies that when a token has a policy
// only for a different path prefix, Evaluate for the target path returns false.
//
// For each iteration:
//  1. Open a fresh in-memory DB.
//  2. Create a token via TokenService.Create().
//  3. Create a policy ONLY for "other_prefix/*" (not for the tested path prefix).
//  4. Evaluate for path = tested_prefix + "/" + child — must return false.
//
// We ensure "other_prefix" != "tested_prefix" by picking the first char of
// other_prefix from 'a'-'m' and the first char of tested_prefix from 'n'-'z',
// so they never collide.
//
// Property: ∀ tokenID without policy for path: Evaluate == false
// **Validates: Requirements 5.2, 5.3**
func TestProperty16_NoPolicyAlwaysDenied(t *testing.T) {
	properties := gopter.NewProperties(policyPBTParameters())

	// genPrefixLow: first char in [a-m], rest 5 chars [a-z].
	genPrefixLow := gen.SliceOfN(5, gen.RuneRange('a', 'z')).Map(func(runes []rune) string {
		// Prepend 'a' so this prefix always starts lower than genPrefixHigh.
		return "a" + string(runes)
	})

	// genPrefixHigh: first char in [n-z], rest 5 chars [a-z].
	genPrefixHigh := gen.SliceOfN(5, gen.RuneRange('a', 'z')).Map(func(runes []rune) string {
		// Prepend 'z' so this prefix always starts higher than genPrefixLow.
		return "z" + string(runes)
	})

	properties.Property("token with no matching policy is always denied", prop.ForAll(
		func(policyPrefix string, testedPrefix string, child string) bool {
			// Guard: if prefixes somehow match, skip this case.
			// (Should never happen with our generator design, but safety first.)
			if policyPrefix == testedPrefix {
				return true
			}

			// Fresh DB per iteration.
			db, err := database.Open(":memory:")
			if err != nil {
				return false
			}
			defer database.Close(db) //nolint:errcheck

			ctx := context.Background()
			tokenSvc := service.NewTokenService(db)
			policySvc := service.NewPolicyService(db)

			// Create a real token.
			_, tokenID, err := tokenSvc.Create(ctx, "pbt-no-match", time.Hour)
			if err != nil {
				return false
			}

			// Create a policy ONLY for the policyPrefix, not for testedPrefix.
			if err := policySvc.Create(ctx, tokenID, policyPrefix+"/*", []string{"read"}); err != nil {
				return false
			}

			// Evaluate for a path under testedPrefix — must return false.
			path := testedPrefix + "/" + child
			allowed, err := policySvc.Evaluate(ctx, tokenID, path, "read")
			if err != nil {
				return false
			}
			return !allowed
		},
		genPrefixLow,    // policyPrefix  (starts with 'a')
		genPrefixHigh,   // testedPrefix  (starts with 'z')
		genSixCharLower, // child segment
	))

	properties.TestingRun(t)
}

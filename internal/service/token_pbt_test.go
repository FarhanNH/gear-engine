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

// tokenPBTParameters returns gopter test parameters with a fixed seed and
// minimum 200 successful tests per property, as required by the spec.
func tokenPBTParameters() *gopter.TestParameters {
	params := gopter.DefaultTestParametersWithSeed(5678)
	params.MinSuccessfulTests = 200
	return params
}

// newFreshTokenService opens a fresh in-memory SQLite DB (with migrations) and
// returns a TokenServiceImpl backed by it.  Each call returns an independent
// service so property iterations cannot interfere with each other.
func newFreshTokenService(t *testing.T) *service.TokenServiceImpl {
	t.Helper()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("newFreshTokenService: open db: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(db); err != nil {
			t.Errorf("newFreshTokenService cleanup: %v", err)
		}
	})
	return service.NewTokenService(db)
}

// genTokenName generates a random lowercase alpha string between 3 and 10
// characters — a valid token name for every iteration.
var genTokenName = gen.RegexMatch("^[a-z]{3,10}$")

// genTTLHours generates a random TTL between 1 h and 24 h (step: 1 h).
var genTTLHours = gen.IntRange(1, 24).Map(func(hours int) time.Duration {
	return time.Duration(hours) * time.Hour
})

// TestProperty13_NewlyCreatedTokenAlwaysValid verifies that a token returned
// by Create is immediately accepted by Validate with no error.
//
// Property: ∀ name, ttl > 0: Validate(Create(name, ttl).plaintext) == valid
// Validates: Requirements 4.1, 4.2, 4.3
func TestProperty13_NewlyCreatedTokenAlwaysValid(t *testing.T) {
	properties := gopter.NewProperties(tokenPBTParameters())

	properties.Property("newly created token is always valid", prop.ForAll(
		func(name string, ttl time.Duration) bool {
			// Fresh DB per iteration — no cross-test pollution.
			db, err := database.Open(":memory:")
			if err != nil {
				return false
			}
			defer database.Close(db) //nolint:errcheck

			svc := service.NewTokenService(db)
			ctx := context.Background()

			plaintext, _, err := svc.Create(ctx, name, ttl)
			if err != nil {
				return false
			}

			tok, err := svc.Validate(ctx, plaintext)
			if err != nil {
				return false
			}

			// Validate must return a non-nil, non-revoked token.
			return tok != nil && !tok.Revoked
		},
		genTokenName,
		genTTLHours,
	))

	properties.TestingRun(t)
}

// TestProperty14_RevokedTokenAlwaysInvalid verifies that a token becomes
// permanently invalid after it has been revoked.
//
// Property: ∀ token: Validate setelah Revoke == ErrTokenRevoked
// Validates: Requirements 4.5, 4.6
func TestProperty14_RevokedTokenAlwaysInvalid(t *testing.T) {
	properties := gopter.NewProperties(tokenPBTParameters())

	properties.Property("revoked token always returns ErrTokenRevoked", prop.ForAll(
		func(name string) bool {
			// Fresh DB per iteration — no cross-test pollution.
			db, err := database.Open(":memory:")
			if err != nil {
				return false
			}
			defer database.Close(db) //nolint:errcheck

			svc := service.NewTokenService(db)
			ctx := context.Background()

			plaintext, id, err := svc.Create(ctx, name, time.Hour)
			if err != nil {
				return false
			}

			if err := svc.Revoke(ctx, id); err != nil {
				return false
			}

			_, err = svc.Validate(ctx, plaintext)
			return err == service.ErrTokenRevoked
		},
		genTokenName,
	))

	properties.TestingRun(t)
}

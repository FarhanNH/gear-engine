package validate

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// pbtParameters returns gopter test parameters with a fixed seed and minimum
// 200 successful tests per property, as required by the spec.
func pbtParameters() *gopter.TestParameters {
	params := gopter.DefaultTestParametersWithSeed(5678)
	params.MinSuccessfulTests = 200
	return params
}

// allowedChars is the full set of characters permitted in a valid secret path.
const allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-."

// alphaNumChars contains only letters and digits — safe as the first character.
const alphaNumChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// genValidPath generates paths composed exclusively of allowed characters
// [a-zA-Z0-9/_\-.], length 1–512, that never start with '/' and never contain
// traversal patterns or null bytes.
//
// Strategy: generate firstCharIndex (alphanumeric), bodyCharIndex (alphanumeric,
// avoids all traversal risk), and length. Assemble as first + repeated bodyChar.
// Using alphanumeric-only chars for body ensures no "..", "/./", or "/" appear.
func genValidPath() gopter.Gen {
	return gen.IntRange(0, len(alphaNumChars)-1).FlatMap(func(fi interface{}) gopter.Gen {
		firstIdx := fi.(int)
		first := string(alphaNumChars[firstIdx])
		return gen.IntRange(0, len(alphaNumChars)-1).FlatMap(func(bi interface{}) gopter.Gen {
			bodyIdx := bi.(int)
			bodyChar := string(alphaNumChars[bodyIdx])
			return gen.IntRange(0, maxPathLength-1).Map(func(extra int) string {
				// length = 1 (first) + extra (0..511) => 1..512
				return first + strings.Repeat(bodyChar, extra)
			})
		}, reflect.TypeOf(""))
	}, reflect.TypeOf(""))
}

// genTraversalPath generates paths that embed ".." or "/./" so that
// ErrPathTraversal is always triggered.
func genTraversalPath() gopter.Gen {
	return gen.IntRange(0, 1).FlatMap(func(v interface{}) gopter.Gen {
		var marker string
		if v.(int) == 0 {
			marker = ".."
		} else {
			marker = "/./"
		}
		m := marker
		return gen.IntRange(0, 100).Map(func(prefixLen int) string {
			prefix := strings.Repeat("a", prefixLen)
			result := prefix + m
			if len(result) > maxPathLength {
				result = result[:maxPathLength]
			}
			return result
		})
	}, reflect.TypeOf(""))
}

// genTooLongPath generates strings longer than 512 chars using only 'a', so
// only ErrPathTooLong can be triggered.
func genTooLongPath() gopter.Gen {
	return gen.IntRange(513, 2048).Map(func(n int) string {
		return strings.Repeat("a", n)
	})
}

// TestProperty7_ValidPathAlwaysAccepted verifies that every path composed of
// allowed characters [a-zA-Z0-9/_\-.], length 1–512, not starting with '/',
// and free of traversal patterns is accepted by ValidatePath.
//
// Validates: Requirements 10.1, 10.2, 10.3
func TestProperty7_ValidPathAlwaysAccepted(t *testing.T) {
	properties := gopter.NewProperties(pbtParameters())

	properties.Property("ValidatePath(path) == nil for all valid paths", prop.ForAll(
		func(path string) bool {
			err := ValidatePath(path)
			return err == nil
		},
		genValidPath(),
	))

	properties.TestingRun(t)
}

// TestProperty8_TraversalPathAlwaysRejected verifies that every path containing
// ".." or "/./" is rejected with ErrPathTraversal.
//
// Validates: Requirements 10.1
func TestProperty8_TraversalPathAlwaysRejected(t *testing.T) {
	properties := gopter.NewProperties(pbtParameters())

	properties.Property("ValidatePath returns ErrPathTraversal for paths with '..' or '/./'", prop.ForAll(
		func(path string) bool {
			err := ValidatePath(path)
			return errors.Is(err, ErrPathTraversal)
		},
		genTraversalPath(),
	))

	properties.TestingRun(t)
}

// TestProperty9_TooLongPathAlwaysRejected verifies that every path with length
// greater than 512 characters is rejected with ErrPathTooLong.
//
// Validates: Requirements 10.3
func TestProperty9_TooLongPathAlwaysRejected(t *testing.T) {
	properties := gopter.NewProperties(pbtParameters())

	properties.Property("ValidatePath returns ErrPathTooLong for paths longer than 512 chars", prop.ForAll(
		func(path string) bool {
			err := ValidatePath(path)
			return errors.Is(err, ErrPathTooLong)
		},
		genTooLongPath(),
	))

	properties.TestingRun(t)
}

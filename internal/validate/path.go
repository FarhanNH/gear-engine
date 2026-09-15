package validate

import (
	"errors"
	"regexp"
	"strings"
)

var (
	// ErrPathTooLong is returned when the path exceeds the maximum allowed length.
	ErrPathTooLong = errors.New("path exceeds maximum length of 512 characters")

	// ErrPathTraversal is returned when the path contains a traversal pattern.
	ErrPathTraversal = errors.New("path contains traversal pattern")

	// ErrInvalidPathChars is returned when the path contains characters outside the allowed set.
	ErrInvalidPathChars = errors.New("path contains invalid characters")
)

// allowedPathPattern matches paths that only contain safe characters.
var allowedPathPattern = regexp.MustCompile(`^[a-zA-Z0-9/_\-\.]+$`)

const maxPathLength = 512

// ValidatePath validates that the given path is safe to use as a secret path.
// It checks for maximum length, traversal patterns, and allowed characters.
//
// Requirements: 5.6, 10.1, 10.2, 10.3
func ValidatePath(path string) error {
	// 1. Length check
	if len(path) > maxPathLength {
		return ErrPathTooLong
	}

	// 2. Traversal patterns: "..", "/./", null byte, leading "/"
	if strings.Contains(path, "..") ||
		strings.Contains(path, "/./") ||
		strings.ContainsRune(path, 0) ||
		strings.HasPrefix(path, "/") {
		return ErrPathTraversal
	}

	// 3. Allowed characters only
	if !allowedPathPattern.MatchString(path) {
		return ErrInvalidPathChars
	}

	return nil
}

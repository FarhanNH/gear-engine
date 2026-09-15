package validate

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePath(t *testing.T) {
	t.Run("valid paths", func(t *testing.T) {
		validCases := []struct {
			name string
			path string
		}{
			{"single char", "a"},
			{"simple app/key", "app/db/password"},
			{"three segments", "abc/def/ghi"},
			{"hyphen underscore dot version", "my-app_v1.2/key"},
			{"uppercase segments", "A/B/C"},
			{"digits only segments", "123/456"},
			{"mixed alphanumeric", "App1/Key2/val3"},
			{"all allowed specials: hyphen dot underscore", "a-b.c_d/e"},
			{"max allowed length (512)", strings.Repeat("a", 512)},
			{"dot in name but not traversal", "app/v1.0/secret"},
			{"single segment no slash", "mysecret"},
			{"digits and letters mixed", "abc123"},
			{"full charset", "aZ0/_-."},
		}

		for _, tc := range validCases {
			t.Run(tc.name, func(t *testing.T) {
				err := ValidatePath(tc.path)
				if err != nil {
					t.Errorf("expected nil error for path %q, got: %v", tc.path, err)
				}
			})
		}
	})

	t.Run("reject traversal patterns", func(t *testing.T) {
		cases := []struct {
			name string
			path string
		}{
			{"bare dotdot", ".."},
			{"dotdot prefix", "../etc/passwd"},
			{"dotdot in middle", "app/../secret"},
			{"slash-dot-slash", "app/./secret"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := ValidatePath(tc.path)
				if !errors.Is(err, ErrPathTraversal) {
					t.Errorf("expected ErrPathTraversal for path %q, got: %v", tc.path, err)
				}
			})
		}
	})

	t.Run("reject null byte", func(t *testing.T) {
		path := "app/key\x00extra"
		err := ValidatePath(path)
		if !errors.Is(err, ErrPathTraversal) {
			t.Errorf("expected ErrPathTraversal for path with null byte, got: %v", err)
		}
	})

	t.Run("reject leading slash", func(t *testing.T) {
		cases := []struct {
			name string
			path string
		}{
			{"absolute path", "/app/key"},
			{"bare slash", "/"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := ValidatePath(tc.path)
				if !errors.Is(err, ErrPathTraversal) {
					t.Errorf("expected ErrPathTraversal for path %q, got: %v", tc.path, err)
				}
			})
		}
	})

	t.Run("reject non-ASCII characters", func(t *testing.T) {
		cases := []struct {
			name string
			path string
		}{
			{"latin extended", "app/pässword"},
			{"cyrillic", "app/кey"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := ValidatePath(tc.path)
				if !errors.Is(err, ErrInvalidPathChars) {
					t.Errorf("expected ErrInvalidPathChars for path %q, got: %v", tc.path, err)
				}
			})
		}
	})

	t.Run("reject path over 512 chars", func(t *testing.T) {
		path := strings.Repeat("a", 513)
		err := ValidatePath(path)
		if !errors.Is(err, ErrPathTooLong) {
			t.Errorf("expected ErrPathTooLong for 513-char path, got: %v", err)
		}
	})

	t.Run("reject empty path", func(t *testing.T) {
		err := ValidatePath("")
		if !errors.Is(err, ErrInvalidPathChars) {
			t.Errorf("expected ErrInvalidPathChars for empty path, got: %v", err)
		}
	})
}

func TestValidatePath_SentinelErrors(t *testing.T) {
	t.Run("ErrPathTooLong is distinct sentinel", func(t *testing.T) {
		err := ValidatePath(strings.Repeat("x", 513))
		if !errors.Is(err, ErrPathTooLong) {
			t.Fatalf("expected ErrPathTooLong, got %v", err)
		}
		if errors.Is(err, ErrPathTraversal) || errors.Is(err, ErrInvalidPathChars) {
			t.Fatal("ErrPathTooLong must not match other sentinel errors")
		}
	})

	t.Run("ErrPathTraversal is distinct sentinel", func(t *testing.T) {
		err := ValidatePath("../secret")
		if !errors.Is(err, ErrPathTraversal) {
			t.Fatalf("expected ErrPathTraversal, got %v", err)
		}
		if errors.Is(err, ErrPathTooLong) || errors.Is(err, ErrInvalidPathChars) {
			t.Fatal("ErrPathTraversal must not match other sentinel errors")
		}
	})

	t.Run("ErrInvalidPathChars is distinct sentinel", func(t *testing.T) {
		err := ValidatePath("app/pässword")
		if !errors.Is(err, ErrInvalidPathChars) {
			t.Fatalf("expected ErrInvalidPathChars, got %v", err)
		}
		if errors.Is(err, ErrPathTooLong) || errors.Is(err, ErrPathTraversal) {
			t.Fatal("ErrInvalidPathChars must not match other sentinel errors")
		}
	})
}

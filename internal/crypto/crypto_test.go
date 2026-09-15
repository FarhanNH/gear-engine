package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// ── AES-256-GCM ──────────────────────────────────────────────────────────────

func TestEncryptDecryptRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"ascii sentence", []byte("the quick brown fox jumps over the lazy dog")},
		{"binary data", []byte{0x00, 0xFF, 0x10, 0x20, 0xAB, 0xCD}},
		{"unicode", []byte("こんにちは世界 — привет мир")},
	}

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ct, nonce, err := Encrypt(tc.plaintext, key)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			got, err := Decrypt(ct, nonce, key)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(got, tc.plaintext) {
				t.Errorf("round-trip mismatch: want %q, got %q", tc.plaintext, got)
			}
		})
	}
}

func TestEncryptKeySize(t *testing.T) {
	plaintext := []byte("test")
	tests := []struct {
		name    string
		keySize int
	}{
		{"zero", 0},
		{"16 bytes (AES-128)", 16},
		{"24 bytes (AES-192)", 24},
		{"31 bytes", 31},
		{"33 bytes", 33},
		{"64 bytes", 64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keySize)
			_, _, err := Encrypt(plaintext, key)
			if err == nil {
				t.Errorf("expected error for key size %d, got nil", tc.keySize)
			}
		})
	}

	// Correct key size must succeed
	t.Run("32 bytes ok", func(t *testing.T) {
		key := make([]byte, 32)
		_, _, err := Encrypt(plaintext, key)
		if err != nil {
			t.Errorf("unexpected error for 32-byte key: %v", err)
		}
	})
}

func TestDecryptKeySize(t *testing.T) {
	key32, _ := GenerateKey()
	ct, nonce, _ := Encrypt([]byte("test"), key32)

	badKey := make([]byte, 16)
	_, err := Decrypt(ct, nonce, badKey)
	if err == nil {
		t.Error("expected error when decrypting with wrong key size, got nil")
	}
}

func TestEncryptNonceUniqueness(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	plaintext := []byte("same data every time")

	const iterations = 100
	nonces := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		_, nonce, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encrypt iteration %d: %v", i, err)
		}
		k := hex.EncodeToString(nonce)
		if _, dup := nonces[k]; dup {
			t.Fatalf("duplicate nonce detected at iteration %d", i)
		}
		nonces[k] = struct{}{}
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	ct, nonce, err := Encrypt([]byte("sensitive"), key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip the first byte of the ciphertext.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[0] ^= 0xFF

	_, err = Decrypt(tampered, nonce, key)
	if err == nil {
		t.Error("expected error when decrypting tampered ciphertext, got nil")
	}
}

// ── GenerateKey ───────────────────────────────────────────────────────────────

func TestGenerateKeySize(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(key))
	}
}

func TestGenerateKeyUniqueness(t *testing.T) {
	const iterations = 50
	keys := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey iteration %d: %v", i, err)
		}
		k := hex.EncodeToString(key)
		if _, dup := keys[k]; dup {
			t.Fatalf("duplicate key generated at iteration %d", i)
		}
		keys[k] = struct{}{}
	}
}

// ── GenerateToken / HashToken ─────────────────────────────────────────────────

func TestGenerateTokenFormat(t *testing.T) {
	const iterations = 20
	for i := 0; i < iterations; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken iteration %d: %v", i, err)
		}

		if len(tok) != 64 {
			t.Errorf("iteration %d: expected 64-char token, got %d chars: %q", i, len(tok), tok)
		}

		if _, err := hex.DecodeString(tok); err != nil {
			t.Errorf("iteration %d: token is not valid hex: %q", i, tok)
		}
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	inputs := []string{
		"",
		"abc",
		"the quick brown fox",
		"a very long token string with 64 hex characters 0123456789abcdef",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			h1 := HashToken(input)
			h2 := HashToken(input)
			if h1 != h2 {
				t.Errorf("HashToken not deterministic for input %q: %q != %q", input, h1, h2)
			}
		})
	}
}

func TestHashTokenDifferentInputs(t *testing.T) {
	tests := []struct {
		a, b string
	}{
		{"foo", "bar"},
		{"", "a"},
		{"abc", "ABC"},
		{"token1", "token2"},
	}

	for _, tc := range tests {
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			ha := HashToken(tc.a)
			hb := HashToken(tc.b)
			if ha == hb {
				t.Errorf("HashToken(%q) == HashToken(%q); expected different hashes", tc.a, tc.b)
			}
		})
	}
}

func TestHashTokenOutputFormat(t *testing.T) {
	h := HashToken("test input")
	// SHA-256 produces 32 bytes → 64 hex chars
	if len(h) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		t.Errorf("hash is not valid hex: %q", h)
	}
}

// ── HashPassword / VerifyPassword ────────────────────────────────────────────

func TestHashPasswordVerifyRoundTrip(t *testing.T) {
	passwords := []string{
		"correct-horse-battery-staple",
		"P@ssw0rd!",
		"short",
		"a very long passphrase with spaces and special chars: !@#$%^&*()",
		"unicode: こんにちは",
	}

	for _, pw := range passwords {
		t.Run(pw, func(t *testing.T) {
			hash, err := HashPassword(pw)
			if err != nil {
				t.Fatalf("HashPassword: %v", err)
			}
			if hash == "" {
				t.Fatal("HashPassword returned empty string")
			}

			if err := VerifyPassword(hash, pw); err != nil {
				t.Errorf("VerifyPassword failed for correct password: %v", err)
			}
		})
	}
}

func TestVerifyPasswordWrongPassword(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	wrongPasswords := []string{
		"wrong-password",
		"",
		"correct-passwor",  // one char short
		"correct-passwordX", // one char extra
		"CORRECT-PASSWORD",  // different case
	}

	for _, wrong := range wrongPasswords {
		t.Run(wrong, func(t *testing.T) {
			if err := VerifyPassword(hash, wrong); err == nil {
				t.Errorf("VerifyPassword should have failed for wrong password %q", wrong)
			}
		})
	}
}

func TestHashPasswordUniqueSalts(t *testing.T) {
	password := "same-password-every-time"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword (1): %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword (2): %v", err)
	}

	if hash1 == hash2 {
		t.Error("expected different hashes (different salts) for the same password, got identical strings")
	}

	// Both hashes must still verify correctly against the original password.
	if err := VerifyPassword(hash1, password); err != nil {
		t.Errorf("hash1 failed verification: %v", err)
	}
	if err := VerifyPassword(hash2, password); err != nil {
		t.Errorf("hash2 failed verification: %v", err)
	}
}

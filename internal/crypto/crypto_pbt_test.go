package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// pbtParameters returns gopter test parameters with a fixed seed and minimum
// 200 successful tests per property, as required by the spec.
func pbtParameters() *gopter.TestParameters {
	params := gopter.DefaultTestParametersWithSeed(1234)
	params.MinSuccessfulTests = 200
	return params
}

// gen32ByteKey generates a random 32-byte slice suitable for AES-256.
var gen32ByteKey = gen.SliceOfN(32, gen.UInt8()).Map(func(bs []byte) []byte {
	return bs
})

// genPlaintext generates a random []byte of 0–1024 bytes.
var genPlaintext = gen.SliceOf(gen.UInt8()).SuchThat(func(v interface{}) bool {
	bs, ok := v.([]byte)
	if !ok {
		return false
	}
	return len(bs) <= 1024
}).Map(func(bs []byte) []byte {
	return bs
})

// genNonEmptyPlaintext generates a random non-empty []byte of 1–1024 bytes.
var genNonEmptyPlaintext = gen.SliceOf(gen.UInt8()).SuchThat(func(v interface{}) bool {
	bs, ok := v.([]byte)
	if !ok {
		return false
	}
	return len(bs) >= 1 && len(bs) <= 1024
}).Map(func(bs []byte) []byte {
	return bs
})

// TestProperty1_EncryptDecryptRoundTrip verifies that Decrypt(Encrypt(plaintext, key)) == plaintext
// for all plaintexts (0–1024 bytes) and random 32-byte keys.
//
// Validates: Requirements 2.2, 2.6
func TestProperty1_EncryptDecryptRoundTrip(t *testing.T) {
	properties := gopter.NewProperties(pbtParameters())

	properties.Property("Decrypt(Encrypt(plaintext, key)) == plaintext", prop.ForAll(
		func(plaintext []byte, key []byte) bool {
			ct, nonce, err := Encrypt(plaintext, key)
			if err != nil {
				return false
			}
			got, err := Decrypt(ct, nonce, key)
			if err != nil {
				return false
			}
			return bytes.Equal(got, plaintext)
		},
		genPlaintext,
		gen32ByteKey,
	))

	properties.TestingRun(t)
}

// TestProperty2_NonceUniqueness verifies that two consecutive Encrypt calls
// on the same plaintext and key produce different nonces.
//
// Validates: Requirements 2.3
func TestProperty2_NonceUniqueness(t *testing.T) {
	properties := gopter.NewProperties(pbtParameters())

	properties.Property("two consecutive Encrypt calls produce distinct nonces", prop.ForAll(
		func(plaintext []byte, key []byte) bool {
			_, nonce1, err := Encrypt(plaintext, key)
			if err != nil {
				return false
			}
			_, nonce2, err := Encrypt(plaintext, key)
			if err != nil {
				return false
			}
			return !bytes.Equal(nonce1, nonce2)
		},
		genPlaintext,
		gen32ByteKey,
	))

	properties.TestingRun(t)
}

// TestProperty3_CiphertextDiffersFromPlaintext verifies that for any non-empty
// plaintext the resulting ciphertext is different from the plaintext bytes.
//
// Validates: Requirements 2.2, 2.7
func TestProperty3_CiphertextDiffersFromPlaintext(t *testing.T) {
	properties := gopter.NewProperties(pbtParameters())

	properties.Property("ciphertext != plaintext for non-empty input", prop.ForAll(
		func(plaintext []byte, key []byte) bool {
			ct, _, err := Encrypt(plaintext, key)
			if err != nil {
				return false
			}
			return !bytes.Equal(ct, plaintext)
		},
		genNonEmptyPlaintext,
		gen32ByteKey,
	))

	properties.TestingRun(t)
}

// TestProperty4_DecryptFailsOnModifiedCiphertext verifies that flipping any
// single byte in a valid ciphertext causes Decrypt to return an error.
//
// Validates: Requirements 2.2, 2.6
func TestProperty4_DecryptFailsOnModifiedCiphertext(t *testing.T) {
	properties := gopter.NewProperties(pbtParameters())

	properties.Property("modifying one ciphertext byte causes decryption error", prop.ForAll(
		func(plaintext []byte, key []byte) bool {
			ct, nonce, err := Encrypt(plaintext, key)
			if err != nil {
				return false
			}
			if len(ct) == 0 {
				// Nothing to flip — skip (empty plaintext can yield short/empty ciphertext)
				return true
			}

			// Flip the first byte of the ciphertext.
			tampered := make([]byte, len(ct))
			copy(tampered, ct)
			tampered[0] ^= 0xFF

			_, err = Decrypt(tampered, nonce, key)
			return err != nil
		},
		genPlaintext,
		gen32ByteKey,
	))

	properties.TestingRun(t)
}

// TestProperty5_GenerateTokenAlways64HexChars verifies that every call to
// GenerateToken returns exactly 64 valid hexadecimal characters.
//
// Validates: Requirements 4.1
func TestProperty5_GenerateTokenAlways64HexChars(t *testing.T) {
	properties := gopter.NewProperties(pbtParameters())

	// We use a unit generator that simply returns a constant so gopter can
	// iterate 200 times (the function itself is the subject under test).
	properties.Property("GenerateToken returns 64 hex chars on every call", prop.ForAll(
		func(_ int) bool {
			tok, err := GenerateToken()
			if err != nil {
				return false
			}
			if len(tok) != 64 {
				return false
			}
			_, decErr := hex.DecodeString(tok)
			return decErr == nil
		},
		gen.IntRange(0, 0), // dummy generator — 200 iterations of the same check
	))

	properties.TestingRun(t)
}

// TestProperty6_HashTokenDeterministic verifies that calling HashToken twice
// with the same input always produces the same output.
//
// Validates: Requirements 4.2
func TestProperty6_HashTokenDeterministic(t *testing.T) {
	properties := gopter.NewProperties(pbtParameters())

	properties.Property("HashToken(s) == HashToken(s) for all inputs", prop.ForAll(
		func(input string) bool {
			h1 := HashToken(input)
			h2 := HashToken(input)
			return h1 == h2
		},
		gen.AnyString(),
	))

	properties.TestingRun(t)
}

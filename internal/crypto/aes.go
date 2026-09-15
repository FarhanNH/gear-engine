package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext with key using AES-256-GCM.
// A fresh nonce is generated via crypto/rand for every call.
// Returns ciphertext (includes GCM auth tag) and the nonce used.
// Key must be exactly 32 bytes; returns an error otherwise.
func Encrypt(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext with nonce and key using AES-256-GCM.
// Returns an error if the key is not 32 bytes or if authentication fails
// (tampered ciphertext or wrong key/nonce).
// Key must be exactly 32 bytes; returns an error otherwise.
func Decrypt(ciphertext, nonce, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication error or wrong key): %w", err)
	}

	return plaintext, nil
}

// GenerateKey generates a 32-byte AES-256 key using crypto/rand.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return key, nil
}

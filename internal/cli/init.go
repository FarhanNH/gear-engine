package cli

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	gearCrypto "github.com/gear/engine/internal/crypto"
	"github.com/gear/engine/internal/database"
	"golang.org/x/term"
)

const (
	defaultDBPath        = "./gear.db"
	defaultMasterKeyPath = "./master.key"
	adminUsername        = "admin"
)

// RunInit executes the "gear init" command.
// It initializes the system by generating a Master Key and creating the admin account.
// The operation is atomic:
//  1. Generate Master Key → write to master.key.tmp (chmod 600)
//  2. Hash password, INSERT admin into DB inside a transaction
//  3. If INSERT succeeds → rename master.key.tmp to master.key
//  4. If INSERT fails → delete master.key.tmp, rollback transaction
func RunInit(args []string) error {
	fs := flag.NewFlagSet("gear init", flag.ContinueOnError)
	dbPath := fs.String("db", defaultDBPath, "path to SQLite database file")
	masterKeyPath := fs.String("master-key", defaultMasterKeyPath, "path to master key file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	tmpKeyPath := *masterKeyPath + ".tmp"

	// 1. Check if system is already initialized.
	if err := checkNotInitialized(*dbPath); err != nil {
		return err
	}

	// 2. Open (or create) the database.
	db, err := database.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// 3. Generate Master Key and write to tmp file.
	masterKey, err := gearCrypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	if err := writeMasterKeyTmp(tmpKeyPath, masterKey); err != nil {
		return err
	}
	// Ensure tmp file is cleaned up on any error path after this point.
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			os.Remove(tmpKeyPath)
		}
	}()

	// 4. Get admin password from terminal or generate one.
	password, generated, err := readOrGeneratePassword()
	if err != nil {
		return fmt.Errorf("failed to get admin password: %w", err)
	}

	// 5. Hash the password.
	passwordHash, err := gearCrypto.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// 6. INSERT admin in a DB transaction.
	if err := insertAdmin(db, adminUsername, passwordHash); err != nil {
		return fmt.Errorf("failed to create admin account: %w", err)
	}

	// 7. INSERT succeeded → atomically rename tmp to final master key.
	if err := os.Rename(tmpKeyPath, *masterKeyPath); err != nil {
		// Rename failed — we need to roll back the admin row.
		// The defer will remove tmpKeyPath.
		// We attempt a best-effort delete of the just-inserted admin row.
		_, _ = db.Exec("DELETE FROM admins WHERE username = ?", adminUsername)
		return fmt.Errorf("failed to finalize master key file: %w", err)
	}

	// Rename succeeded — do NOT delete the tmp file (it no longer exists anyway).
	cleanupTmp = false

	// 8. Print success message.
	printSuccess(*masterKeyPath, password, generated)

	return nil
}

// checkNotInitialized returns an error if the system has already been initialized
// (i.e., the DB file exists AND the admins table already has at least one row).
func checkNotInitialized(dbPath string) error {
	// If the DB file doesn't exist yet, we're definitely not initialized.
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	// DB file exists — open it and check for existing admin rows.
	db, err := database.Open(dbPath)
	if err != nil {
		// Can't open: treat as not initialized so Open() later will surface the real error.
		return nil
	}
	defer db.Close()

	var count int
	row := db.QueryRow("SELECT COUNT(*) FROM admins")
	if err := row.Scan(&count); err != nil {
		// Table may not exist yet; treat as not initialized.
		return nil
	}

	if count > 0 {
		return fmt.Errorf("system already initialized: admin account exists in %s", dbPath)
	}

	return nil
}

// writeMasterKeyTmp writes key bytes to path with chmod 600.
func writeMasterKeyTmp(path string, key []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create master key temp file: %w", err)
	}

	_, writeErr := f.Write(key)
	closeErr := f.Close()

	if writeErr != nil {
		os.Remove(path)
		return fmt.Errorf("failed to write master key: %w", writeErr)
	}
	if closeErr != nil {
		os.Remove(path)
		return fmt.Errorf("failed to close master key temp file: %w", closeErr)
	}

	return nil
}

// readOrGeneratePassword reads a password from the terminal (without echo).
// If the terminal is unavailable or the user enters an empty password,
// a random 16-byte hex password is generated.
// Returns (password, wasGenerated, error).
func readOrGeneratePassword() (string, bool, error) {
	fmt.Print("Enter admin password (leave empty to auto-generate): ")

	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Move to next line after the hidden input.

	if err != nil || strings.TrimSpace(string(password)) == "" {
		// Terminal unavailable or empty input — generate random password.
		generated, genErr := generateRandomPassword()
		if genErr != nil {
			return "", false, genErr
		}
		return generated, true, nil
	}

	return string(password), false, nil
}

// generateRandomPassword generates a random 16-byte password encoded as hex (32 chars).
func generateRandomPassword() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// insertAdmin inserts the admin user inside a DB transaction.
// Rolls back and returns an error if the INSERT fails.
func insertAdmin(db *sql.DB, username, passwordHash string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	now := time.Now().Unix()
	_, err = tx.Exec(
		"INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
		username, passwordHash, now,
	)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("insert admin: %w", err)
	}

	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// printSuccess prints the post-init instructions to stdout.
func printSuccess(masterKeyPath, password string, generated bool) {
	if generated {
		fmt.Printf("\n⚠  Auto-generated admin password (save this now, it will NOT be shown again):\n")
		fmt.Printf("   %s\n", password)
	}

	fmt.Printf(`
✓ Gear initialized successfully!

Master Key saved to: %s

Next steps:
  1. Start the server: gear serve
  2. Save your admin password in a secure location!

⚠  WARNING: Loss of master.key means ALL secrets are unrecoverable.
`, masterKeyPath)
}

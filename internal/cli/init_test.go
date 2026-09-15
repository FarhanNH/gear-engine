package cli_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gear/engine/internal/cli"
	"github.com/gear/engine/internal/database"
)

// TestRunInit_Success verifies the happy-path atomicity guarantee:
// both master.key and the admin row are created together.
//
// Validates: Requirements 1.4, 1.5
func TestRunInit_Success(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "gear.db")
	masterKeyPath := filepath.Join(dir, "master.key")
	tmpKeyPath := masterKeyPath + ".tmp"

	err := cli.RunInit([]string{
		"--db", dbPath,
		"--master-key", masterKeyPath,
	})
	if err != nil {
		t.Fatalf("RunInit returned unexpected error: %v", err)
	}

	// master.key must exist with permission 0600
	info, err := os.Stat(masterKeyPath)
	if err != nil {
		t.Fatalf("master.key not found after successful init: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("master.key has wrong permission: got %04o, want 0600", perm)
	}

	// master.key.tmp must NOT exist (was renamed to master.key)
	if _, err := os.Stat(tmpKeyPath); !os.IsNotExist(err) {
		t.Errorf("master.key.tmp still exists after successful init; want it removed")
	}

	// DB must have exactly 1 admin row
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open DB for verification: %v", err)
	}
	defer db.Close()

	count := adminCount(t, db)
	if count != 1 {
		t.Errorf("admins table has %d rows, want exactly 1", count)
	}
}

// TestRunInit_AlreadyInitialized verifies idempotency:
// a second `gear init` on an already-initialised system must fail
// without duplicating the admin row.
//
// Validates: Requirements 1.4, 1.5
func TestRunInit_AlreadyInitialized(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "gear.db")
	masterKeyPath := filepath.Join(dir, "master.key")

	args := []string{"--db", dbPath, "--master-key", masterKeyPath}

	// First run must succeed.
	if err := cli.RunInit(args); err != nil {
		t.Fatalf("first RunInit failed unexpectedly: %v", err)
	}

	// Second run must return an "already initialized" error.
	err := cli.RunInit(args)
	if err == nil {
		t.Fatal("second RunInit succeeded; want an error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "already initialized") {
		t.Errorf("error message %q does not contain 'already initialized'", err.Error())
	}

	// Admin count must still be exactly 1 — not duplicated.
	db, err2 := database.Open(dbPath)
	if err2 != nil {
		t.Fatalf("failed to open DB for verification: %v", err2)
	}
	defer db.Close()

	count := adminCount(t, db)
	if count != 1 {
		t.Errorf("admins table has %d rows after second run, want still 1", count)
	}
}

// TestRunInit_AtomicCleanup verifies the failure atomicity guarantee:
// when RunInit cannot open/create the database (invalid directory path),
// no master.key.tmp should remain on disk.
//
// Validates: Requirements 1.5
func TestRunInit_AtomicCleanup(t *testing.T) {
	dir := t.TempDir()
	// Point the DB to a path whose parent directory does not exist so
	// database.Open will fail early, before any key file can be finalised.
	dbPath := filepath.Join(dir, "nonexistent_subdir", "gear.db")
	masterKeyPath := filepath.Join(dir, "master.key")
	tmpKeyPath := masterKeyPath + ".tmp"

	err := cli.RunInit([]string{
		"--db", dbPath,
		"--master-key", masterKeyPath,
	})
	if err == nil {
		t.Fatal("RunInit with invalid DB path succeeded; want an error")
	}

	// master.key.tmp must NOT exist — the defer cleanup in RunInit should have removed it.
	if _, statErr := os.Stat(tmpKeyPath); !os.IsNotExist(statErr) {
		t.Errorf("master.key.tmp still exists after failed init; want it cleaned up")
	}

	// master.key must NOT exist — it was never created.
	if _, statErr := os.Stat(masterKeyPath); !os.IsNotExist(statErr) {
		t.Errorf("master.key exists after failed init; want it absent")
	}
}

// adminCount is a helper that returns the number of rows in the admins table.
func adminCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count); err != nil {
		t.Fatalf("failed to count admins: %v", err)
	}
	return count
}

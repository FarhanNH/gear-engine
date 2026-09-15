package database

import (
	"database/sql"
	_ "embed"
	"fmt"

	_ "modernc.org/sqlite"
)

//go:embed migrations/001_init.sql
var migrationSQL string

// Open membuka database SQLite di path yang diberikan, menjalankan pragma
// dan migrasi awal, lalu mengembalikan *sql.DB yang siap dipakai.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("database: open %q: %w", path, err)
	}

	// Verifikasi koneksi
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: ping %q: %w", path, err)
	}

	// Terapkan pragma performa dan keamanan
	if _, err = db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: set journal_mode: %w", err)
	}
	if _, err = db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: set foreign_keys: %w", err)
	}

	// Jalankan migrasi DDL yang sudah di-embed
	if _, err = db.Exec(migrationSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: run migration: %w", err)
	}

	return db, nil
}

// Close menutup koneksi database dengan graceful.
func Close(db *sql.DB) error {
	if db == nil {
		return nil
	}
	if err := db.Close(); err != nil {
		return fmt.Errorf("database: close: %w", err)
	}
	return nil
}

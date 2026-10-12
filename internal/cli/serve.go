package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/gear/engine/internal/config"
	"github.com/gear/engine/internal/server"
)

// RunServe executes the "gear serve" command.
// It starts the HTTPS API server with HTTP→HTTPS redirect.
//
// Configuration is loaded primarily from environment variables (see config.Load).
// The optional --db and --master-key flags, when provided, override the
// corresponding env vars (GEAR_DB_PATH, GEAR_MASTER_KEY_PATH) before Load is called.
// TLS cert/key must be supplied via GEAR_TLS_CERT and GEAR_TLS_KEY; config.Load
// returns a clear error if either is absent.
func RunServe(args []string) error {
	fs := flag.NewFlagSet("gear serve", flag.ContinueOnError)
	db := fs.String("db", "", "path to SQLite database file (overrides GEAR_DB_PATH)")
	masterKey := fs.String("master-key", "", "path to master key file (overrides GEAR_MASTER_KEY_PATH)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Allow flag values to override env vars before config.Load reads them.
	if *db != "" {
		os.Setenv("GEAR_DB_PATH", *db)
	}
	if *masterKey != "" {
		os.Setenv("GEAR_MASTER_KEY_PATH", *masterKey)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	s, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	if err := s.Run(); err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}

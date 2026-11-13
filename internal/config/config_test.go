package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gear/engine/internal/config"
)

func setBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GEAR_TLS_CERT", "/tmp/cert.pem")
	t.Setenv("GEAR_TLS_KEY", "/tmp/key.pem")
	t.Setenv("GEAR_TURNSTILE_ENABLED", "")
	t.Setenv("GEAR_TURNSTILE_SECRET_FILE", "")
	t.Setenv("GEAR_TURNSTILE_TIMEOUT", "")
}

func writeSecretFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "turnstile.secret")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	return p
}

func TestLoad_TurnstileDefaultsAndSecretFile(t *testing.T) {
	setBaseEnv(t)
	secretPath := writeSecretFile(t, "test-secret-value\n")
	t.Setenv("GEAR_TURNSTILE_SECRET_FILE", secretPath)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("expected Load() to succeed, got %v", err)
	}
	if !cfg.TurnstileEnabled {
		t.Error("expected TurnstileEnabled to default to true")
	}
	if cfg.TurnstileTimeout != 5*time.Second {
		t.Errorf("expected TurnstileTimeout default 5s, got %v", cfg.TurnstileTimeout)
	}
	if cfg.TurnstileSecret != "test-secret-value" {
		t.Errorf("expected trimmed TurnstileSecret, got %q", cfg.TurnstileSecret)
	}
}

func TestLoad_TurnstileEnabledMissingSecretFileFails(t *testing.T) {
	setBaseEnv(t)

	if _, err := config.Load(); err == nil {
		t.Fatal("expected error when GEAR_TURNSTILE_SECRET_FILE is unset while enabled")
	}

	t.Setenv("GEAR_TURNSTILE_SECRET_FILE", filepath.Join(t.TempDir(), "does-not-exist")) 
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error when GEAR_TURNSTILE_SECRET_FILE does not exist")
	}
}

func TestLoad_TurnstileEnabledEmptySecretFileFails(t *testing.T) {
	setBaseEnv(t)
	secretPath := writeSecretFile(t, "   \n\t  ")
	t.Setenv("GEAR_TURNSTILE_SECRET_FILE", secretPath)

	if _, err := config.Load(); err == nil {
		t.Fatal("expected error when GEAR_TURNSTILE_SECRET_FILE is empty")
	}
}

func TestLoad_TurnstileDisabledSkipsSecretFile(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("GEAR_TURNSTILE_ENABLED", "false")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("expected Load() to succeed when Turnstile disabled, got %v", err)
	}
	if cfg.TurnstileEnabled {
		t.Error("expected TurnstileEnabled to be false")
	}
}

func TestLoad_TurnstileCustomTimeoutAndValidation(t *testing.T) {
	setBaseEnv(t)
	secretPath := writeSecretFile(t, "test-secret")
	t.Setenv("GEAR_TURNSTILE_SECRET_FILE", secretPath)
	t.Setenv("GEAR_TURNSTILE_TIMEOUT", "8s")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("expected Load() to succeed with custom timeout, got %v", err)
	}
	if cfg.TurnstileTimeout != 8*time.Second {
		t.Errorf("expected TurnstileTimeout 8s, got %v", cfg.TurnstileTimeout)
	}

	t.Setenv("GEAR_TURNSTILE_TIMEOUT", "not-a-duration")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for invalid GEAR_TURNSTILE_TIMEOUT")
	}

	t.Setenv("GEAR_TURNSTILE_TIMEOUT", "0s")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for non-positive GEAR_TURNSTILE_TIMEOUT")
	}
}

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/gear/engine/internal/config"
)

func TestLoginFailConfigRejectsInvalidValues(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"GEAR_LOGIN_FAIL_MAX", "bad"}, {"GEAR_LOGIN_FAIL_MAX", "0"},
		{"GEAR_LOGIN_FAIL_WINDOW", "bad"}, {"GEAR_LOGIN_FAIL_WINDOW", "0s"},
		{"GEAR_LOGIN_FAIL_WINDOW", "1ns"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			setBaseEnv(t)
			t.Setenv("GEAR_TURNSTILE_ENABLED", "false")
			t.Setenv(tc.key, tc.value)
			_, err := config.Load()
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("expected error naming %s, got %v", tc.key, err)
			}
		})
	}
}

func TestLoginFailConfigDefaults(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("GEAR_TURNSTILE_ENABLED", "false")
	t.Setenv("GEAR_LOGIN_FAIL_MAX", "")
	t.Setenv("GEAR_LOGIN_FAIL_WINDOW", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoginFailMax != 5 || cfg.LoginFailWindow != 15*time.Minute {
		t.Fatalf("unexpected defaults: %d %s", cfg.LoginFailMax, cfg.LoginFailWindow)
	}
}

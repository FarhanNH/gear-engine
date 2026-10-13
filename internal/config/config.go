package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration for gear-engine.
// Values are loaded from environment variables via Load().
type Config struct {
	// DBPath is the path to the SQLite database file.
	// Env: GEAR_DB_PATH, default: ./gear.db
	DBPath string

	// MasterKeyPath is the path to the master encryption key file.
	// Env: GEAR_MASTER_KEY_PATH, default: ./master.key
	MasterKeyPath string

	// TLSCert is the path to the TLS certificate file (required).
	// Env: GEAR_TLS_CERT
	TLSCert string

	// TLSKey is the path to the TLS private key file (required).
	// Env: GEAR_TLS_KEY
	TLSKey string

	// ListenAddr is the HTTPS listener address.
	// Env: GEAR_LISTEN_ADDR, default: :8443
	ListenAddr string

	// HTTPAddr is the plain HTTP listener address (redirect-only).
	// Env: GEAR_HTTP_ADDR, default: :8080
	HTTPAddr string

	// CORSOrigins is the list of allowed CORS origins.
	// Env: GEAR_CORS_ORIGIN (comma-separated), default: empty (no CORS)
	CORSOrigins []string

	// RateLimitMax is the maximum number of login attempts per window per IP.
	// Env: GEAR_RATE_LIMIT_MAX, default: 10
	RateLimitMax int

	// RateLimitWindow is the duration of the rate-limit sliding window.
	// Env: GEAR_RATE_LIMIT_WINDOW, default: 5m
	RateLimitWindow time.Duration

	// RedisAddr is the address of the shared Redis instance used for rate limiting.
	// Env: GEAR_REDIS_ADDR, default: localhost:6379
	RedisAddr string

	// RedisPassword is the optional Redis authentication password.
	// Env: GEAR_REDIS_PASSWORD
	RedisPassword string

	// RedisDB is the Redis database number used for rate limiting.
	// Env: GEAR_REDIS_DB, default: 0
	RedisDB int

	// SessionTTL is the default TTL for admin session tokens.
	// Env: GEAR_SESSION_TTL, default: 12h
	SessionTTL time.Duration
}

// Load reads configuration from environment variables and applies defaults.
// It returns an error if required variables (GEAR_TLS_CERT, GEAR_TLS_KEY) are missing.
func Load() (*Config, error) {
	cfg := &Config{
		DBPath:        getEnv("GEAR_DB_PATH", "./gear.db"),
		MasterKeyPath: getEnv("GEAR_MASTER_KEY_PATH", "./master.key"),
		TLSCert:       getEnv("GEAR_TLS_CERT", ""),
		TLSKey:        getEnv("GEAR_TLS_KEY", ""),
		ListenAddr:    getEnv("GEAR_LISTEN_ADDR", ":8443"),
		HTTPAddr:      getEnv("GEAR_HTTP_ADDR", ":8080"),
		RedisAddr:     getEnv("GEAR_REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("GEAR_REDIS_PASSWORD", ""),
	}

	if raw := getEnv("GEAR_REDIS_DB", ""); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			return nil, errors.New("invalid GEAR_REDIS_DB: must be a non-negative integer")
		}
		cfg.RedisDB = v
	}

	// GEAR_CORS_ORIGIN — optional, comma-separated list
	if raw := getEnv("GEAR_CORS_ORIGIN", ""); raw != "" {
		parts := strings.Split(raw, ",")
		origins := make([]string, 0, len(parts))
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				origins = append(origins, trimmed)
			}
		}
		cfg.CORSOrigins = origins
	}

	// GEAR_RATE_LIMIT_MAX — optional int, default 10
	if raw := getEnv("GEAR_RATE_LIMIT_MAX", ""); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return nil, errors.New("invalid GEAR_RATE_LIMIT_MAX: must be an integer")
		}
		cfg.RateLimitMax = v
	} else {
		cfg.RateLimitMax = 10
	}

	// GEAR_RATE_LIMIT_WINDOW — optional duration, default 5m
	if raw := getEnv("GEAR_RATE_LIMIT_WINDOW", ""); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, errors.New("invalid GEAR_RATE_LIMIT_WINDOW: must be a valid duration (e.g. 5m)")
		}
		cfg.RateLimitWindow = d
	} else {
		cfg.RateLimitWindow = 5 * time.Minute
	}
	if cfg.RateLimitMax < 1 {
		return nil, errors.New("GEAR_RATE_LIMIT_MAX must be greater than zero")
	}
	if cfg.RateLimitWindow < time.Microsecond {
		return nil, errors.New("GEAR_RATE_LIMIT_WINDOW must be at least 1us")
	}

	// GEAR_SESSION_TTL — optional duration, default 12h
	if raw := getEnv("GEAR_SESSION_TTL", ""); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, errors.New("invalid GEAR_SESSION_TTL: must be a valid duration (e.g. 12h)")
		}
		cfg.SessionTTL = d
	} else {
		cfg.SessionTTL = 12 * time.Hour
	}

	// Validation: TLS cert and key are required.
	if cfg.TLSCert == "" {
		return nil, errors.New("GEAR_TLS_CERT is required but not set")
	}
	if cfg.TLSKey == "" {
		return nil, errors.New("GEAR_TLS_KEY is required but not set")
	}

	return cfg, nil
}

// getEnv returns the value of the named environment variable,
// or the provided fallback if the variable is not set or empty.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Package server menyediakan setup HTTP server, registrasi route, dan graceful shutdown
// untuk gear-engine.
//
// Validates: Requirements 9.1, 9.2, 9.3
package server

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/gear/engine/internal/config"
	"github.com/gear/engine/internal/database"
	"github.com/gear/engine/internal/handler"
	"github.com/gear/engine/internal/middleware"
	"github.com/gear/engine/internal/service"
	"github.com/gear/engine/internal/validate"
)

// Server menyimpan semua dependensi runtime untuk gear-engine HTTP server.
type Server struct {
	cfg         *config.Config
	db          *sql.DB
	redisClient *redis.Client

	masterKey []byte

	// Services
	secretSvc service.SecretService
	tokenSvc  service.TokenService
	policySvc *service.PolicyServiceImpl
	auditSvc  service.AuditService

	// Handlers
	authHandler   *handler.AuthHandler
	secretHandler *handler.SecretHandler
	tokenHandler  *handler.TokenHandler
	policyHandler *handler.PolicyHandler
	auditHandler  *handler.AuditHandler

	// chi router (built during New)
	router chi.Router
}

// New membangun Server baru dengan urutan:
//  1. Validasi TLS cert/key via middleware.ValidateTLSCertFiles
//  2. Verifikasi permission master.key adalah 0600 (fatal jika tidak)
//  3. Buka database via database.Open
//  4. Baca master key dari file
//  5. Inisialisasi semua service dan handler
//  6. Bangun chi router dengan middleware stack dan route
//
// Validates: Requirements 9.1, 9.2, 9.3
func New(cfg *config.Config) (*Server, error) {
	// 1. Validasi TLS certificate dan key files.
	if err := middleware.ValidateTLSCertFiles(cfg.TLSCert, cfg.TLSKey); err != nil {
		return nil, fmt.Errorf("server: TLS cert/key validation failed: %w", err)
	}

	// 2. Verifikasi permission master.key harus tepat 0600.
	checkMasterKeyPermission(cfg.MasterKeyPath)

	// 3. Buka SQLite database.
	db, err := database.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("server: open database: %w", err)
	}

	// 4. Baca master key dari file.
	masterKey, err := os.ReadFile(cfg.MasterKeyPath)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("server: read master key: %w", err)
	}

	// 5. Connect to Redis and verify it is ready before serving traffic.
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	redisCtx, redisCancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = redisClient.Ping(redisCtx).Err()
	redisCancel()
	if err != nil {
		redisClient.Close()
		db.Close()
		return nil, fmt.Errorf("server: connect to Redis at %s: %w", cfg.RedisAddr, err)
	}

	// 6. Inisialisasi services.
	secretSvc := service.NewSecretService(db, masterKey)
	tokenSvc := service.NewTokenService(db)
	policySvc := service.NewPolicyService(db)
	auditSvc := service.NewAuditService(db)

	// 7. Inisialisasi handlers.
	authHandler := handler.NewAuthHandler(db, tokenSvc, cfg.SessionTTL)
	secretHandler := handler.NewSecretHandler(secretSvc)
	tokenHandler := handler.NewTokenHandler(tokenSvc)
	policyHandler := handler.NewPolicyHandler(policySvc)
	auditHandler := handler.NewAuditHandler(auditSvc)

	s := &Server{
		cfg:           cfg,
		db:            db,
		redisClient:   redisClient,
		masterKey:     masterKey,
		secretSvc:     secretSvc,
		tokenSvc:      tokenSvc,
		policySvc:     policySvc,
		auditSvc:      auditSvc,
		authHandler:   authHandler,
		secretHandler: secretHandler,
		tokenHandler:  tokenHandler,
		policyHandler: policyHandler,
		auditHandler:  auditHandler,
	}

	// 8. Bangun chi router.
	s.router = s.buildRouter()

	return s, nil
}

// checkMasterKeyPermission memeriksa file permission master.key.
// Jika permission bukan tepat 0600 → log.Fatal + os.Exit(1).
//
// Validates: Requirements 9.3
func checkMasterKeyPermission(path string) {
	info, err := os.Stat(path)
	if err != nil {
		log.Fatalf("FATAL: cannot stat master key file %q: %v", path, err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		log.Fatalf(
			"FATAL: master key file %q has insecure permissions %04o (must be 0600). "+
				"Run: chmod 600 %s",
			path, perm, path,
		)
	}
}

// buildRouter membangun chi.Router dengan middleware stack yang benar dan semua route terdaftar.
//
// Urutan middleware (dari luar ke dalam):
//  1. chimiddleware.RequestID
//  2. chimiddleware.RealIP
//  3. middleware.TLSRedirectMiddleware
//  4. middleware.CORSMiddleware
//  5. chimiddleware.Logger
//  6. chimiddleware.Recoverer
//
// Sub-tree /v1/* dilindungi oleh:
//   - RateLimitMiddleware hanya pada /v1/auth/login
//   - PathValidationMiddleware hanya pada /v1/secret/* dan /v1/list/*
//   - AuthMiddleware pada semua /v1/* kecuali /v1/auth/login
//   - PolicyMiddleware pada /v1/secret/* dan /v1/list/*
//   - AuditMiddleware pada semua /v1/*
func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()

	// ── Global middleware stack ────────────────────────────────────────────────
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.TLSRedirectMiddleware())
	r.Use(middleware.CORSMiddleware(s.cfg.CORSOrigins))
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)

	// ── /v1 routes ─────────────────────────────────────────────────────────────
	r.Route("/v1", func(r chi.Router) {
		// AuditMiddleware: semua /v1/* request
		r.Use(middleware.AuditMiddleware(s.auditSvc))

		// ── /v1/auth ────────────────────────────────────────────────────────────
		r.Route("/auth", func(r chi.Router) {
			// Rate limit: hanya POST /v1/auth/login
			r.With(
				middleware.RateLimitMiddleware(middleware.NewRedisRateLimiter(
					s.redisClient,
					s.cfg.RateLimitMax,
					s.cfg.RateLimitWindow,
				)),
			).Post("/login", s.authHandler.Login)

			// Logout butuh autentikasi
			r.With(
				middleware.AuthMiddleware(s.tokenSvc),
			).Post("/logout", s.authHandler.Logout)

			// Change password butuh autentikasi
			r.With(
				middleware.AuthMiddleware(s.tokenSvc),
			).Post("/change-password", s.authHandler.ChangePassword)
		})

		// ── /v1/secret/* ────────────────────────────────────────────────────────
		r.Route("/secret", func(r chi.Router) {
			r.Use(pathValidationMiddleware)
			r.Use(middleware.AuthMiddleware(s.tokenSvc))
			r.Use(s.policyMiddleware)

			r.Put("/*", s.secretHandler.PutSecret)
			r.Get("/*", s.secretHandler.GetSecret)
			r.Delete("/*", s.secretHandler.DeleteSecret)
		})

		// ── /v1/list/* ──────────────────────────────────────────────────────────
		r.Route("/list", func(r chi.Router) {
			r.Use(pathValidationMiddleware)
			r.Use(middleware.AuthMiddleware(s.tokenSvc))
			r.Use(s.policyMiddleware)

			r.Get("/*", s.secretHandler.ListSecrets)
		})

		// ── /v1/token ───────────────────────────────────────────────────────────
		r.Route("/token", func(r chi.Router) {
			r.Use(middleware.AuthMiddleware(s.tokenSvc))

			r.Post("/", s.tokenHandler.CreateToken)
			r.Get("/", s.tokenHandler.ListTokens)
			r.Delete("/{id}", s.tokenHandler.RevokeToken)
		})

		// ── /v1/policy ──────────────────────────────────────────────────────────
		r.Route("/policy", func(r chi.Router) {
			r.Use(middleware.AuthMiddleware(s.tokenSvc))

			r.Post("/", s.policyHandler.CreatePolicy)
			r.Get("/", s.policyHandler.ListPolicies)
			r.Delete("/{id}", s.policyHandler.DeletePolicy)
		})

		// ── /v1/audit ───────────────────────────────────────────────────────────
		r.Route("/audit", func(r chi.Router) {
			r.Use(middleware.AuthMiddleware(s.tokenSvc))

			r.Get("/", s.auditHandler.GetAuditLog)
		})
	})

	return r
}

// pathValidationMiddleware adalah chi middleware yang memvalidasi path secret/list
// menggunakan validate.ValidatePath. Mengembalikan 400 jika path tidak valid.
//
// Validates: Requirements 5.6, 10.1, 10.2, 10.3
func pathValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ambil bagian path setelah prefix /v1/secret/ atau /v1/list/
		rawPath := r.URL.Path
		var secretPath string
		switch {
		case strings.HasPrefix(rawPath, "/v1/secret/"):
			secretPath = strings.TrimPrefix(rawPath, "/v1/secret/")
		case strings.HasPrefix(rawPath, "/v1/list/"):
			secretPath = strings.TrimPrefix(rawPath, "/v1/list/")
		default:
			secretPath = rawPath
		}

		// Cek traversal sebelum memanggil ValidatePath.
		if strings.Contains(rawPath, "..") || strings.Contains(rawPath, "/./") {
			writeJSONError(w, http.StatusBadRequest, "path traversal detected")
			return
		}

		// Validasi path (characters, length, traversal).
		if secretPath != "" {
			if err := validate.ValidatePath(secretPath); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// policyMiddleware adalah middleware inline yang memanggil PolicyService.Evaluate
// untuk memeriksa apakah token yang sedang autentikasi punya izin untuk aksi yang diminta.
// Mengembalikan 403 jika tidak diizinkan.
//
// HTTP method → action mapping:
//   GET    → "read"
//   PUT    → "write"
//   DELETE → "delete"
//
// Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5
func (s *Server) policyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ambil tokenID dari context (di-set oleh AuthMiddleware).
		tokenID := middleware.TokenIDFromContext(r.Context())
		if tokenID == nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		// Bypass policy evaluation untuk admin-session tokens.
		tokenName := middleware.TokenNameFromContext(r.Context())
		if tokenName != nil && strings.HasPrefix(*tokenName, "admin-session") {
			next.ServeHTTP(w, r)
			return
		}

		// Tentukan action berdasarkan HTTP method.
		var action string
		switch r.Method {
		case http.MethodGet:
			action = "read"
		case http.MethodPut:
			action = "write"
		case http.MethodDelete:
			action = "delete"
		default:
			// Method lain (POST tidak ada di secret/list) — izinkan.
			next.ServeHTTP(w, r)
			return
		}

		// Ambil path dari URL untuk evaluasi policy.
		rawPath := r.URL.Path
		var secretPath string
		switch {
		case strings.HasPrefix(rawPath, "/v1/secret/"):
			secretPath = strings.TrimPrefix(rawPath, "/v1/secret/")
		case strings.HasPrefix(rawPath, "/v1/list/"):
			secretPath = strings.TrimPrefix(rawPath, "/v1/list/")
		default:
			secretPath = rawPath
		}

		// Evaluasi policy.
		allowed, err := s.policySvc.Evaluate(r.Context(), *tokenID, secretPath, action)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "policy evaluation failed")
			return
		}
		if !allowed {
			writeJSONError(w, http.StatusForbidden, "forbidden")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// writeJSONError menulis error response JSON dengan status code yang diberikan.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, message)
}

// Run memulai HTTP server (redirect) dan HTTPS server, lalu menunggu sinyal shutdown.
//
// Urutan:
//  1. Jalankan HTTP redirect server pada cfg.HTTPAddr (goroutine)
//  2. Buat *http.Server HTTPS dengan TLS config dari middleware.NewTLSConfig()
//  3. ListenAndServeTLS dengan cfg.TLSCert dan cfg.TLSKey
//  4. Tangkap SIGINT/SIGTERM; panggil server.Shutdown(ctx) dengan timeout 30 detik
//
// Validates: Requirements 9.1, 9.2, 9.3
func (s *Server) Run() error {
	defer func() {
		if err := s.redisClient.Close(); err != nil {
			log.Printf("WARN: Redis close error: %v", err)
		}
		if err := database.Close(s.db); err != nil {
			log.Printf("WARN: database close error: %v", err)
		}
	}()

	// 1. Jalankan HTTP redirect server di goroutine terpisah.
	httpSrv := &http.Server{
		Addr:    s.cfg.HTTPAddr,
		Handler: middleware.HTTPSRedirectHandler(""),
	}
	go func() {
		log.Printf("INFO: HTTP redirect server listening on %s", s.cfg.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("WARN: HTTP redirect server error: %v", err)
		}
	}()

	// 2. Buat HTTPS server dengan hardened TLS config.
	tlsConfig := middleware.NewTLSConfig()
	httpsSrv := &http.Server{
		Addr:      s.cfg.ListenAddr,
		Handler:   s.router,
		TLSConfig: tlsConfig,

		// Timeout yang masuk akal untuk mencegah slowloris.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 3. Channel untuk menangkap sinyal OS.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Jalankan HTTPS server di goroutine terpisah.
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("INFO: HTTPS server listening on %s", s.cfg.ListenAddr)
		if err := httpsSrv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// 4. Tunggu sinyal shutdown atau error dari server.
	select {
	case err := <-serverErr:
		return fmt.Errorf("server: HTTPS server error: %w", err)

	case sig := <-quit:
		log.Printf("INFO: received signal %s, shutting down gracefully...", sig)
	}

	// Graceful shutdown: beri waktu 30 detik untuk menyelesaikan request aktif.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpsSrv.Shutdown(ctx); err != nil {
		log.Printf("WARN: HTTPS server forced shutdown: %v", err)
	}

	// Shutdown HTTP redirect server juga.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("WARN: HTTP redirect server forced shutdown: %v", err)
	}

	log.Printf("INFO: server shutdown complete")
	return nil
}

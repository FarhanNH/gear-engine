package middleware

import (
	"crypto/tls"
	"log"
	"net/http"
)

// NewTLSConfig returns a hardened TLS configuration with:
//   - Minimum TLS version 1.2
//   - Strong cipher suites (ECDHE + AES-256-GCM / ChaCha20-Poly1305)
//   - Preferred curve: X25519, then P-256
//
// Validates: Requirements 9.2, 9.3
func NewTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

// HTTPSRedirectHandler returns an http.Handler that issues a permanent (301)
// redirect from HTTP to HTTPS for every incoming request.
//
// If httpsHost is non-empty it is used as the target host; otherwise r.Host
// is used (preserving the original host header).
//
// Validates: Requirements 9.1
func HTTPSRedirectHandler(httpsHost string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := httpsHost
		if host == "" {
			host = r.Host
		}
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// TLSRedirectMiddleware returns a middleware that redirects plain HTTP requests
// to their HTTPS equivalent with a 301 status code.
//
// The check is performed by inspecting r.TLS: if the field is non-nil the
// request already arrived over TLS and is passed through unchanged.
//
// Validates: Requirements 9.1
func TLSRedirectMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Request already over TLS — pass through.
			if r.TLS != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Plain HTTP — redirect to HTTPS, preserving host and URI.
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
	}
}

// ValidateTLSCertFiles validates that the given certificate and key files can
// be loaded as a valid TLS key pair. It logs the error and returns it so the
// caller (server startup) can decide how to handle failure (e.g. os.Exit(1)).
//
// Validates: Requirements 9.2, 9.3
func ValidateTLSCertFiles(certFile, keyFile string) error {
	_, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("ERROR: failed to load TLS certificate/key pair (%s, %s): %v", certFile, keyFile, err)
		return err
	}
	return nil
}

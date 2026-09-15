package middleware_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gear/engine/internal/middleware"
)

// ─── TLSRedirectMiddleware tests ──────────────────────────────────────────────

// TestTLSRedirectMiddleware_RedirectsHTTP verifies that plain HTTP requests
// (r.TLS == nil) receive a 301 redirect to the HTTPS equivalent.
//
// Validates: Requirements 9.1
func TestTLSRedirectMiddleware_RedirectsHTTP(t *testing.T) {
	mw := middleware.TLSRedirectMiddleware()(okHandler())

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v1/secret/foo", nil)
	req.Host = "example.com"
	// r.TLS is nil by default for httptest.NewRequest — simulates plain HTTP.
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("expected 301 for plain HTTP, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header to be set on redirect")
	}

	expected := "https://example.com/v1/secret/foo"
	if location != expected {
		t.Errorf("expected Location %q, got %q", expected, location)
	}
}

// TestTLSRedirectMiddleware_PassesTLS verifies that TLS requests (r.TLS != nil)
// are passed through to the next handler and receive a 200 response.
//
// Validates: Requirements 9.1
func TestTLSRedirectMiddleware_PassesTLS(t *testing.T) {
	mw := middleware.TLSRedirectMiddleware()(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
	// Simulate an HTTPS request by setting r.TLS to a non-nil ConnectionState.
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for TLS request, got %d", rr.Code)
	}
}

// ─── HTTPSRedirectHandler tests ───────────────────────────────────────────────

// TestHTTPSRedirectHandler_ConstructsCorrectURL verifies that
// HTTPSRedirectHandler("") builds the correct https://host/path Location URL
// from the request's Host header and RequestURI.
//
// Validates: Requirements 9.1
func TestHTTPSRedirectHandler_ConstructsCorrectURL(t *testing.T) {
	h := middleware.HTTPSRedirectHandler("")

	req := httptest.NewRequest(http.MethodGet, "/v1/secret/foo", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("expected 301, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	expected := "https://example.com/v1/secret/foo"
	if location != expected {
		t.Errorf("expected Location %q, got %q", expected, location)
	}
}

// ─── ValidateTLSCertFiles tests ───────────────────────────────────────────────

// TestValidateTLSCertFiles_InvalidFiles verifies that ValidateTLSCertFiles
// returns a non-nil error when the certificate and key files do not exist.
//
// Validates: Requirements 9.2
func TestValidateTLSCertFiles_InvalidFiles(t *testing.T) {
	err := middleware.ValidateTLSCertFiles("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent cert/key files, got nil")
	}
}

// TestValidateTLSCertFiles_ValidSelfSigned verifies that ValidateTLSCertFiles
// returns nil when provided a valid self-signed certificate and key pair.
//
// Validates: Requirements 9.2
func TestValidateTLSCertFiles_ValidSelfSigned(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	err := middleware.ValidateTLSCertFiles(certFile, keyFile)
	if err != nil {
		t.Errorf("expected nil error for valid self-signed cert, got: %v", err)
	}
}

// ─── Helper: self-signed cert generator ──────────────────────────────────────

// generateSelfSignedCert creates a temporary self-signed ECDSA certificate and
// key pair, writes them to temp files, and returns their paths.
// The test will fail immediately if certificate generation fails.
func generateSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	// Generate ECDSA private key on P-256.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Build a minimal self-signed certificate template.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "gear-test",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate.
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Encode certificate to PEM and write to a temp file.
	certTmp, err := os.CreateTemp("", "gear-test-cert-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	if err := pem.Encode(certTmp, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("failed to PEM-encode certificate: %v", err)
	}
	certTmp.Close()

	// Encode private key to PEM and write to a temp file.
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}
	keyTmp, err := os.CreateTemp("", "gear-test-key-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	if err := pem.Encode(keyTmp, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("failed to PEM-encode private key: %v", err)
	}
	keyTmp.Close()

	return certTmp.Name(), keyTmp.Name()
}

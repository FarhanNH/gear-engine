package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultTurnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// TurnstileVerifier memverifikasi token Cloudflare Turnstile.
type TurnstileVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
}

// HTTPSTurnstileVerifier memanggil endpoint siteverify Cloudflare.
type HTTPSTurnstileVerifier struct {
	secret   string
	endpoint string
	client   *http.Client
}

// NewTurnstileVerifier membuat verifier untuk endpoint resmi Cloudflare.
func NewTurnstileVerifier(secret string, timeout time.Duration) *HTTPSTurnstileVerifier {
	return NewTurnstileVerifierWithEndpoint(secret, timeout, defaultTurnstileEndpoint)
}

// NewTurnstileVerifierWithEndpoint membuat verifier dengan endpoint khusus (untuk unit test).
func NewTurnstileVerifierWithEndpoint(secret string, timeout time.Duration, endpoint string) *HTTPSTurnstileVerifier {
	return &HTTPSTurnstileVerifier{
		secret:   secret,
		endpoint: endpoint,
		client:   &http.Client{Timeout: timeout},
	}
}

type siteverifyResponse struct {
	Success bool `json:"success"`
}

// Verify memvalidasi token Turnstile ke endpoint siteverify (fail-closed).
func (v *HTTPSTurnstileVerifier) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return false, nil
	}

	form := url.Values{}
	form.Set("secret", v.secret)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("turnstile siteverify status %d", resp.StatusCode)
	}

	var parsed siteverifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return false, err
	}
	return parsed.Success, nil
}

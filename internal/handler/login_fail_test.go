package handler_test

import (
	"context"
	"errors"
	"github.com/gear/engine/internal/handler"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var errLimiter = errors.New("unavailable")

type fakeLoginFailures struct {
	counts map[string]int
	fail   string
}

func (f *fakeLoginFailures) Check(_ context.Context, user string) (int, error) {
	if f.fail == "check" {
		return 0, errLimiter
	}
	if f.counts[strings.ToLower(strings.TrimSpace(user))] >= 5 {
		return 900, nil
	}
	return 0, nil
}
func (f *fakeLoginFailures) Record(_ context.Context, user string) error {
	if f.fail == "record" {
		return errLimiter
	}
	f.counts[strings.ToLower(strings.TrimSpace(user))]++
	return nil
}
func (f *fakeLoginFailures) Reset(_ context.Context, user string) error {
	if f.fail == "reset" {
		return errLimiter
	}
	delete(f.counts, strings.ToLower(strings.TrimSpace(user)))
	return nil
}

func TestLoginFailureLimitBlocksSixthBeforeTurnstile(t *testing.T) {
	db := setupAdminsDB(t)
	calls := 0
	verifier := &mockTurnstileVerifier{fn: func(context.Context, string, string) (bool, error) { calls++; return false, nil }}
	h := handler.NewAuthHandler(db, &mockTokenService{}, time.Hour, verifier)
	h.SetLoginFailureLimiter(&fakeLoginFailures{counts: map[string]int{}})
	for i := 0; i < 6; i++ {
		rr := httptest.NewRecorder()
		h.Login(rr, newLoginRequest("admin", "wrong", "bad"))
		want := http.StatusUnauthorized
		if i == 5 {
			want = http.StatusTooManyRequests
		}
		if rr.Code != want {
			t.Fatalf("attempt %d: got %d want %d", i+1, rr.Code, want)
		}
		if i == 5 && rr.Header().Get("Retry-After") == "" {
			t.Fatal("missing Retry-After")
		}
	}
	if calls != 5 {
		t.Fatalf("Turnstile called %d times", calls)
	}
}

func TestLoginFailureIsolationNormalizationAndReset(t *testing.T) {
	db := setupAdminsDB(t)
	f := &fakeLoginFailures{counts: map[string]int{}}
	h := handler.NewAuthHandler(db, &mockTokenService{create: func(context.Context, string, time.Duration) (string, int64, error) { return "token", 1, nil }}, time.Hour, nil)
	h.SetLoginFailureLimiter(f)
	request := func(user, pass string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.Login(rr, newLoginRequest(user, pass, ""))
		return rr
	}
	for i := 0; i < 4; i++ {
		if got := request("admin", "wrong").Code; got != 401 {
			t.Fatal(got)
		}
	}
	if got := request("admin", "correct-password").Code; got != 200 {
		t.Fatal(got)
	}
	for i := 0; i < 5; i++ {
		if got := request(" AdMiN ", "wrong").Code; got != 401 {
			t.Fatal(got)
		}
	}
	if got := request("admin", "wrong").Code; got != 429 {
		t.Fatal(got)
	}
	if got := request("someone-else", "wrong").Code; got != 401 {
		t.Fatal(got)
	}
}

func TestLoginFailureUnknownAndExistingHaveSameResponse(t *testing.T) {
	db := setupAdminsDB(t)
	h := handler.NewAuthHandler(db, &mockTokenService{}, time.Hour, nil)
	h.SetLoginFailureLimiter(&fakeLoginFailures{counts: map[string]int{}})
	for i := 0; i < 6; i++ {
		a, b := httptest.NewRecorder(), httptest.NewRecorder()
		h.Login(a, newLoginRequest("admin", "wrong", ""))
		h.Login(b, newLoginRequest("nonexistent", "wrong", ""))
		if a.Code != b.Code || a.Body.String() != b.Body.String() || a.Header().Get("Retry-After") != b.Header().Get("Retry-After") {
			t.Fatalf("attempt %d responses differ", i+1)
		}
	}
}

func TestLoginFailureStoreErrorsFailClosed(t *testing.T) {
	for _, stage := range []string{"check", "record", "reset"} {
		t.Run(stage, func(t *testing.T) {
			db := setupAdminsDB(t)
			f := &fakeLoginFailures{counts: map[string]int{}, fail: stage}
			h := handler.NewAuthHandler(db, &mockTokenService{}, time.Hour, nil)
			h.SetLoginFailureLimiter(f)
			pass := "wrong"
			if stage == "reset" {
				pass = "correct-password"
			}
			rr := httptest.NewRecorder()
			h.Login(rr, newLoginRequest("admin", pass, ""))
			if rr.Code != 503 {
				t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

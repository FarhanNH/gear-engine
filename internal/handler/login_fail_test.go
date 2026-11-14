package handler_test

import (
	"context"
	"errors"
	"github.com/gear/engine/internal/handler"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var errLimiter = errors.New("unavailable")

type fakeLoginFailures struct {
	counts map[string]int
	fail   string
}

func (f *fakeLoginFailures) Reserve(_ context.Context, user string) (int, error) {
	if f.fail == "reserve" {
		return 0, errLimiter
	}
	key := strings.ToLower(strings.TrimSpace(user))
	if f.counts[key] >= 5 {
		return 900, nil
	}
	f.counts[key]++
	return 0, nil
}
func (f *fakeLoginFailures) Reset(ctx context.Context, user string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("reset has no deadline")
	}
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

func TestLoginTokenCreateFailureDoesNotReset(t *testing.T) {
	db := setupAdminsDB(t)
	f := &fakeLoginFailures{counts: map[string]int{"admin": 2}}
	h := handler.NewAuthHandler(db, &mockTokenService{create: func(context.Context, string, time.Duration) (string, int64, error) {
		return "", 0, errors.New("create failed")
	}}, time.Hour, nil)
	h.SetLoginFailureLimiter(f)
	rr := httptest.NewRecorder()
	h.Login(rr, newLoginRequest("admin", "correct-password", ""))
	if rr.Code != http.StatusInternalServerError || f.counts["admin"] < 2 {
		t.Fatalf("status=%d counts=%v", rr.Code, f.counts)
	}
}

func TestLoginResetAfterClientCancellation(t *testing.T) {
	db := setupAdminsDB(t)
	f := &fakeLoginFailures{counts: map[string]int{"admin": 2}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := handler.NewAuthHandler(db, &mockTokenService{create: func(context.Context, string, time.Duration) (string, int64, error) {
		cancel()
		return "secret-token", 42, nil
	}}, time.Hour, nil)
	h.SetLoginFailureLimiter(f)
	rr := httptest.NewRecorder()
	h.Login(rr, newLoginRequest("admin", "correct-password", "").WithContext(ctx))
	if rr.Code != http.StatusOK || f.counts["admin"] != 0 {
		t.Fatalf("status=%d counts=%v body=%s", rr.Code, f.counts, rr.Body.String())
	}
}

func TestLoginResetFailureRevokesAndNeverReturnsToken(t *testing.T) {
	for _, revokeFails := range []bool{false, true} {
		t.Run(strconv.FormatBool(revokeFails), func(t *testing.T) {
			db := setupAdminsDB(t)
			f := &fakeLoginFailures{counts: map[string]int{}, fail: "reset"}
			called := false
			h := handler.NewAuthHandler(db, &mockTokenService{
				create: func(context.Context, string, time.Duration) (string, int64, error) { return "secret-token", 42, nil },
				revoke: func(ctx context.Context, id int64) error {
					called = true
					if id != 42 || ctx.Err() != nil {
						t.Errorf("revoke id=%d ctx=%v", id, ctx.Err())
					}
					if _, ok := ctx.Deadline(); !ok {
						t.Error("revoke has no deadline")
					}
					if revokeFails {
						return errors.New("revoke failed")
					}
					return nil
				},
			}, time.Hour, nil)
			h.SetLoginFailureLimiter(f)
			rr := httptest.NewRecorder()
			h.Login(rr, newLoginRequest("admin", "correct-password", ""))
			if rr.Code != http.StatusServiceUnavailable || strings.Contains(rr.Body.String(), "secret-token") || !called || f.counts["admin"] != 1 {
				t.Fatalf("status=%d body=%s revoked=%v counts=%v", rr.Code, rr.Body.String(), called, f.counts)
			}
		})
	}
}

func TestLoginFailureStoreErrorsFailClosed(t *testing.T) {
	for _, stage := range []string{"reserve", "reset"} {
		t.Run(stage, func(t *testing.T) {
			db := setupAdminsDB(t)
			f := &fakeLoginFailures{counts: map[string]int{}, fail: stage}
			h := handler.NewAuthHandler(db, &mockTokenService{
				create: func(context.Context, string, time.Duration) (string, int64, error) { return "secret-token", 42, nil },
				revoke: func(context.Context, int64) error { return nil },
			}, time.Hour, nil)
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

package handler

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func TestLoginUnknownUsernameCallsBcrypt(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE admins (username TEXT, password_hash TEXT)`); err != nil {
		t.Fatal(err)
	}
	h := NewAuthHandler(db, nil, time.Hour, nil)
	calls := 0
	h.bcrypt = func(hash, password string) error {
		calls++
		if password != "test-password" {
			t.Errorf("password = %q", password)
		}
		cost, err := bcrypt.Cost([]byte(hash))
		if err != nil || cost != 12 {
			t.Errorf("dummy hash cost = %d, error = %v", cost, err)
		}
		return nil // Even a matching dummy hash must never authenticate.
	}
	rr := httptest.NewRecorder()
	h.Login(rr, httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"username":"missing","password":"test-password"}`)))
	if rr.Code != http.StatusUnauthorized || calls != 1 {
		t.Fatalf("status = %d, bcrypt calls = %d", rr.Code, calls)
	}
}

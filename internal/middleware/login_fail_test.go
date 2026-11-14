package middleware

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"testing"
	"time"
)

func TestLoginFailureKeyNormalizesAndHashes(t *testing.T) {
	want := fmt.Sprintf("gear:login-fail:%x", sha256.Sum256([]byte("admin")))
	if got := loginFailureKey(" AdMiN \t"); got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
}

type fakeRedis struct {
	redis.UniversalClient
	keys  []string
	args  []interface{}
	value int64
	err   error
}

func (f *fakeRedis) EvalSha(ctx context.Context, sha string, keys []string, args ...interface{}) *redis.Cmd {
	f.keys, f.args = keys, args
	c := redis.NewCmd(ctx)
	c.SetVal(f.value)
	c.SetErr(f.err)
	return c
}
func (f *fakeRedis) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	f.keys = keys
	c := redis.NewIntCmd(ctx)
	c.SetErr(f.err)
	return c
}
func TestRedisLoginFailuresPassesHashedKeyAndPropagatesErrors(t *testing.T) {
	f := &fakeRedis{value: 42}
	l := NewRedisLoginFailures(f, 5, 15*time.Minute)
	ctx := context.Background()
	retry, err := l.Reserve(ctx, " Admin ")
	if err != nil || retry != 42 || len(f.keys) != 1 || f.keys[0] != loginFailureKey("admin") || len(f.args) != 3 || f.args[0] != 5 || f.args[1] != (15*time.Minute).Microseconds() {
		t.Fatalf("reserve: %d %v keys=%v args=%v", retry, err, f.keys, f.args)
	}
	if err := l.Reset(ctx, " Admin "); err != nil || f.keys[0] != loginFailureKey("admin") {
		t.Fatalf("reset: %v", err)
	}
	f.err = errors.New("unavailable")
	if _, err := l.Reserve(ctx, "admin"); err == nil {
		t.Fatal("reserve ignored error")
	}
	if err := l.Reset(ctx, "admin"); err == nil {
		t.Fatal("reset ignored error")
	}
}

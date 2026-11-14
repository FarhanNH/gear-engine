package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Prefix the exact keys passed to Redis without altering the production limiter.
type prefixedTestRedis struct {
	redis.UniversalClient
	prefix string
}

func (r *prefixedTestRedis) keys(keys []string) []string {
	out := make([]string, len(keys))
	for i, key := range keys {
		out[i] = r.prefix + key
	}
	return out
}
func (r *prefixedTestRedis) EvalSha(ctx context.Context, sha string, keys []string, args ...interface{}) *redis.Cmd {
	return r.UniversalClient.EvalSha(ctx, sha, r.keys(keys), args...)
}
func (r *prefixedTestRedis) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
	return r.UniversalClient.Eval(ctx, script, r.keys(keys), args...)
}
func (r *prefixedTestRedis) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	return r.UniversalClient.Del(ctx, r.keys(keys)...)
}

func TestRedisLoginFailuresIntegration(t *testing.T) {
	addr := os.Getenv("GEAR_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("GEAR_TEST_REDIS_ADDR not set")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	prefix := "gear:test:login-fail:" + hex.EncodeToString(nonce[:]) + ":"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cleanupCancel()
		if err := client.Del(cleanupCtx, prefix+loginFailureKey("alice"), prefix+loginFailureKey("bob")).Err(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	l := NewRedisLoginFailures(&prefixedTestRedis{UniversalClient: client, prefix: prefix}, 5, 2*time.Second)
	check := func(user string, blocked bool) {
		t.Helper()
		retry, err := l.Check(ctx, user)
		if err != nil || (retry > 0) != blocked {
			t.Fatalf("check %s: retry=%d err=%v, blocked=%v", user, retry, err, blocked)
		}
	}
	record := func(user string) {
		t.Helper()
		if err := l.Record(ctx, user); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		check("alice", false)
		record("alice")
	}
	check("alice", true) // sixth attempt
	check("bob", false)
	for i := 0; i < 5; i++ {
		record("bob")
	}
	check("bob", true)
	if err := l.Reset(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	check("alice", false)
	check("bob", true)
	if n, err := client.Exists(ctx, prefix+loginFailureKey("alice")).Result(); err != nil || n != 0 {
		t.Fatalf("reset key exists=%d err=%v", n, err)
	}
	for i := 0; i < 5; i++ {
		check("alice", false)
		record("alice")
	}
	check("alice", true)
	time.Sleep(2100 * time.Millisecond)
	check("alice", false)
}

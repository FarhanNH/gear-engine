package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
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

func testRedisLimiter(t *testing.T, window time.Duration) (*RedisLoginFailures, *redis.Client, string) {
	t.Helper()
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
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := client.Del(ctx, prefix+loginFailureKey("alice"), prefix+loginFailureKey("bob")).Err(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return NewRedisLoginFailures(&prefixedTestRedis{UniversalClient: client, prefix: prefix}, 5, window), client, prefix
}

func TestParallelLoginReservations(t *testing.T) {
	l, _, _ := testRedisLimiter(t, time.Minute)
	var done sync.WaitGroup
	start := make(chan struct{})
	type result struct {
		retry int
		err   error
	}
	results := make(chan result, 20)
	for i := 0; i < 20; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			<-start
			retry, err := l.Reserve(context.Background(), "alice")
			results <- result{retry, err}
		}()
	}
	close(start)
	done.Wait()
	close(results)
	allowed, denied := 0, 0
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.retry == 0 {
			allowed++
		} else {
			denied++
		}
	}
	if allowed != 5 || denied != 15 {
		t.Fatalf("allowed=%d denied=%d", allowed, denied)
	}
}

func TestRedisLoginFailuresIntegration(t *testing.T) {
	l, client, prefix := testRedisLimiter(t, 300*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reserve := func(user string, blocked bool) {
		t.Helper()
		retry, err := l.Reserve(ctx, user)
		if err != nil || (retry > 0) != blocked {
			t.Fatalf("reserve %s: retry=%d err=%v blocked=%v", user, retry, err, blocked)
		}
	}
	for i := 0; i < 5; i++ {
		reserve("alice", false)
	}
	reserve("alice", true)
	for i := 0; i < 5; i++ {
		reserve("bob", false)
	}
	if err := l.Reset(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	reserve("bob", true)
	if n, err := client.Exists(ctx, prefix+loginFailureKey("alice")).Result(); err != nil || n != 0 {
		t.Fatalf("reset key exists=%d err=%v", n, err)
	}
	for i := 0; i < 5; i++ {
		reserve("alice", false)
	}
	reserve("alice", true)
	time.Sleep(400 * time.Millisecond)
	reserve("alice", false)
}

func TestRedisRetryAfterAboveLimit(t *testing.T) {
	l, client, prefix := testRedisLimiter(t, 10*time.Second)
	ctx := context.Background()
	key := prefix + loginFailureKey("alice")
	// Seed seven historic entries; the third-oldest, not the oldest, determines retry.
	err := client.Eval(ctx, `
local t = redis.call('TIME')
local now = tonumber(t[1])*1000000+tonumber(t[2])
for i, age in ipairs({9, 8, 4, 3, 2, 1, 0}) do
  redis.call('ZADD', KEYS[1], now-age*1000000, tostring(i))
end
redis.call('EXPIRE', KEYS[1], 10)
return 1`, []string{key}).Err()
	if err != nil {
		t.Fatal(err)
	}
	retry, err := l.Reserve(ctx, "alice")
	if err != nil || retry != 6 {
		t.Fatalf("retry=%d err=%v, want 6", retry, err)
	}
	if count, err := client.ZCard(ctx, key).Result(); err != nil || count != 7 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

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
func (r *prefixedTestRedis) ZRem(ctx context.Context, key string, members ...interface{}) *redis.IntCmd {
	return r.UniversalClient.ZRem(ctx, r.prefix+key, members...)
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
			_, retry, err := l.Reserve(context.Background(), "alice")
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
	reserve := func(user string, blocked bool) string {
		t.Helper()
		member, retry, err := l.Reserve(ctx, user)
		if err != nil || (retry > 0) != blocked {
			t.Fatalf("reserve %s: retry=%d err=%v blocked=%v", user, retry, err, blocked)
		}
		return member
	}
	for i := 0; i < 4; i++ {
		reserve("alice", false)
	}
	success := reserve("alice", false)
	reserve("alice", true)
	for i := 0; i < 5; i++ {
		reserve("bob", false)
	}
	if err := l.Release(ctx, "alice", success); err != nil {
		t.Fatal(err)
	}
	reserve("bob", true)
	if n, err := client.ZCard(ctx, prefix+loginFailureKey("alice")).Result(); err != nil || n != 4 {
		t.Fatalf("remaining=%d err=%v", n, err)
	}
	reserve("alice", false)
	reserve("alice", true)
	time.Sleep(400 * time.Millisecond)
	reserve("alice", false)
}

func TestSuccessfulLoginPreservesOtherReservations(t *testing.T) {
	l, client, prefix := testRedisLimiter(t, 15*time.Minute)
	ctx := context.Background()
	a, retry, err := l.Reserve(ctx, "alice")
	if err != nil || retry != 0 || a == "" {
		t.Fatalf("reserve A: member=%q retry=%d err=%v", a, retry, err)
	}
	type reservation struct {
		member string
		retry  int
		err    error
	}
	ready := make(chan reservation, 4)
	finish := make(chan struct{})
	defer close(finish)
	for i := 0; i < 4; i++ {
		go func() {
			member, retry, err := l.Reserve(ctx, "alice")
			ready <- reservation{member, retry, err}
			<-finish
		}()
	}
	others := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		r := <-ready
		if r.err != nil || r.retry != 0 || r.member == "" {
			t.Fatalf("reserve %d: retry=%d err=%v", i, r.retry, r.err)
		}
		others = append(others, r.member)
	}
	// A completes while B..E remain in flight, before any further reservation.
	if err := l.Release(ctx, "alice", a); err != nil {
		t.Fatal(err)
	}
	key := prefix + loginFailureKey("alice")
	if count, err := client.ZCard(ctx, key).Result(); err != nil || count != 4 {
		t.Fatalf("remaining reservations=%d err=%v, want 4", count, err)
	}
	for _, member := range others {
		if _, err := client.ZScore(ctx, key, member).Result(); err != nil {
			t.Fatalf("in-flight member %q missing: %v", member, err)
		}
	}
	if _, err := client.ZScore(ctx, key, a).Result(); err != redis.Nil {
		t.Fatalf("A still present or error: %v", err)
	}
	if member, retry, err := l.Reserve(ctx, "alice"); err != nil || retry != 0 || member == "" {
		t.Fatalf("next reserve: member=%q retry=%d err=%v", member, retry, err)
	}
	if member, retry, err := l.Reserve(ctx, "alice"); err != nil || retry <= 0 || member != "" {
		t.Fatalf("limit: member=%q retry=%d err=%v", member, retry, err)
	}
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
	_, retry, err := l.Reserve(ctx, "alice")
	if err != nil || retry != 6 {
		t.Fatalf("retry=%d err=%v, want 6", retry, err)
	}
	if count, err := client.ZCard(ctx, key).Result(); err != nil || count != 7 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

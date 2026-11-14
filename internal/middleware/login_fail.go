package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisLoginFailures struct {
	client redis.UniversalClient
	max    int
	window time.Duration
}

func NewRedisLoginFailures(client redis.UniversalClient, max int, window time.Duration) *RedisLoginFailures {
	return &RedisLoginFailures{client: client, max: max, window: window}
}
func loginFailureKey(username string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username))))
	return "gear:login-fail:" + hex.EncodeToString(sum[:])
}

var loginFailureReserve = redis.NewScript(`
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local window = tonumber(ARGV[2])
local max = tonumber(ARGV[1])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now-window)
local count = redis.call('ZCARD', KEYS[1])
if count >= max then
  local entry = redis.call('ZRANGE', KEYS[1], count-max, count-max, 'WITHSCORES')
  return math.max(1, math.ceil((tonumber(entry[2])+window-now)/1000000))
end
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], math.ceil(window/1000))
return 0
`)

func (l *RedisLoginFailures) Reserve(ctx context.Context, username string) (int, error) {
	var member [16]byte
	if _, err := rand.Read(member[:]); err != nil {
		return 0, fmt.Errorf("generate login failure member: %w", err)
	}
	n, err := loginFailureReserve.Run(ctx, l.client, []string{loginFailureKey(username)}, l.max, l.window.Microseconds(), hex.EncodeToString(member[:])).Int64()
	if err != nil {
		return 0, fmt.Errorf("reserve login failure: %w", err)
	}
	return int(n), nil
}
func (l *RedisLoginFailures) Reset(ctx context.Context, username string) error {
	return l.client.Del(ctx, loginFailureKey(username)).Err()
}

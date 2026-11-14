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

var loginFailureCheck = redis.NewScript(`
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local window = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now-window)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  return math.max(1, math.ceil((tonumber(oldest[2])+window-now)/1000000))
end
return 0
`)
var loginFailureRecord = redis.NewScript(`
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local window = tonumber(ARGV[1])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now-window)
redis.call('ZADD', KEYS[1], now, ARGV[2])
redis.call('PEXPIRE', KEYS[1], math.ceil(window/1000))
return 1
`)

func (l *RedisLoginFailures) Check(ctx context.Context, username string) (int, error) {
	n, err := loginFailureCheck.Run(ctx, l.client, []string{loginFailureKey(username)}, l.max, l.window.Microseconds()).Int64()
	if err != nil {
		return 0, fmt.Errorf("check login failures: %w", err)
	}
	return int(n), nil
}
func (l *RedisLoginFailures) Record(ctx context.Context, username string) error {
	var member [16]byte
	if _, err := rand.Read(member[:]); err != nil {
		return fmt.Errorf("generate login failure member: %w", err)
	}
	return loginFailureRecord.Run(ctx, l.client, []string{loginFailureKey(username)}, l.window.Microseconds(), hex.EncodeToString(member[:])).Err()
}
func (l *RedisLoginFailures) Reset(ctx context.Context, username string) error {
	return l.client.Del(ctx, loginFailureKey(username)).Err()
}

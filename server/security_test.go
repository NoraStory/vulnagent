package main

import (
	"testing"
	"time"
)

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		pwd  string
		want string
	}{
		{"short1", "口令至少 10 个字符"},
		{"onlyletters", "口令需同时包含字母与数字"},
		{"1234567890123", "口令需同时包含字母与数字"},
		{"Admin@12345", ""},
	}
	for _, c := range cases {
		if got := validatePassword(c.pwd); got != c.want {
			t.Fatalf("validatePassword(%q) = %q, want %q", c.pwd, got, c.want)
		}
	}
}

func TestLoginLimiterLocksAfterFiveFailures(t *testing.T) {
	l := newLoginLimiter()
	key := "admin|127.0.0.1"
	for i := 0; i < 4; i++ {
		if l.fail(key) {
			t.Fatalf("第 %d 次失败不应锁定", i+1)
		}
	}
	if !l.fail(key) {
		t.Fatal("第 5 次失败应触发锁定")
	}
	if wait := l.retryAfter(key); wait <= 0 {
		t.Fatal("锁定后 retryAfter 应大于 0")
	}
	l.reset(key)
	if wait := l.retryAfter(key); wait != 0 {
		t.Fatal("reset 后应解除锁定")
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		origin, host string
		want         bool
	}{
		{"http://127.0.0.1:8787", "127.0.0.1:8787", true},
		{"http://localhost:5173", "127.0.0.1:8787", true},
		{"https://evil.example.com", "127.0.0.1:8787", false},
	}
	for _, c := range cases {
		if got := sameOrigin(c.origin, c.host); got != c.want {
			t.Fatalf("sameOrigin(%q,%q) = %t, want %t", c.origin, c.host, got, c.want)
		}
	}
}

func TestSessionIdleAndDropUser(t *testing.T) {
	s := &sessionStore{m: map[string]session{}, idle: 40 * time.Millisecond}
	tokAdmin := s.create(User{Username: "admin", Name: "管理员", Role: "admin"})
	time.Sleep(60 * time.Millisecond)
	if _, ok := s.get(tokAdmin); ok {
		t.Fatal("空闲超时后会话应失效")
	}
	s.idle = time.Minute
	tokAdmin2 := s.create(User{Username: "admin", Role: "admin"})
	tokOps := s.create(User{Username: "operator", Name: "运维", Role: "operator"})
	if dropped := s.dropUser("admin", ""); dropped != 1 {
		t.Fatalf("dropUser 应清理 1 个会话，实际 %d", dropped)
	}
	if _, ok := s.get(tokAdmin2); ok {
		t.Fatal("dropUser 后 admin 会话应失效")
	}
	if _, ok := s.get(tokOps); !ok {
		t.Fatal("其他账号会话不应受影响")
	}
}

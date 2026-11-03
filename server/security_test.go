package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestRedactedRequestURI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ssh/shared/secret-token?token=abc123&path=%2Fetc%2Fpasswd&hostId=1", nil)
	got := redactedRequestURI(req)
	for _, leaked := range []string{"secret-token", "abc123", "/etc/passwd"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("日志地址仍包含敏感信息 %q：%s", leaked, got)
		}
	}
	if !strings.Contains(got, "hostId=1") {
		t.Fatalf("非敏感参数应保留：%s", got)
	}
}

func TestClientIPTrustProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 1.2.3.4")

	t.Setenv("VA_TRUST_PROXY", "off")
	if got := clientIP(req); got != "10.0.0.1" {
		t.Fatalf("未信任代理时应使用 RemoteAddr，实际 %s", got)
	}
	t.Setenv("VA_TRUST_PROXY", "on")
	if got := clientIP(req); got != "1.2.3.4" {
		t.Fatalf("信任代理时应取 X-Forwarded-For 最右值，实际 %s", got)
	}
}

func TestCheckWebSocketOrigin(t *testing.T) {
	newReq := func(origin string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ssh/terminal", nil)
		req.Host = "127.0.0.1:8787"
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		return req
	}
	cases := []struct {
		origin string
		want   bool
	}{
		{"http://127.0.0.1:5173", true},
		{"https://evil.example.com", false},
		{"null", false},
		{"", true},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		if got := checkWebSocketOrigin(rec, newReq(c.origin)); got != c.want {
			t.Fatalf("Origin=%q 期望 %t，实际 %t", c.origin, c.want, got)
		}
		if !c.want && rec.Code != http.StatusForbidden {
			t.Fatalf("Origin=%q 应返回 403，实际 %d", c.origin, rec.Code)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := withSecurity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:8787"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("缺少 CSP 或策略不完整：%q", csp)
	}
	if rec.Header().Get("Permissions-Policy") == "" {
		t.Fatal("缺少 Permissions-Policy")
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HTTP 请求不应返回 HSTS")
	}

	secureReq := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8787/", nil)
	secureReq.TLS = &tls.ConnectionState{}
	secureRec := httptest.NewRecorder()
	handler.ServeHTTP(secureRec, secureReq)
	if secureRec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HTTPS 请求应返回 HSTS")
	}
}

func TestMetricsAuthorizedUsesDedicatedToken(t *testing.T) {
	t.Setenv("VA_METRICS_TOKEN", "metrics-secret")
	app := &App{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	req.Header.Set("Authorization", "Bearer metrics-secret")
	if !app.metricsAuthorized(req) {
		t.Fatal("专用指标令牌应通过校验")
	}
	req.Header.Set("Authorization", "Bearer wrong")
	if app.metricsAuthorized(req) {
		t.Fatal("错误令牌不应通过校验")
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

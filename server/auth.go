package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User 对外暴露的用户信息
type User struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

type session struct {
	user    User
	expires time.Time
}

// sessionStore 服务端会话表，空闲超过 VA_SESSION_IDLE（默认 30 分钟）失效
type sessionStore struct {
	mu   sync.Mutex
	m    map[string]session
	idle time.Duration
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: make(map[string]session), idle: sessionIdleFromEnv()}
}

func (s *sessionStore) create(u User) string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// 极端情况下退化为时间戳，保证仍可登录
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	tok := hex.EncodeToString(buf)
	s.mu.Lock()
	s.m[tok] = session{user: u, expires: time.Now().Add(s.idle)}
	s.mu.Unlock()
	return tok
}

func (s *sessionStore) get(tok string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.m[tok]
	if !ok {
		return User{}, false
	}
	now := time.Now()
	if now.After(item.expires) {
		delete(s.m, tok)
		return User{}, false
	}
	// 滑动续期：活跃访问不断延长空闲窗口
	item.expires = now.Add(s.idle)
	s.m[tok] = item
	return item.user, true
}

func (s *sessionStore) remove(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// dropUser 使指定账号的会话立即失效，keep 指定的令牌保留（修改本人口令时使用）
func (s *sessionStore) dropUser(username, keep string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped := 0
	for tok, item := range s.m {
		if item.user.Username == username && tok != keep {
			delete(s.m, tok)
			dropped++
		}
	}
	return dropped
}

type ctxKeyUser struct{}

func userFrom(r *http.Request) *User {
	if v, ok := r.Context().Value(ctxKeyUser{}).(User); ok {
		return &v
	}
	return nil
}

func roleRank(role string) int {
	switch role {
	case "admin":
		return 3
	case "operator":
		return 2
	case "viewer":
		return 1
	}
	return 0
}

// withAuth 除登录与健康检查外的接口都要求会话
func (a *App) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if !strings.HasPrefix(p, "/api/v1/") || p == "/api/v1/auth/login" || p == "/api/v1/healthz" ||
			p == "/api/v1/agent/report" {
			next.ServeHTTP(w, r)
			return
		}
		// 指标接口允许 Prometheus 使用 Agent Bearer 令牌抓取
		if p == "/api/v1/metrics" && a.agentAuthorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie("va_session")
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "未登录或会话已过期")
			return
		}
		u, ok := a.sessions.get(cookie.Value)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "未登录或会话已过期")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser{}, u)))
	})
}

// requireRole 校验最小角色，失败时已写出响应
func requireRole(w http.ResponseWriter, r *http.Request, min string) (*User, bool) {
	u := userFrom(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "未登录或会话已过期")
		return nil, false
	}
	if roleRank(u.Role) < roleRank(min) {
		writeErr(w, http.StatusForbidden, "forbidden", "当前角色无权执行该操作")
		return nil, false
	}
	return u, true
}

// audit 写一条审计日志，只追加不修改
func (a *App) audit(r *http.Request, action, target, detail string) {
	actor, role := "系统", "system"
	ip, ua := "127.0.0.1", ""
	if r != nil {
		if u := userFrom(r); u != nil {
			actor, role = u.Name, u.Role
		}
		ip = clientIP(r)
		ua = r.UserAgent()
	}
	a.auditAs(actor, role, ip, ua, action, target, detail)
}

// auditAs 以指定身份写审计日志（Agent 上报等无会话场景）
func (a *App) auditAs(actor, role, ip, ua, action, target, detail string) {
	if _, err := a.db.Exec(`INSERT INTO audit_logs(actor, role, action, target, ip, ua, detail, created_at)
		VALUES(?,?,?,?,?,?,?,?)`, actor, role, action, target, ip, ua, detail, fmtT(nowT())); err != nil {
		slog.Error("写审计日志失败", "action", action, "err", err)
	}
}

// demoAccounts 演示账号，口令以 bcrypt 落库
var demoAccounts = []struct {
	Username string
	Password string
	Role     string
	Name     string
}{
	{"admin", "Admin@12345", "admin", "张启明"},
	{"operator", "Ops@12345", "operator", "李维"},
	{"viewer", "View@12345", "viewer", "陈可"},
}

// ensureUsers 演示模式下保证三个演示账号存在；生产模式（VA_SEED_DEMO=off）
// 仅在没有管理员时用 VA_ADMIN_PASSWORD 初始化一个 admin 账号。
func ensureUsers(db *sql.DB) error {
	if !seedDemoEnabled() {
		return ensureBootstrapAdmin(db)
	}
	now := fmtT(nowT())
	for _, acc := range demoAccounts {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, acc.Username).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(acc.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO users(username, name, pwd_hash, role, disabled, last_login)
			VALUES(?,?,?,?,0,?)`, acc.Username, acc.Name, string(hash), acc.Role, now); err != nil {
			return err
		}
	}
	return nil
}

func ensureBootstrapAdmin(db *sql.DB) error {
	var admins int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&admins); err != nil {
		return err
	}
	if admins > 0 {
		return nil
	}
	pwd := strings.TrimSpace(os.Getenv("VA_ADMIN_PASSWORD"))
	if msg := validatePassword(pwd); msg != "" {
		return fmt.Errorf("未启用演示数据时必须通过 VA_ADMIN_PASSWORD 设置管理员初始口令（%s）", msg)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO users(username, name, pwd_hash, role, disabled, last_login)
		VALUES('admin','管理员',?,'admin',0,?)`, string(hash), fmtT(nowT())); err != nil {
		return err
	}
	slog.Info("已初始化管理员账号", "username", "admin", "hint", "请登录后立即修改口令")
	return nil
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "用户名与口令不能为空")
		return
	}

	key := req.Username + "|" + clientIP(r)
	if wait := a.loginGuard.retryAfter(key); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		a.auditAs(req.Username, "-", clientIP(r), r.UserAgent(), "auth.login_blocked", req.Username,
			"连续失败过多，已临时锁定")
		writeErr(w, http.StatusTooManyRequests, "too_many_attempts",
			"登录失败次数过多，请 "+humanDuration(wait)+"后重试")
		return
	}

	var pwdHash, name, role string
	var disabled int
	err := a.db.QueryRow(`SELECT pwd_hash, name, role, disabled FROM users WHERE username = ?`, req.Username).
		Scan(&pwdHash, &name, &role, &disabled)
	if err != nil || disabled != 0 || bcrypt.CompareHashAndPassword([]byte(pwdHash), []byte(req.Password)) != nil {
		locked := a.loginGuard.fail(key)
		detail := "用户名或口令错误"
		if locked {
			detail = "连续失败达到上限，账号临时锁定"
		}
		a.auditAs(req.Username, "-", clientIP(r), r.UserAgent(), "auth.login_failed", req.Username, detail)
		writeErr(w, http.StatusUnauthorized, "unauthorized", "用户名或口令错误")
		return
	}
	a.loginGuard.reset(key)

	u := User{Username: req.Username, Name: name, Role: role}
	tok := a.sessions.create(u)
	a.db.Exec(`UPDATE users SET last_login = ? WHERE username = ?`, fmtT(nowT()), req.Username)
	a.setSessionCookie(w, r, tok)
	// 登录本身也需要留痕
	req2 := r.Clone(r.Context())
	req2 = req2.WithContext(context.WithValue(req2.Context(), ctxKeyUser{}, u))
	a.audit(req2, "auth.login", u.Username, "登录成功")
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if u := userFrom(r); u != nil {
		a.audit(r, "auth.logout", u.Username, "退出登录")
	}
	if tok := cookieToken(r); tok != "" {
		a.sessions.remove(tok)
	}
	a.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "未登录或会话已过期")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": *u})
}

func (a *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": appVersion, "demo": a.demoMode()})
}

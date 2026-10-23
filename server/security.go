package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/platform/config"
)

// ---------- 会话与 Cookie ----------

const cookieName = "va_session"

// sessionIdleFromEnv 会话空闲过期时间，配置见 internal/platform/config
func sessionIdleFromEnv() time.Duration { return config.Load().SessionIdle }

// cookieSecure 仅在使用 HTTPS 或显式开启时给会话 Cookie 加 Secure
func cookieSecure(r *http.Request) bool {
	if config.Load().CookieSecure {
		return true
	}
	return r.TLS != nil
}

func (a *App) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
}

func (a *App) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func cookieToken(r *http.Request) string {
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}

// ---------- 登录失败限速 ----------

const (
	loginWindow     = 10 * time.Minute
	loginMaxFails   = 5
	loginLockPeriod = 5 * time.Minute
)

type loginState struct {
	fails  int
	window time.Time
	lockTo time.Time
}

type loginLimiter struct {
	mu sync.Mutex
	m  map[string]*loginState
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{m: make(map[string]*loginState)}
}

// retryAfter 返回剩余锁定时间，0 表示未锁定
func (l *loginLimiter) retryAfter(key string) time.Duration {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.m[key]
	if !ok {
		return 0
	}
	if now.Before(st.lockTo) {
		return st.lockTo.Sub(now)
	}
	if now.Sub(st.window) > loginWindow {
		delete(l.m, key)
	}
	return 0
}

// fail 记录一次失败，达到阈值则锁定并返回 true
func (l *loginLimiter) fail(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) > 4096 {
		for k, v := range l.m {
			if now.Sub(v.window) > loginWindow && now.After(v.lockTo) {
				delete(l.m, k)
			}
		}
	}
	st, ok := l.m[key]
	if !ok || now.Sub(st.window) > loginWindow {
		st = &loginState{window: now}
		l.m[key] = st
	}
	st.fails++
	if st.fails >= loginMaxFails {
		st.lockTo = now.Add(loginLockPeriod)
		st.fails = 0
		st.window = now
		return true
	}
	return false
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

// ---------- 安全响应头与同源校验 ----------

func withSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
				if !sameOrigin(origin, r.Host) {
					writeErr(w, http.StatusForbidden, "csrf_origin_mismatch", "请求来源与当前站点不一致")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin 忽略端口与 localhost/127.0.0.1 差异，兼容前端开发代理
func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return normalizeHost(u.Host) == normalizeHost(host)
}

func normalizeHost(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	if v == "localhost" || v == "::1" || v == "[::1]" {
		return "127.0.0.1"
	}
	return v
}

// ---------- 口令策略 ----------

func validatePassword(pwd string) string {
	if len([]rune(pwd)) < 10 {
		return "口令至少 10 个字符"
	}
	var letter, digit bool
	for _, r := range pwd {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			letter = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	if !letter || !digit {
		return "口令需同时包含字母与数字"
	}
	return ""
}

// ---------- 修改自己的口令 ----------

func (a *App) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "未登录或会话已过期")
		return
	}
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, http.StatusBadRequest, "weak_password", msg)
		return
	}
	if req.NewPassword == req.OldPassword {
		writeErr(w, http.StatusBadRequest, "bad_request", "新口令不能与原口令相同")
		return
	}
	hash, err := a.identityRepo().PasswordHash(r.Context(), u.Username)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "账号不存在")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)) != nil {
		a.audit(r, "auth.password_change_failed", u.Username, "原口令校验失败")
		writeErr(w, http.StatusBadRequest, "invalid_password", "原口令不正确")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新口令失败")
		return
	}
	if err := a.identityRepo().UpdatePassword(r.Context(), u.Username, string(newHash)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新口令失败")
		return
	}
	// 口令变更后其余会话立即失效，当前会话保留
	a.sessions.dropUser(u.Username, cookieToken(r))
	a.audit(r, "auth.password_change", u.Username, "口令已更新，其他会话已下线")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- 账号管理（admin） ----------

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,32}$`)

func validRole(role string) bool {
	return roleRank(role) > 0
}

func (a *App) handleUsersList(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	rows, err := a.identityRepo().ListAccounts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询账号失败")
		return
	}
	items := make([]settingsUser, 0, len(rows))
	for _, acc := range rows {
		items = append(items, settingsUser{
			Username:  acc.Username,
			Name:      acc.Name,
			Role:      acc.Role,
			LastLogin: acc.LastLogin,
			Disabled:  acc.Disabled,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	var req struct {
		Username string `json:"username"`
		Name     string `json:"name"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Name = strings.TrimSpace(req.Name)
	if !usernamePattern.MatchString(req.Username) {
		writeErr(w, http.StatusBadRequest, "bad_request", "账号需 3–32 位，仅含字母、数字、点、下划线或短横线")
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "姓名不能为空")
		return
	}
	if !validRole(req.Role) {
		writeErr(w, http.StatusBadRequest, "bad_request", "角色必须为 admin / operator / viewer")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, http.StatusBadRequest, "weak_password", msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建账号失败")
		return
	}
	if err := a.identityRepo().CreateAccount(r.Context(), ports.Account{
		Username: req.Username,
		Name:     req.Name,
		PwdHash:  string(hash),
		Role:     req.Role,
	}); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeErr(w, http.StatusConflict, "username_exists", "账号已存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建账号失败")
		return
	}
	a.audit(r, "user.create", req.Username, "创建账号，角色 "+req.Role)
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":   true,
		"user": settingsUser{Username: req.Username, Name: req.Name, Role: req.Role},
	})
}

func (a *App) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	admin, ok := requireRole(w, r, "admin")
	if !ok {
		return
	}
	target := r.PathValue("username")
	var req struct {
		Name     *string `json:"name"`
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	cur, err := a.identityRepo().FindAccount(r.Context(), target)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "账号不存在")
		return
	}
	nextRole, nextName, nextDisabled := cur.Role, cur.Name, cur.Disabled
	if req.Role != nil {
		if !validRole(*req.Role) {
			writeErr(w, http.StatusBadRequest, "bad_request", "角色必须为 admin / operator / viewer")
			return
		}
		nextRole = *req.Role
	}
	if req.Name != nil {
		nextName = strings.TrimSpace(*req.Name)
		if nextName == "" {
			writeErr(w, http.StatusBadRequest, "bad_request", "姓名不能为空")
			return
		}
	}
	if req.Disabled != nil {
		nextDisabled = *req.Disabled
	}
	if target == admin.Username && (nextRole != "admin" || nextDisabled) {
		writeErr(w, http.StatusBadRequest, "cannot_modify_self", "不能停用或降级当前登录账号")
		return
	}
	losesAdmin := cur.Role == "admin" && !cur.Disabled && (nextRole != "admin" || nextDisabled)
	if losesAdmin {
		activeAdmins, err := a.identityRepo().CountActiveAdmins(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "更新账号失败")
			return
		}
		if activeAdmins <= 1 {
			writeErr(w, http.StatusBadRequest, "last_admin", "至少保留一个启用状态的管理员")
			return
		}
	}
	if err := a.identityRepo().UpdateAccount(r.Context(), target, nextName, nextRole, nextDisabled); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新账号失败")
		return
	}
	if nextDisabled {
		a.sessions.dropUser(target, "")
	}
	a.audit(r, "user.update", target, fmt.Sprintf("姓名=%s 角色=%s 停用=%t", nextName, nextRole, nextDisabled))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"user": settingsUser{Username: target, Name: nextName, Role: nextRole, Disabled: nextDisabled},
	})
}

func (a *App) handleUserResetPassword(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	target := r.PathValue("username")
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, http.StatusBadRequest, "weak_password", msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "重置口令失败")
		return
	}
	if err := a.identityRepo().UpdatePassword(r.Context(), target, string(hash)); err != nil {
		if errors.Is(err, ports.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "账号不存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal_error", "重置口令失败")
		return
	}
	a.sessions.dropUser(target, "")
	a.audit(r, "user.reset_password", target, "管理员重置口令，该账号所有会话已下线")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- Agent 令牌轮换 ----------

func (a *App) handleAgentTokenRotate(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	if strings.TrimSpace(config.Load().AgentToken) != "" {
		writeErr(w, http.StatusConflict, "env_managed", "当前令牌由 VA_AGENT_TOKEN 指定，无法在控制台轮换")
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "生成令牌失败")
		return
	}
	token := hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(token))

	if err := a.identityRepo().ReplaceToken(r.Context(), hex.EncodeToString(sum[:]), fmtT(nowT())); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "轮换令牌失败")
		return
	}
	path := filepath.Join(a.dataDir, agentTokenFileName)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "写入令牌文件失败："+err.Error())
		return
	}
	a.audit(r, "agent.token.rotate", path, "旧令牌已失效，新令牌仅本次返回")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"token":     token,
		"file":      path,
		"rotatedAt": fmtT(nowT()),
	})
}

// ---------- 将秒数格式化为可读中文 ----------

func humanDuration(d time.Duration) string {
	secs := int(d.Seconds() + 0.5)
	if secs < 60 {
		return strconv.Itoa(secs) + " 秒"
	}
	return strconv.Itoa((secs+59)/60) + " 分钟"
}

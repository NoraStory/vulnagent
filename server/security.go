package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
)

// ---------- 会话与 Cookie ----------

const cookieName = "va_session"

// sessionIdleFromEnv 会话空闲过期时间，默认 30 分钟（文档口径一致）
func sessionIdleFromEnv() time.Duration {
	raw := os.Getenv("VA_SESSION_IDLE")
	if raw == "" {
		return 30 * time.Minute
	}
	if d, err := time.ParseDuration(raw); err == nil && d >= time.Minute {
		return d
	}
	return 30 * time.Minute
}

// cookieSecure 仅在使用 HTTPS 或显式开启时给会话 Cookie 加 Secure
func cookieSecure(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("VA_COOKIE_SECURE"))) {
	case "1", "true", "yes":
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
	var hash string
	if err := a.db.QueryRow(`SELECT pwd_hash FROM users WHERE username = ?`, u.Username).Scan(&hash); err != nil {
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
	if _, err := a.db.Exec(`UPDATE users SET pwd_hash = ? WHERE username = ?`, string(newHash), u.Username); err != nil {
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
	rows, err := a.db.Query(`SELECT username, name, role, last_login, disabled FROM users ORDER BY id ASC`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询账号失败")
		return
	}
	defer rows.Close()
	items := make([]settingsUser, 0, 8)
	for rows.Next() {
		var u settingsUser
		var disabled int
		if err := rows.Scan(&u.Username, &u.Name, &u.Role, &u.LastLogin, &disabled); err != nil {
			continue
		}
		u.Disabled = disabled != 0
		items = append(items, u)
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
	if _, err := a.db.Exec(`INSERT INTO users(username, name, pwd_hash, role, disabled, last_login)
		VALUES(?,?,?,?,0,'')`, req.Username, req.Name, string(hash), req.Role); err != nil {
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
	var curRole, curName string
	var curDisabled int
	if err := a.db.QueryRow(`SELECT role, name, disabled FROM users WHERE username = ?`, target).
		Scan(&curRole, &curName, &curDisabled); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "账号不存在")
		return
	}
	nextRole, nextName, nextDisabled := curRole, curName, curDisabled != 0
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
	losesAdmin := curRole == "admin" && curDisabled == 0 && (nextRole != "admin" || nextDisabled)
	if losesAdmin {
		var activeAdmins int
		if err := a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&activeAdmins); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "更新账号失败")
			return
		}
		if activeAdmins <= 1 {
			writeErr(w, http.StatusBadRequest, "last_admin", "至少保留一个启用状态的管理员")
			return
		}
	}
	disabledValue := 0
	if nextDisabled {
		disabledValue = 1
	}
	if _, err := a.db.Exec(`UPDATE users SET name = ?, role = ?, disabled = ? WHERE username = ?`,
		nextName, nextRole, disabledValue, target); err != nil {
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
	res, err := a.db.Exec(`UPDATE users SET pwd_hash = ? WHERE username = ?`, string(hash), target)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "重置口令失败")
		return
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		writeErr(w, http.StatusNotFound, "not_found", "账号不存在")
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
	if strings.TrimSpace(os.Getenv("VA_AGENT_TOKEN")) != "" {
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

	tx, err := a.db.Begin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "轮换令牌失败")
		return
	}
	if _, err := tx.Exec(`DELETE FROM agent_tokens`); err != nil {
		tx.Rollback()
		writeErr(w, http.StatusInternalServerError, "internal_error", "轮换令牌失败")
		return
	}
	if _, err := tx.Exec(`INSERT INTO agent_tokens(token_hash, created_at) VALUES(?,?)`,
		hex.EncodeToString(sum[:]), fmtT(nowT())); err != nil {
		tx.Rollback()
		writeErr(w, http.StatusInternalServerError, "internal_error", "轮换令牌失败")
		return
	}
	if err := tx.Commit(); err != nil {
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

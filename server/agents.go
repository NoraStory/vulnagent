package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	agentOnlineWindow = 3 * time.Minute
	// agentJobKeyPrefix 与 CLI 端保持一致的作业签名派生前缀
	agentJobKeyPrefix = "vulnagent-job:"
)

type agentRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	OSVersion   string `json:"osVersion"`
	Version     string `json:"version"`
	ProjectID   int64  `json:"projectId"`
	ProjectName string `json:"projectName"`
	ClusterID   int64  `json:"clusterId"`
	ClusterName string `json:"clusterName"`
	LastSeenAt  string `json:"lastSeenAt"`
	LastIP      string `json:"lastIp"`
	EnrolledAt  string `json:"enrolledAt"`
	EnrolledBy  string `json:"enrolledBy"`
	RevokedAt   string `json:"revokedAt"`
	Online      bool   `json:"online"`
	Status      string `json:"status"`
	Pending     int    `json:"pendingCommands"`
	Total       int    `json:"totalCommands"`
	SecretHash  string `json:"-"`
}

type agentEnrollTokenRecord struct {
	ID          string `json:"id"`
	NameHint    string `json:"nameHint"`
	ProjectID   int64  `json:"projectId"`
	ProjectName string `json:"projectName"`
	ClusterID   int64  `json:"clusterId"`
	ClusterName string `json:"clusterName"`
	ExpiresAt   string `json:"expiresAt"`
	UsedAt      string `json:"usedAt"`
	UsedByAgent string `json:"usedByAgent"`
	CreatedBy   string `json:"createdBy"`
	CreatedAt   string `json:"createdAt"`
	Status      string `json:"status"`
}

type agentCommandRecord struct {
	ID          string `json:"id"`
	AgentID     string `json:"agentId"`
	Action      string `json:"action"`
	Params      string `json:"params"`
	Status      string `json:"status"`
	Output      string `json:"output"`
	Error       string `json:"error"`
	RequestedBy string `json:"requestedBy"`
	CreatedAt   string `json:"createdAt"`
	ClaimedAt   string `json:"claimedAt"`
	FinishedAt  string `json:"finishedAt"`
}

type agentPrincipal struct {
	Legacy bool
	Agent  agentRecord
	Key    []byte
}

func agentSecretHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func agentSigningKey(secret string) []byte {
	sum := sha256.Sum256([]byte(agentJobKeyPrefix + secret))
	return sum[:]
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

const agentSelect = `SELECT a.id, a.name, a.hostname, a.os, a.os_version, a.version,
	a.project_id, COALESCE(p.name,''), a.cluster_id, COALESCE(c.name,''),
	a.secret_hash, a.enrolled_by, a.enrolled_at, a.last_seen_at, a.last_ip, a.revoked_at,
	(SELECT COUNT(*) FROM agent_commands cmd WHERE cmd.agent_id = a.id AND cmd.status = 'pending'),
	(SELECT COUNT(*) FROM agent_commands cmd WHERE cmd.agent_id = a.id)
	FROM agents a
	LEFT JOIN projects p ON p.id = a.project_id
	LEFT JOIN clusters c ON c.id = a.cluster_id`

func scanAgent(row interface{ Scan(dest ...any) error }) (agentRecord, error) {
	var rec agentRecord
	err := row.Scan(&rec.ID, &rec.Name, &rec.Hostname, &rec.OS, &rec.OSVersion, &rec.Version,
		&rec.ProjectID, &rec.ProjectName, &rec.ClusterID, &rec.ClusterName,
		&rec.SecretHash, &rec.EnrolledBy, &rec.EnrolledAt, &rec.LastSeenAt, &rec.LastIP, &rec.RevokedAt,
		&rec.Pending, &rec.Total)
	if err != nil {
		return rec, err
	}
	rec.Online, rec.Status = agentStatusOf(rec)
	return rec, nil
}

func agentStatusOf(rec agentRecord) (bool, string) {
	if rec.RevokedAt != "" {
		return false, "revoked"
	}
	if rec.LastSeenAt == "" {
		return false, "offline"
	}
	seen, err := time.Parse(time.RFC3339, rec.LastSeenAt)
	if err != nil {
		return false, "offline"
	}
	if time.Since(seen) <= agentOnlineWindow {
		return true, "online"
	}
	return false, "offline"
}

func (a *App) agentByID(ctx context.Context, id string) (agentRecord, error) {
	return scanAgent(a.db.QueryRowContext(ctx, agentSelect+` WHERE a.id = ?`, id))
}

func (a *App) listAgents(ctx context.Context) ([]agentRecord, error) {
	rows, err := a.db.QueryContext(ctx, agentSelect+` ORDER BY a.enrolled_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]agentRecord, 0, 16)
	for rows.Next() {
		rec, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, rec)
	}
	return items, rows.Err()
}

// authenticateAgent 支持两种身份：全局 Agent 令牌（兼容旧部署）与单机 Agent 身份。
func (a *App) authenticateAgent(r *http.Request) (agentPrincipal, bool) {
	agentID := strings.TrimSpace(r.Header.Get("X-Agent-Id"))
	secret := strings.TrimSpace(r.Header.Get("X-Agent-Secret"))
	if agentID != "" || secret != "" {
		if agentID == "" || secret == "" {
			return agentPrincipal{}, false
		}
		rec, err := a.agentByID(r.Context(), agentID)
		if err != nil || rec.RevokedAt != "" {
			return agentPrincipal{}, false
		}
		if subtle.ConstantTimeCompare([]byte(rec.SecretHash), []byte(agentSecretHash(secret))) != 1 {
			return agentPrincipal{}, false
		}
		return agentPrincipal{Agent: rec, Key: agentSigningKey(secret)}, true
	}
	if a.legacyAgentAuthorized(r) {
		return agentPrincipal{Legacy: true, Key: a.jobKey}, true
	}
	return agentPrincipal{}, false
}

func (a *App) legacyAgentAuthorized(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	sumHex := hex.EncodeToString(sum[:])
	stored, err := a.identityRepo().ListTokenHashes(r.Context())
	if err != nil {
		return false
	}
	for _, hash := range stored {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(sumHex)) == 1 {
			return true
		}
	}
	return false
}

func (a *App) touchAgent(ctx context.Context, id, ip string) {
	if id == "" {
		return
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE agents SET last_seen_at=?, last_ip=? WHERE id=?`, fmtT(nowT()), ip, id)
}

// ---------- 注册 ----------

func (a *App) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token     string `json:"token"`
		Name      string `json:"name"`
		Hostname  string `json:"hostname"`
		OS        string `json:"os"`
		OSVersion string `json:"osVersion"`
		Version   string `json:"version"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	token := strings.TrimSpace(in.Token)
	if token == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "缺少注册令牌")
		return
	}
	hostname := strings.TrimSpace(in.Hostname)
	if hostname == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "缺少 hostname")
		return
	}
	hash := agentSecretHash(token)
	now := fmtT(nowT())

	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "注册失败")
		return
	}
	defer tx.Rollback()
	var tokenID string
	var projectID, clusterID int64
	var expiresAt, usedAt string
	err = tx.QueryRowContext(r.Context(), `SELECT id, project_id, cluster_id, expires_at, used_at
		FROM agent_enroll_tokens WHERE token_hash = ?`, hash).Scan(&tokenID, &projectID, &clusterID, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusUnauthorized, "invalid_token", "注册令牌无效")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "注册失败")
		return
	}
	if usedAt != "" {
		writeErr(w, http.StatusConflict, "token_used", "注册令牌已使用")
		return
	}
	expires, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().After(expires) {
		writeErr(w, http.StatusGone, "token_expired", "注册令牌已过期")
		return
	}

	agentID := "AGT-" + mustRandomHex(6)
	secret, err := randomHex(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "注册失败")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = hostname
	}
	if len(name) > 80 {
		name = name[:80]
	}
	res, err := tx.ExecContext(r.Context(), `UPDATE agent_enroll_tokens SET used_at=?, used_by_agent=?
		WHERE id=? AND used_at=''`, now, agentID, tokenID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "注册失败")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusConflict, "token_used", "注册令牌已被使用")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO agents
		(id, name, hostname, os, os_version, version, project_id, cluster_id, secret_hash,
		 enrolled_by, enrolled_at, last_seen_at, last_ip)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		agentID, name, hostname, strings.TrimSpace(in.OS), strings.TrimSpace(in.OSVersion),
		strings.TrimSpace(in.Version), projectID, clusterID, agentSecretHash(secret),
		"注册令牌", now, now, clientIP(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "注册失败")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "注册失败")
		return
	}
	a.auditAs("Agent "+name, "agent", clientIP(r), r.UserAgent(), "agent.enroll", agentID,
		fmt.Sprintf("%s 注册成功，项目 #%d 集群 #%d", hostname, projectID, clusterID))
	writeJSON(w, http.StatusCreated, map[string]any{
		"agentId": agentID, "secret": secret, "name": name,
		"projectId": projectID, "clusterId": clusterID,
	})
}

func mustRandomHex(bytes int) string {
	value, err := randomHex(bytes)
	if err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return value
}

func (a *App) handleAgentEnrollTokenCreate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	var in struct {
		NameHint   string `json:"nameHint"`
		ProjectID  int64  `json:"projectId"`
		ClusterID  int64  `json:"clusterId"`
		TTLMinutes int    `json:"ttlMinutes"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if in.TTLMinutes <= 0 {
		in.TTLMinutes = 60
	}
	if in.TTLMinutes < 5 {
		in.TTLMinutes = 5
	}
	if in.TTLMinutes > 1440 {
		in.TTLMinutes = 1440
	}
	projectID, clusterID := in.ProjectID, in.ClusterID
	if clusterID > 0 {
		var clusterProject int64
		err := a.db.QueryRowContext(r.Context(), `SELECT project_id FROM clusters WHERE id = ?`, clusterID).Scan(&clusterProject)
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusBadRequest, "bad_request", "集群不存在")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "读取集群失败")
			return
		}
		if projectID > 0 && projectID != clusterProject {
			writeErr(w, http.StatusBadRequest, "bad_request", "集群不属于所选项目")
			return
		}
		projectID = clusterProject
	}
	if projectID > 0 {
		var exists int
		if err := a.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM projects WHERE id = ?`, projectID).Scan(&exists); err != nil || exists == 0 {
			writeErr(w, http.StatusBadRequest, "bad_request", "项目不存在")
			return
		}
	}
	token := "VAENR-" + mustRandomHex(24)
	id := "ET-" + mustRandomHex(6)
	now := nowT()
	expiresAt := fmtT(now.Add(time.Duration(in.TTLMinutes) * time.Minute))
	if _, err := a.db.ExecContext(r.Context(), `INSERT INTO agent_enroll_tokens
		(id, token_hash, name_hint, project_id, cluster_id, expires_at, created_by, created_at)
		VALUES(?,?,?,?,?,?,?,?)`,
		id, agentSecretHash(token), strings.TrimSpace(in.NameHint), projectID, clusterID,
		expiresAt, u.Username, fmtT(now)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建注册令牌失败")
		return
	}
	a.audit(r, "agent.enroll_token", id, fmt.Sprintf("创建一次性注册令牌，有效期 %d 分钟", in.TTLMinutes))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "token": token, "expiresAt": expiresAt,
		"projectId": projectID, "clusterId": clusterID,
	})
}

func (a *App) handleAgentEnrollTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT t.id, t.name_hint, t.project_id, COALESCE(p.name,''),
		t.cluster_id, COALESCE(c.name,''), t.expires_at, t.used_at, t.used_by_agent, t.created_by, t.created_at
		FROM agent_enroll_tokens t
		LEFT JOIN projects p ON p.id = t.project_id
		LEFT JOIN clusters c ON c.id = t.cluster_id
		ORDER BY t.created_at DESC LIMIT 50`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取注册令牌失败")
		return
	}
	defer rows.Close()
	items := make([]agentEnrollTokenRecord, 0, 10)
	for rows.Next() {
		var item agentEnrollTokenRecord
		if err := rows.Scan(&item.ID, &item.NameHint, &item.ProjectID, &item.ProjectName,
			&item.ClusterID, &item.ClusterName, &item.ExpiresAt, &item.UsedAt, &item.UsedByAgent,
			&item.CreatedBy, &item.CreatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "读取注册令牌失败")
			return
		}
		switch {
		case item.UsedAt != "":
			item.Status = "used"
		case item.ExpiresAt < fmtT(nowT()):
			item.Status = "expired"
		default:
			item.Status = "active"
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleAgentEnrollTokenDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id := r.PathValue("id")
	res, err := a.db.ExecContext(r.Context(), `DELETE FROM agent_enroll_tokens WHERE id = ? AND used_at = ''`, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "删除注册令牌失败")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "not_found", "令牌不存在或已被使用")
		return
	}
	a.audit(r, "agent.enroll_token.delete", id, "删除未使用的注册令牌")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- Agent 管理 ----------

func (a *App) handleAgents(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	items, err := a.listAgents(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取 Agent 失败")
		return
	}
	online := 0
	for _, item := range items {
		if item.Online {
			online++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "online": online})
}

func (a *App) handleAgentRevoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id := r.PathValue("id")
	agent, err := a.agentByID(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "Agent 不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取 Agent 失败")
		return
	}
	now := fmtT(nowT())
	if _, err := a.db.ExecContext(r.Context(), `UPDATE agents SET revoked_at=? WHERE id=?`, now, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "吊销 Agent 失败")
		return
	}
	_, _ = a.db.ExecContext(r.Context(), `UPDATE agent_commands SET status='failed', error='Agent 已吊销', finished_at=?
		WHERE agent_id=? AND status IN ('pending','claimed')`, now, id)
	a.audit(r, "agent.revoke", agent.Name, "吊销 Agent 身份（"+agent.Hostname+"）")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- 心跳与命令通道 ----------

func (a *App) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.authenticateAgent(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "Agent 身份无效")
		return
	}
	if principal.Legacy {
		writeErr(w, http.StatusBadRequest, "legacy_agent", "旧版全局令牌不支持心跳，请使用注册令牌接入")
		return
	}
	var in struct {
		Hostname  string `json:"hostname"`
		OS        string `json:"os"`
		OSVersion string `json:"osVersion"`
		Version   string `json:"version"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	now := fmtT(nowT())
	_, err := a.db.ExecContext(r.Context(), `UPDATE agents SET last_seen_at=?, last_ip=?,
		hostname=CASE WHEN ?='' THEN hostname ELSE ? END,
		os=CASE WHEN ?='' THEN os ELSE ? END,
		os_version=CASE WHEN ?='' THEN os_version ELSE ? END,
		version=CASE WHEN ?='' THEN version ELSE ? END
		WHERE id=?`,
		now, clientIP(r),
		strings.TrimSpace(in.Hostname), strings.TrimSpace(in.Hostname),
		strings.TrimSpace(in.OS), strings.TrimSpace(in.OS),
		strings.TrimSpace(in.OSVersion), strings.TrimSpace(in.OSVersion),
		strings.TrimSpace(in.Version), strings.TrimSpace(in.Version),
		principal.Agent.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "更新心跳失败")
		return
	}
	var pending int
	_ = a.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM agent_commands WHERE agent_id=? AND status='pending'`,
		principal.Agent.ID).Scan(&pending)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "serverTime": now, "pendingCommands": pending,
	})
}

func (a *App) handleAgentCommandCreate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	agent, err := a.agentByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "not_found", "Agent 不存在")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取 Agent 失败")
		return
	}
	if agent.RevokedAt != "" {
		writeErr(w, http.StatusBadRequest, "agent_revoked", "Agent 已吊销")
		return
	}
	var in struct {
		Action string `json:"action"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	action := strings.ToLower(strings.TrimSpace(in.Action))
	if action != "ping" && action != "collect" {
		writeErr(w, http.StatusBadRequest, "bad_request", "action 仅支持 ping 或 collect")
		return
	}
	id := "ACMD-" + mustRandomHex(6)
	if _, err := a.db.ExecContext(r.Context(), `INSERT INTO agent_commands
		(id, agent_id, action, params, status, requested_by, created_at)
		VALUES(?,?,?,'{}','pending',?,?)`, id, agent.ID, action, u.Username, fmtT(nowT())); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建命令失败")
		return
	}
	a.audit(r, "agent.command", agent.Name, "下发命令 "+action)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "id": id})
}

func (a *App) handleAgentCommands(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	agentID := r.PathValue("id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	commands, err := a.agentCommandHistory(r.Context(), agentID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取命令失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": commands})
}

func (a *App) agentCommandHistory(ctx context.Context, agentID string, limit int) ([]agentCommandRecord, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id, agent_id, action, params, status, output, error,
		requested_by, created_at, claimed_at, finished_at
		FROM agent_commands WHERE agent_id=? ORDER BY created_at DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]agentCommandRecord, 0, limit)
	for rows.Next() {
		var item agentCommandRecord
		if err := rows.Scan(&item.ID, &item.AgentID, &item.Action, &item.Params, &item.Status,
			&item.Output, &item.Error, &item.RequestedBy, &item.CreatedAt, &item.ClaimedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// handleAgentCommandPoll 由 Agent 主动拉取并抢占命令
func (a *App) handleAgentCommandPoll(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.authenticateAgent(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "Agent 身份无效")
		return
	}
	if principal.Legacy {
		writeJSON(w, http.StatusOK, map[string]any{"items": []agentCommandRecord{}})
		return
	}
	a.touchAgent(r.Context(), principal.Agent.ID, clientIP(r))
	rows, err := a.db.QueryContext(r.Context(), `SELECT id, agent_id, action, params, status, output, error,
		requested_by, created_at, claimed_at, finished_at
		FROM agent_commands WHERE agent_id=? AND status='pending' ORDER BY created_at LIMIT 5`, principal.Agent.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取命令失败")
		return
	}
	items := make([]agentCommandRecord, 0, 5)
	for rows.Next() {
		var item agentCommandRecord
		if err := rows.Scan(&item.ID, &item.AgentID, &item.Action, &item.Params, &item.Status,
			&item.Output, &item.Error, &item.RequestedBy, &item.CreatedAt, &item.ClaimedAt, &item.FinishedAt); err != nil {
			continue
		}
		items = append(items, item)
	}
	rows.Close()
	now := fmtT(nowT())
	for i := range items {
		res, err := a.db.ExecContext(r.Context(), `UPDATE agent_commands SET status='claimed', claimed_at=?
			WHERE id=? AND status='pending'`, now, items[i].ID)
		if err != nil {
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			items[i].Status = "claimed"
			items[i].ClaimedAt = now
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleAgentCommandResult(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.authenticateAgent(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "Agent 身份无效")
		return
	}
	if principal.Legacy {
		writeErr(w, http.StatusForbidden, "legacy_agent", "旧版全局令牌不支持命令回传")
		return
	}
	var in struct {
		Status string `json:"status"`
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if in.Status != "succeeded" && in.Status != "failed" {
		writeErr(w, http.StatusBadRequest, "bad_request", "status 仅支持 succeeded/failed")
		return
	}
	commandID := r.PathValue("id")
	var owner string
	if err := a.db.QueryRowContext(r.Context(), `SELECT agent_id FROM agent_commands WHERE id=?`, commandID).Scan(&owner); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "命令不存在")
		return
	}
	if owner != principal.Agent.ID {
		writeErr(w, http.StatusForbidden, "forbidden", "命令不属于该 Agent")
		return
	}
	_, err := a.db.ExecContext(r.Context(), `UPDATE agent_commands SET status=?, output=?, error=?, finished_at=?
		WHERE id=?`, in.Status, truncateRunes(in.Output, 8000), truncateRunes(in.Error, 1000), fmtT(nowT()), commandID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "写入命令结果失败")
		return
	}
	a.touchAgent(r.Context(), principal.Agent.ID, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

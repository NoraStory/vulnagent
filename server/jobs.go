package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	mathrand "math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/application/ports"
)

// signedJob 带 HMAC 签名的主机作业信封
type signedJob struct {
	ports.HostJob
	Signature string `json:"signature"`
}

func (a *App) signJob(job ports.HostJob) signedJob {
	return signedJob{HostJob: job, Signature: jobSignature(a.jobKey, job)}
}

func jobSignature(key []byte, job ports.HostJob) string {
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(job.ID + "|" + job.Action + "|" + job.Params))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyJobSignature 校验作业未被篡改；key 为空时视为未启用签名。
func verifyJobSignature(key []byte, job ports.HostJob, signature string) bool {
	if len(key) == 0 {
		return true
	}
	return hmac.Equal([]byte(jobSignature(key, job)), []byte(signature))
}

// queueHostJob 幂等地创建主机作业，返回作业实体
func (a *App) queueHostJob(assetID int64, action string, params json.RawMessage, requestedBy, approvalID string) (ports.HostJob, error) {
	ctx := context.Background()
	normalized := json.RawMessage("{}")
	if len(params) > 0 {
		var buf map[string]any
		if err := json.Unmarshal(params, &buf); err != nil {
			return ports.HostJob{}, fmt.Errorf("参数格式错误：%w", err)
		}
		raw, _ := json.Marshal(buf)
		normalized = raw
	}
	if err := a.enforceOpsPolicy(assetID, action); err != nil {
		return ports.HostJob{}, err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s", assetID, action, string(normalized))))
	key := hex.EncodeToString(sum[:])
	since := fmtT(nowT().Add(-10 * time.Minute))
	if existing, found, err := a.jobRepo().ExistingByIdempotency(ctx, key, since); err != nil {
		return ports.HostJob{}, err
	} else if found {
		return existing, nil
	}

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return ports.HostJob{}, err
	}
	now := fmtT(nowT())
	job := ports.HostJob{
		ID:             "JOB-" + hex.EncodeToString(idBytes),
		AssetID:        assetID,
		Action:         action,
		Params:         string(normalized),
		Risk:           "high",
		Status:         "pending",
		RequestedBy:    requestedBy,
		ApprovalID:     approvalID,
		IdempotencyKey: key,
		MaxAttempts:    3,
		CreatedAt:      now,
	}
	if err := a.jobRepo().Create(ctx, job); err != nil {
		return ports.HostJob{}, err
	}
	slog.Info("主机作业已排队", "jobId", job.ID, "assetId", assetID, "action", action, "by", requestedBy)
	return job, nil
}

// waitHostJob 最多等待 timeout，返回作业当前状态
func (a *App) waitHostJob(id string, timeout time.Duration) (ports.HostJob, error) {
	deadline := time.Now().Add(timeout)
	for {
		job, found, err := a.jobRepo().ByID(context.Background(), id)
		if err != nil {
			return ports.HostJob{}, err
		}
		if !found {
			return ports.HostJob{}, ports.ErrNotFound
		}
		if job.Status == "succeeded" || job.Status == "failed" || job.Status == "canceled" {
			return job, nil
		}
		if time.Now().After(deadline) {
			return job, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func jobRetryDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 6 {
		attempt = 6
	}
	base := 5 * time.Second * time.Duration(1<<attempt)
	if base > 5*time.Minute {
		base = 5 * time.Minute
	}
	return base + time.Duration(mathrand.Int63n(int64(base/2)+1))
}

func (a *App) assetHostname(assetID int64) (string, error) {
	var hostname string
	err := a.db.QueryRow(`SELECT hostname FROM assets WHERE id = ?`, assetID).Scan(&hostname)
	return hostname, err
}

// handleAgentJobs 返回该主机当前可执行的作业
func (a *App) handleAgentJobs(w http.ResponseWriter, r *http.Request) {
	if !a.agentAuthorized(r) {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "Agent 令牌无效")
		return
	}
	hostname := strings.TrimSpace(r.URL.Query().Get("hostname"))
	if hostname == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "缺少 hostname")
		return
	}
	jobs, err := a.jobRepo().DueForHost(r.Context(), hostname, fmtT(nowT()), 5)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询主机作业失败")
		return
	}
	signed := make([]signedJob, 0, len(jobs))
	for _, job := range jobs {
		signed = append(signed, a.signJob(job))
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": signed})
}

// handleAgentJobClaim 抢占作业
func (a *App) handleAgentJobClaim(w http.ResponseWriter, r *http.Request) {
	if !a.agentAuthorized(r) {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "Agent 令牌无效")
		return
	}
	var req struct {
		Hostname string `json:"hostname"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	hostname := strings.TrimSpace(req.Hostname)
	if hostname == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "缺少 hostname")
		return
	}
	job, ok, err := a.jobRepo().Claim(r.Context(), r.PathValue("id"), hostname, fmtT(nowT()))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "抢占作业失败")
		return
	}
	if !ok {
		writeErr(w, http.StatusConflict, "not_available", "作业不存在、已被取走或未到执行时间")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": a.signJob(job)})
}

// handleAgentJobResult 接收 Agent 执行结果并按需安排重试
func (a *App) handleAgentJobResult(w http.ResponseWriter, r *http.Request) {
	if !a.agentAuthorized(r) {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "Agent 令牌无效")
		return
	}
	var req struct {
		Hostname string `json:"hostname"`
		ports.HostJobResult
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if req.Status != "succeeded" && req.Status != "failed" {
		writeErr(w, http.StatusBadRequest, "bad_request", "status 仅支持 succeeded/failed")
		return
	}
	id := r.PathValue("id")
	job, found, err := a.jobRepo().ByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "读取作业失败")
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "not_found", "作业不存在")
		return
	}
	hostname, err := a.assetHostname(job.AssetID)
	if err != nil || hostname != strings.TrimSpace(req.Hostname) {
		writeErr(w, http.StatusForbidden, "forbidden", "作业不属于该主机")
		return
	}

	now := fmtT(nowT())
	nextRun := ""
	status := req.Status
	if status == "failed" && req.Retryable && job.Attempts < job.MaxAttempts {
		status = "pending"
		nextRun = fmtT(nowT().Add(jobRetryDelay(job.Attempts)))
	}
	if err := a.jobRepo().Complete(r.Context(), id, status, req.Output, req.Error, req.ExitCode, now, nextRun); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "写入作业结果失败")
		return
	}
	a.auditAs("Agent "+hostname, "agent", clientIP(r), r.UserAgent(), "host.job.result", id,
		fmt.Sprintf("%s → %s（exit=%d，重试=%v）", job.Action, status, req.ExitCode, nextRun != ""))
	slog.Info("主机作业完成", "jobId", id, "action", job.Action, "status", status,
		"exitCode", req.ExitCode, "retry", nextRun != "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": status, "retryScheduled": nextRun != ""})
}

// handleAssetJobs 控制台查看资产作业历史
func (a *App) handleAssetJobs(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的资产 ID")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	jobs, err := a.jobRepo().ListByAsset(r.Context(), id, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询作业失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": jobs, "total": len(jobs)})
}

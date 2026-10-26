package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// opsPolicy 运维执行策略
type opsPolicy struct {
	ReadOnly       bool `json:"readOnly"`
	MaxJobsPerHour int  `json:"maxJobsPerHour"`
	RetentionDays  int  `json:"retentionDays"`
}

func defaultOpsPolicy() opsPolicy {
	return opsPolicy{ReadOnly: false, MaxJobsPerHour: 30, RetentionDays: 30}
}

func (a *App) loadOpsPolicy() opsPolicy {
	policy := defaultOpsPolicy()
	if raw := getMeta(a.db, "ops_policy"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &policy)
	}
	return policy
}

func (a *App) saveOpsPolicy(p opsPolicy) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return setMeta(a.db, "ops_policy", string(raw))
}

func (a *App) handleOpsPolicy(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "admin")
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"policy": a.loadOpsPolicy()})
		return
	}
	var req opsPolicy
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if req.MaxJobsPerHour < 0 || req.MaxJobsPerHour > 500 {
		writeErr(w, http.StatusBadRequest, "bad_request", "每小时作业上限需在 0-500 之间")
		return
	}
	if req.RetentionDays < 1 || req.RetentionDays > 3650 {
		writeErr(w, http.StatusBadRequest, "bad_request", "保留天数需在 1-3650 之间")
		return
	}
	if err := a.saveOpsPolicy(req); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存运维策略失败")
		return
	}
	actor := "admin"
	if u != nil {
		actor = u.Name
	}
	a.auditAs(actor, "admin", clientIP(r), r.UserAgent(), "ops.policy.update", "ops_policy",
		"只读模式/作业上限/保留天数已更新")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": req})
}

// enforceOpsPolicy 在作业入队前执行只读与频率限制
func (a *App) enforceOpsPolicy(assetID int64, action string) error {
	policy := a.loadOpsPolicy()
	if policy.ReadOnly && action != "read_file" && action != "run_command" {
		return harnessErrReadOnly
	}
	if policy.MaxJobsPerHour > 0 {
		var count int
		since := fmtT(nowT().Add(-time.Hour))
		if err := a.db.QueryRow(`SELECT COUNT(*) FROM host_jobs WHERE asset_id = ? AND created_at >= ?`,
			assetID, since).Scan(&count); err != nil {
			return err
		}
		if count >= policy.MaxJobsPerHour {
			return harnessErrRateLimited
		}
	}
	return nil
}

// 复用 harness 错误语义，便于工具层统一展示
var (
	harnessErrReadOnly    = &opsPolicyError{"当前处于只读运维模式，已拒绝写入类动作"}
	harnessErrRateLimited = &opsPolicyError{"该资产每小时作业数已达上限"}
)

type opsPolicyError struct{ msg string }

func (e *opsPolicyError) Error() string { return e.msg }

// cleanupOldJobs 按保留天数清理历史作业与尝试记录
func (a *App) cleanupOldJobs() {
	policy := a.loadOpsPolicy()
	if policy.RetentionDays <= 0 {
		return
	}
	cutoff := fmtT(nowT().AddDate(0, 0, -policy.RetentionDays))
	if _, err := a.db.Exec(`DELETE FROM host_job_attempts WHERE job_id IN
		(SELECT id FROM host_jobs WHERE created_at < ?)`, cutoff); err != nil {
		return
	}
	_, _ = a.db.Exec(`DELETE FROM host_jobs WHERE created_at < ?`, cutoff)
}

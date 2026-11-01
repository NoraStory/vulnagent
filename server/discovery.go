package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"vulnagent/server/internal/application/ports"
	"vulnagent/server/internal/discovery"
)

const discoveryPolicyMetaKey = "discovery_policy"

// ---------- 发现策略 ----------

func (a *App) loadDiscoveryPolicy() discovery.Policy {
	return discovery.ParsePolicy(getMeta(a.db, discoveryPolicyMetaKey))
}

func (a *App) saveDiscoveryPolicy(p discovery.Policy) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return setMeta(a.db, discoveryPolicyMetaKey, string(raw))
}

// handleDiscoveryPolicy 读取或更新发现策略（更新仅管理员）
func (a *App) handleDiscoveryPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if _, ok := requireRole(w, r, "viewer"); !ok {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"policy": a.loadDiscoveryPolicy()})
		return
	}
	if _, ok := requireRole(w, r, "admin"); !ok {
		return
	}
	var req discovery.Policy
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	if err := discovery.ValidatePolicyCIDRs(req.AllowedCIDRs); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	policy := discovery.NormalizePolicy(req)
	if _, err := discovery.NormalizePorts(policy.DefaultPorts, policy.MaxPorts); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "默认端口无效："+err.Error())
		return
	}
	if err := a.saveDiscoveryPolicy(policy); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "保存发现策略失败")
		return
	}
	a.audit(r, "discovery.policy.update", "discovery_policy",
		fmt.Sprintf("授权网段 %s，默认端口 %d 个，最大主机 %d", strings.Join(policy.AllowedCIDRs, ","),
			len(policy.DefaultPorts), policy.MaxHosts))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": policy})
}

// ---------- 任务 ----------

type discoveryJobRequest struct {
	Name        string   `json:"name"`
	CIDRs       []string `json:"cidrs"`
	Ports       []int    `json:"ports"`
	Concurrency int      `json:"concurrency"`
	TimeoutMs   int      `json:"timeoutMs"`
	ReverseDNS  *bool    `json:"reverseDns"`
}

// handleDiscoveryJobs 列出任务或创建新任务
func (a *App) handleDiscoveryJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if _, ok := requireRole(w, r, "viewer"); !ok {
			return
		}
		page, size, offset := pageParams(r)
		jobs, total, err := a.discoveryRepo().ListJobs(r.Context(), strings.TrimSpace(r.URL.Query().Get("status")), size, offset)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "查询发现任务失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"total": total, "page": page, "pageSize": size, "items": jobs,
		})
		return
	}

	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	var req discoveryJobRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	policy := a.loadDiscoveryPolicy()
	prefixes, total, err := discovery.ValidateCIDRs(req.CIDRs, policy)
	if err != nil {
		a.audit(r, "discovery.job.reject", "discovery", err.Error())
		writeErr(w, http.StatusBadRequest, "cidr_not_allowed", err.Error())
		return
	}
	requestedPorts := req.Ports
	if len(requestedPorts) == 0 {
		requestedPorts = policy.DefaultPorts
	}
	scanPorts, err := discovery.NormalizePorts(requestedPorts, policy.MaxPorts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	repo := a.discoveryRepo()
	if running, err := repo.CountRunningJobs(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询运行中任务失败")
		return
	} else if running > 0 {
		writeErr(w, http.StatusConflict, "job_running", "已有发现任务在执行，请等待完成或取消后再试")
		return
	}
	since := fmtT(nowT().Add(-time.Hour))
	if count, err := repo.CountJobsSince(r.Context(), since); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "发现任务限流检查失败")
		return
	} else if count >= policy.MaxJobsPerHour {
		writeErr(w, http.StatusTooManyRequests, "too_many_jobs", fmt.Sprintf("每小时最多发起 %d 个发现任务", policy.MaxJobsPerHour))
		return
	}

	concurrency := req.Concurrency
	if concurrency <= 0 || concurrency > policy.MaxConcurrency {
		concurrency = policy.MaxConcurrency
	}
	timeoutMS := req.TimeoutMs
	if timeoutMS <= 0 {
		timeoutMS = policy.TimeoutMS
	}
	if timeoutMS < 100 {
		timeoutMS = 100
	}
	if timeoutMS > 5000 {
		timeoutMS = 5000
	}
	reverseDNS := policy.ReverseDNS
	if req.ReverseDNS != nil {
		reverseDNS = *req.ReverseDNS
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "网段发现 " + nowT().Format("01-02 15:04")
	}
	options, _ := json.Marshal(map[string]any{
		"concurrency": concurrency,
		"timeoutMs":   timeoutMS,
		"reverseDns":  reverseDNS,
		"prefixes":    prefixStrings(prefixes),
	})
	job := ports.DiscoveryJob{
		Name:      name,
		CIDRs:     strings.Join(prefixStrings(prefixes), ","),
		Ports:     intsToCSV(scanPorts),
		Status:    "pending",
		Total:     total,
		Options:   string(options),
		CreatedBy: u.Name,
		CreatedAt: fmtT(nowT()),
	}
	jobID, err := repo.CreateJob(r.Context(), job)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "创建发现任务失败")
		return
	}
	a.audit(r, "discovery.job.create", fmt.Sprintf("discovery:%d", jobID),
		fmt.Sprintf("%s · %s · %s · %d 台主机", name, job.CIDRs, job.Ports, total))

	addrs := discovery.Addrs(prefixes, total)
	a.startDiscoveryJob(jobID, addrs, discovery.ScanOptions{
		Ports:       scanPorts,
		Concurrency: concurrency,
		Timeout:     time.Duration(timeoutMS) * time.Millisecond,
		ReverseDNS:  reverseDNS,
	})
	created, _ := repo.GetJob(r.Context(), jobID)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "job": created})
}

func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out
}

func intsToCSV(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

// handleDiscoveryJobDetail 返回任务详情与候选处置统计
func (a *App) handleDiscoveryJobDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的任务 ID")
		return
	}
	job, err := a.discoveryRepo().GetJob(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "发现任务不存在")
		return
	}
	counts, err := a.discoveryRepo().CountCandidates(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "统计候选资产失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job, "counts": counts})
}

// handleDiscoveryJobCancel 请求取消任务
func (a *App) handleDiscoveryJobCancel(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "operator"); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的任务 ID")
		return
	}
	if err := a.discoveryRepo().RequestCancel(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "任务不存在或已结束")
		return
	}
	a.discoveryMu.Lock()
	cancel := a.discoveryCancel[id]
	a.discoveryMu.Unlock()
	if cancel != nil {
		cancel()
	}
	a.audit(r, "discovery.job.cancel", fmt.Sprintf("discovery:%d", id), "请求取消发现任务")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- 候选资产 ----------

// handleDiscoveryCandidates 列出候选资产
func (a *App) handleDiscoveryCandidates(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "viewer"); !ok {
		return
	}
	page, size, offset := pageParams(r)
	jobID, _ := strconv.ParseInt(r.URL.Query().Get("jobId"), 10, 64)
	filter := ports.DiscoveryCandidateFilter{
		JobID:    jobID,
		Decision: strings.TrimSpace(r.URL.Query().Get("decision")),
		Query:    strings.TrimSpace(r.URL.Query().Get("q")),
	}
	items, total, err := a.discoveryRepo().ListCandidates(r.Context(), filter, size, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "查询候选资产失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": total, "page": page, "pageSize": size, "items": items,
	})
}

// handleDiscoveryCandidateAction 处置单个候选：approve / ignore / merge
func (a *App) handleDiscoveryCandidateAction(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "无效的候选 ID")
		return
	}
	action := strings.ToLower(strings.TrimSpace(r.PathValue("action")))
	candidate, err := a.discoveryRepo().GetCandidate(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "候选资产不存在")
		return
	}

	switch action {
	case "approve":
		assetID, err := a.approveDiscoveryCandidate(r.Context(), candidate, u.Name)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "确认候选资产失败："+err.Error())
			return
		}
		a.audit(r, "discovery.candidate.approve", fmt.Sprintf("candidate:%d", id),
			fmt.Sprintf("%s → asset:%d", candidate.IP, assetID))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "decision": "approved", "assetId": assetID})

	case "ignore":
		if err := a.discoveryRepo().SetCandidateDecision(r.Context(), id, "ignored", 0, u.Name, fmtT(nowT())); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "忽略候选资产失败")
			return
		}
		a.audit(r, "discovery.candidate.ignore", fmt.Sprintf("candidate:%d", id), candidate.IP)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "decision": "ignored"})

	case "merge":
		if roleRank(u.Role) < roleRank("admin") {
			writeErr(w, http.StatusForbidden, "forbidden", "仅管理员可把候选合并到已有资产")
			return
		}
		var req struct {
			AssetID int64 `json:"assetId"`
		}
		if err := readJSON(r, &req); err != nil || req.AssetID <= 0 {
			writeErr(w, http.StatusBadRequest, "bad_request", "请提供有效的目标资产 ID")
			return
		}
		if _, err := a.assetRepo().Detail(r.Context(), req.AssetID); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", "目标资产不存在")
			return
		}
		if err := a.linkCandidateIdentifiers(r.Context(), candidate, req.AssetID); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "写入资产标识失败")
			return
		}
		if err := a.discoveryRepo().SetCandidateDecision(r.Context(), id, "merged", req.AssetID, u.Name, fmtT(nowT())); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "合并候选资产失败")
			return
		}
		a.audit(r, "discovery.candidate.merge", fmt.Sprintf("candidate:%d", id),
			fmt.Sprintf("%s → asset:%d", candidate.IP, req.AssetID))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "decision": "merged", "assetId": req.AssetID})

	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "不支持的操作："+action)
	}
}

// handleDiscoveryCandidatesBatch 批量确认或忽略候选
func (a *App) handleDiscoveryCandidatesBatch(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "operator")
	if !ok {
		return
	}
	var req struct {
		IDs    []int64 `json:"ids"`
		Action string  `json:"action"`
	}
	if err := readJSON(r, &req); err != nil || len(req.IDs) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "请提供候选 ID 列表")
		return
	}
	if len(req.IDs) > 200 {
		writeErr(w, http.StatusBadRequest, "bad_request", "单次最多处理 200 个候选")
		return
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != "approve" && action != "ignore" {
		writeErr(w, http.StatusBadRequest, "bad_request", "批量操作仅支持 approve / ignore")
		return
	}

	processed := 0
	failed := make([]map[string]any, 0)
	for _, id := range req.IDs {
		candidate, err := a.discoveryRepo().GetCandidate(r.Context(), id)
		if err != nil {
			failed = append(failed, map[string]any{"id": id, "error": "候选不存在"})
			continue
		}
		if action == "approve" {
			if _, err := a.approveDiscoveryCandidate(r.Context(), candidate, u.Name); err != nil {
				failed = append(failed, map[string]any{"id": id, "error": err.Error()})
				continue
			}
		} else if err := a.discoveryRepo().SetCandidateDecision(r.Context(), id, "ignored", 0, u.Name, fmtT(nowT())); err != nil {
			failed = append(failed, map[string]any{"id": id, "error": err.Error()})
			continue
		}
		processed++
	}
	a.audit(r, "discovery.candidate.batch", "discovery_candidates",
		fmt.Sprintf("%s %d 个，成功 %d，失败 %d", action, len(req.IDs), processed, len(failed)))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "processed": processed, "failed": failed,
		"decision": map[string]string{"approve": "approved", "ignore": "ignored"}[action],
	})
}

// approveDiscoveryCandidate 把候选写入资产台账；已匹配时只补充标识
func (a *App) approveDiscoveryCandidate(ctx context.Context, candidate ports.DiscoveryCandidate, actor string) (int64, error) {
	if candidate.Decision == "approved" || candidate.Decision == "merged" {
		return candidate.AssetID, nil
	}
	now := fmtT(nowT())
	if candidate.MatchedAssetID > 0 {
		if err := a.linkCandidateIdentifiers(ctx, candidate, candidate.MatchedAssetID); err != nil {
			return 0, err
		}
		if err := a.discoveryRepo().SetCandidateDecision(ctx, candidate.ID, "approved", candidate.MatchedAssetID, actor, now); err != nil {
			return 0, err
		}
		return candidate.MatchedAssetID, nil
	}

	hostname := strings.TrimSpace(candidate.Hostname)
	if hostname == "" {
		hostname = candidate.IP
	}
	if existing, found, err := a.assetRepo().FindByHostname(ctx, hostname); err == nil && found {
		if existing == candidate.MatchedAssetID {
			return existing, nil
		}
		hostname = fmt.Sprintf("%s-%s", hostname, strings.ReplaceAll(candidate.IP, ".", "-"))
	}
	fields := map[string]string{"hostname": hostname, "ip": candidate.IP}
	identifiers := map[string]string{"hostname": hostname, "ip": candidate.IP}
	if candidate.MAC != "" {
		fields["mac"] = candidate.MAC
		identifiers["mac"] = candidate.MAC
	}
	assetID, err := a.assetRepo().Create(ctx, fields, nil, identifiers, "discovery")
	if err != nil {
		return 0, err
	}
	if err := a.discoveryRepo().SetCandidateDecision(ctx, candidate.ID, "approved", assetID, actor, now); err != nil {
		return 0, err
	}
	return assetID, nil
}

// linkCandidateIdentifiers 把候选的 IP / 主机名 / MAC 登记到目标资产
func (a *App) linkCandidateIdentifiers(ctx context.Context, candidate ports.DiscoveryCandidate, assetID int64) error {
	if candidate.IP != "" {
		if err := a.assetRepo().AddIdentifiers(ctx, assetID, "ip", "discovery", []string{candidate.IP}); err != nil {
			return err
		}
	}
	if candidate.Hostname != "" {
		if err := a.assetRepo().AddIdentifiers(ctx, assetID, "hostname", "discovery", []string{candidate.Hostname}); err != nil {
			return err
		}
	}
	if candidate.MAC != "" {
		if err := a.assetRepo().AddIdentifiers(ctx, assetID, "mac", "discovery", []string{candidate.MAC}); err != nil {
			return err
		}
	}
	return nil
}

// ---------- 执行器 ----------

// startDiscoveryJob 后台执行扫描，进度与候选实时落库
func (a *App) startDiscoveryJob(jobID int64, addrs []netip.Addr, opts discovery.ScanOptions) {
	runCtx, cancel := context.WithCancel(context.Background())
	a.discoveryMu.Lock()
	if a.discoveryCancel == nil {
		a.discoveryCancel = make(map[int64]context.CancelFunc)
	}
	a.discoveryCancel[jobID] = cancel
	a.discoveryMu.Unlock()

	go func() {
		defer func() {
			cancel()
			a.discoveryMu.Lock()
			delete(a.discoveryCancel, jobID)
			a.discoveryMu.Unlock()
		}()
		repo := a.discoveryRepo()
		dbCtx := context.Background()
		if _, err := a.db.Exec(`UPDATE discovery_jobs SET status = 'running', started_at = ? WHERE id = ?`,
			fmtT(nowT()), jobID); err != nil {
			slog.Error("更新发现任务状态失败", "jobId", jobID, "err", err)
		}

		stats := discovery.Scan(runCtx, addrs, opts, func(host discovery.HostResult) {
			a.recordDiscoveryCandidate(dbCtx, jobID, host)
		}, func(done, found int) {
			_ = repo.UpdateJobProgress(dbCtx, jobID, done, found)
			if done%16 == 0 {
				if requested, err := repo.CancelRequested(dbCtx, jobID); err == nil && requested {
					cancel()
				}
			}
		})

		status := "completed"
		errText := ""
		if runCtx.Err() != nil {
			status = "cancelled"
		}
		_ = repo.UpdateJobProgress(dbCtx, jobID, stats.Scanned, stats.Found)
		_ = repo.FinishJob(dbCtx, jobID, status, errText, fmtT(nowT()))
		a.auditAs("系统", "system", "127.0.0.1", "", "discovery.job.finish", fmt.Sprintf("discovery:%d", jobID),
			fmt.Sprintf("%s：扫描 %d 台，发现 %d 台", status, stats.Scanned, stats.Found))
		slog.Info("发现任务结束", "jobId", jobID, "status", status, "scanned", stats.Scanned, "found", stats.Found)
	}()
}

// recordDiscoveryCandidate 按主机名/IP 匹配已有资产并写入候选
func (a *App) recordDiscoveryCandidate(ctx context.Context, jobID int64, host discovery.HostResult) {
	matched := int64(0)
	confidence := 0.6
	decision := "new"
	if host.Hostname != "" {
		if id, ok, err := a.assetRepo().FindByIdentity(ctx, "hostname", host.Hostname); err == nil && ok {
			matched, confidence, decision = id, 0.95, "existing"
		} else if id, ok, err := a.assetRepo().FindByHostname(ctx, host.Hostname); err == nil && ok {
			matched, confidence, decision = id, 0.95, "existing"
		}
	}
	if matched == 0 {
		if id, ok, err := a.assetRepo().FindByIdentity(ctx, "ip", host.IP); err == nil && ok {
			matched, confidence, decision = id, 0.85, "existing"
		}
	}
	services, _ := json.Marshal(host.Ports)
	candidate := ports.DiscoveryCandidate{
		JobID:          jobID,
		IP:             host.IP,
		Hostname:       host.Hostname,
		OpenPorts:      host.OpenPorts(),
		Services:       string(services),
		Evidence:       host.Evidence(),
		MatchedAssetID: matched,
		Decision:       decision,
		Confidence:     confidence,
		CreatedAt:      fmtT(nowT()),
	}
	if _, err := a.discoveryRepo().InsertCandidate(ctx, candidate); err != nil {
		slog.Warn("写入发现候选失败", "jobId", jobID, "ip", host.IP, "err", err)
	}
}
